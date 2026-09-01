#!/usr/bin/env python3
"""Minimal Chromium DevTools helpers that do not depend on Selenium."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

DEBUG_PORT_ENV = "OVERDRIVE_DIRECT_CHROME_DEBUG_PORT"
ATTACH_PORT_ENV = "OVERDRIVE_DIRECT_CHROME_ATTACH_PORT"
EXTRA_ARGS_ENV = "OVERDRIVE_DIRECT_CHROME_EXTRA_ARGS"
XVFB_DISPLAY_ENV = "OVERDRIVE_DIRECT_CHROME_X_DISPLAY"
USE_SYSTEM_DISPLAY_ENV = "OVERDRIVE_DIRECT_CHROME_USE_SYSTEM_DISPLAY"
USE_DBUS_RUN_SESSION_ENV = "OVERDRIVE_DIRECT_CHROME_USE_DBUS_RUN_SESSION"
STARTUP_TIMEOUT_ENV = "OVERDRIVE_DIRECT_CHROME_STARTUP_TIMEOUT"
SHARED_STARTUP_TIMEOUT_ENV = "OVERDRIVE_DIRECT_CHROME_SHARED_STARTUP_TIMEOUT"

_IS_LINUX = sys.platform.startswith("linux")
# 0 means wait forever for DevTools / probe callbacks (no wall-clock kill).
DEFAULT_SHARED_STARTUP_TIMEOUT = 500
DEFAULT_PROBE_EXPIRATION = 500
DEFAULT_STARTUP_EXPIRATION = 500


class _AliveProc:
    """Stand-in process handle for DevTools waits against an already-running Chromium."""

    def poll(self) -> None:
        return None


def _expiration_or_none(timeout: int | None) -> int | None:
    """Normalize expiration: ``None``/``<=0`` means wait forever."""
    if timeout is None:
        return None
    value = int(timeout)
    return None if value <= 0 else value


def resolve_probe_expiration(timeout: int | None) -> int | None:
    """
    Browser probes wait on callbacks with a safety wall-clock expiration.

    Default is ``DEFAULT_PROBE_EXPIRATION`` (500s). ``0`` / env ``0`` waits forever.
    ``OVERDRIVE_BROWSER_TIMEOUT`` overrides when set.
    """
    env_raw = (os.environ.get("OVERDRIVE_BROWSER_TIMEOUT") or "").strip()
    if env_raw:
        try:
            return _expiration_or_none(int(env_raw))
        except ValueError:
            pass
    if timeout is not None and int(timeout) > 0:
        if DEFAULT_PROBE_EXPIRATION <= 0:
            return int(timeout)
        return max(DEFAULT_PROBE_EXPIRATION, int(timeout))
    if timeout is not None and int(timeout) <= 0:
        return None
    return _expiration_or_none(DEFAULT_PROBE_EXPIRATION)


def wait_until(
    predicate,
    *,
    expiration_sec: int | None,
    poll_sec: float = 0.2,
    label: str = "condition",
    on_progress=None,
    progress_every_sec: float = 15.0,
) -> None:
    """Poll until ``predicate()`` is true. ``expiration_sec=None`` waits forever."""
    started = time.monotonic()
    last_progress = started
    deadline = None if expiration_sec is None else started + max(1, int(expiration_sec))
    while deadline is None or time.monotonic() < deadline:
        if predicate():
            return
        now = time.monotonic()
        if on_progress is not None and (now - last_progress) >= progress_every_sec:
            on_progress(int(now - started), expiration_sec)
            last_progress = now
        time.sleep(poll_sec)
    raise TimeoutError(f"{label} did not complete within {expiration_sec}s safety expiration")


def first_executable_path(*candidates: str) -> str | None:
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def chromium_binary() -> str | None:
    env = (os.environ.get("CHROME_BIN") or os.environ.get("CHROMIUM_BIN") or "").strip()
    if env and os.path.isfile(env):
        return env
    return (
        shutil.which("chromium-browser")
        or shutil.which("chromium")
        or shutil.which("google-chrome")
        or shutil.which("google-chrome-stable")
        or first_executable_path(
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
        )
    )


def xvfb_binary() -> str | None:
    return shutil.which("Xvfb") or first_executable_path("/usr/bin/Xvfb")


def dbus_run_session_binary() -> str | None:
    return shutil.which("dbus-run-session") or first_executable_path("/usr/bin/dbus-run-session")


def dbus_machine_id_present() -> bool:
    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        try:
            if path.read_text(encoding="utf-8", errors="ignore").strip():
                return True
        except OSError:
            continue
    return False


def chromium_swiftshader_available(chromium: str) -> bool:
    """True when Chromium's SwiftShader/Vulkan software stack is on disk."""
    candidates: list[Path] = [
        Path("/usr/lib/chromium/libvk_swiftshader.so"),
        Path("/usr/lib/chromium/libswiftshader_libvulkan.so"),
        Path("/usr/lib/chromium/libEGL.so"),
    ]
    try:
        parent = Path(chromium).resolve().parent
        candidates.extend(
            [
                parent / "libvk_swiftshader.so",
                parent / "libswiftshader_libvulkan.so",
                parent / "swiftshader" / "libvk_swiftshader.so",
            ]
        )
    except OSError:
        pass
    return any(path.is_file() for path in candidates)


def chromium_gl_args(chromium: str) -> list[str]:
    """
    GL / GPU flags for DevTools stability.

    Alpine's Chromium package often lacks SwiftShader. ANGLE then fails Vulkan
    init, the GPU process exits, and remote debugging never becomes ready.
    """
    common = [
        "--disable-vulkan",
        "--disable-gpu-vsync",
        "--disable-features=Vulkan,VulkanFromANGLE,DefaultANGLEVulkan,WebGPU",
    ]
    if chromium_swiftshader_available(chromium):
        return [
            *common,
            "--use-gl=angle",
            "--use-angle=swiftshader",
            "--enable-unsafe-swiftshader",
        ]
    return [
        *common,
        "--disable-gpu",
        "--disable-gpu-compositing",
        "--in-process-gpu",
        "--use-gl=disabled",
    ]


def chrome_full_version(binary: str | None) -> str:
    version = "120.0.0.0"
    if binary:
        try:
            out = subprocess.check_output(
                [binary, "--version"],
                text=True,
                timeout=8,
                stderr=subprocess.DEVNULL,
            )
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", out) or re.search(
                r"(\d+\.\d+\.\d+)",
                out,
            )
            if match:
                version = match.group(1)
                if version.count(".") == 2:
                    version += ".0"
        except (OSError, subprocess.SubprocessError):
            pass
    return version


def desktop_chrome_user_agent(binary: str | None) -> str:
    version = chrome_full_version(binary)
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{version} Safari/537.36"
    )


def chrome_stealth_prelude(binary: str | None) -> str:
    ua = json.dumps(desktop_chrome_user_agent(binary))
    version = json.dumps(chrome_full_version(binary))
    return f"""
(() => {{
  const ua = {ua};
  const fullVersion = {version};
  const major = fullVersion.split(".", 1)[0];
  const overrideValue = (target, name, value) => {{
    try {{
      Object.defineProperty(target, name, {{
        configurable: true,
        get: () => value,
      }});
    }} catch (_err) {{}}
  }};
  overrideValue(Navigator.prototype, "webdriver", undefined);
  overrideValue(Navigator.prototype, "platform", "Win32");
  overrideValue(Navigator.prototype, "vendor", "Google Inc.");
  overrideValue(Navigator.prototype, "language", "en-US");
  overrideValue(Navigator.prototype, "languages", Object.freeze(["en-US", "en"]));
  const brands = Object.freeze([
    Object.freeze({{ brand: "Not:A-Brand", version: "99" }}),
    Object.freeze({{ brand: "Google Chrome", version: major }}),
    Object.freeze({{ brand: "Chromium", version: major }}),
  ]);
  const fullVersionList = Object.freeze([
    Object.freeze({{ brand: "Not:A-Brand", version: "10.0.0.0" }}),
    Object.freeze({{ brand: "Google Chrome", version: fullVersion }}),
    Object.freeze({{ brand: "Chromium", version: fullVersion }}),
  ]);
  overrideValue(Navigator.prototype, "userAgentData", {{
    brands,
    mobile: false,
    platform: "Windows",
    getHighEntropyValues: (hints) => {{
      const out = {{}};
      for (const hint of Array.isArray(hints) ? hints : []) {{
        if (hint === "architecture") out.architecture = "x86";
        if (hint === "bitness") out.bitness = "64";
        if (hint === "brands") out.brands = brands;
        if (hint === "formFactors") out.formFactors = ["Desktop"];
        if (hint === "fullVersionList") out.fullVersionList = fullVersionList;
        if (hint === "mobile") out.mobile = false;
        if (hint === "model") out.model = "";
        if (hint === "platform") out.platform = "Windows";
        if (hint === "platformVersion") out.platformVersion = "15.0.0";
        if (hint === "uaFullVersion") out.uaFullVersion = fullVersion;
        if (hint === "wow64") out.wow64 = false;
      }}
      return Promise.resolve(out);
    }},
    toJSON: () => ({{ brands, mobile: false, platform: "Windows" }}),
  }});
  overrideValue(window, "outerWidth", 1920);
  overrideValue(window, "outerHeight", 1080);
  const patchWebGL = (proto) => {{
    if (!proto || !proto.getParameter) return;
    const originalGetParameter = proto.getParameter;
    try {{
      Object.defineProperty(proto, "getParameter", {{
        configurable: true,
        value: function(parameter) {{
          if (parameter === 37445) return "Google Inc. (Intel)";
          if (parameter === 37446) {{
            return "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)";
          }}
          return originalGetParameter.apply(this, arguments);
        }},
      }});
    }} catch (_err) {{}}
  }};
  patchWebGL(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
  patchWebGL(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
}})();
"""


def chrome_user_agent_metadata(binary: str | None) -> dict[str, Any]:
    full_version = chrome_full_version(binary)
    major = full_version.split(".", 1)[0]
    brands = [
        {"brand": "Not:A-Brand", "version": "99"},
        {"brand": "Google Chrome", "version": major},
        {"brand": "Chromium", "version": major},
    ]
    full_version_list = [
        {"brand": "Not:A-Brand", "version": "10.0.0.0"},
        {"brand": "Google Chrome", "version": full_version},
        {"brand": "Chromium", "version": full_version},
    ]
    return {
        "brands": brands,
        "fullVersionList": full_version_list,
        "fullVersion": full_version,
        "platform": "Windows",
        "platformVersion": "15.0.0",
        "architecture": "x86",
        "model": "",
        "mobile": False,
        "bitness": "64",
        "wow64": False,
    }


def pick_local_port(start: int = 22000, end: int = 60999, *, honor_env: bool = True) -> int:
    if honor_env:
        env_port = (os.environ.get(DEBUG_PORT_ENV) or "").strip()
        if env_port.isdigit():
            return int(env_port)

    span = max(1, end - start)
    first = start + ((os.getpid() * 41) % span)
    for offset in range(min(span, 2000)):
        port = start + ((first - start + offset) % span)
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            if sock is not None:
                sock.close()
    return 9222 + (os.getpid() % 1000)


def attach_debug_port() -> int | None:
    """Port of a suite-owned Chromium that probes should attach to instead of launching."""
    raw = (os.environ.get(ATTACH_PORT_ENV) or "").strip()
    if raw.isdigit():
        return int(raw)
    return None


def pick_x_display(start: int = 90, end: int = 199) -> str:
    configured = (os.environ.get(XVFB_DISPLAY_ENV) or "").strip()
    if configured:
        return configured if configured.startswith(":") else f":{configured}"

    for display_num in range(start, end + 1):
        lock_path = Path("/tmp") / f".X{display_num}-lock"
        socket_path = Path("/tmp") / ".X11-unix" / f"X{display_num}"
        if not lock_path.exists() and not socket_path.exists():
            return f":{display_num}"
    return f":{start + (os.getpid() % max(1, end - start + 1))}"


def read_small(path: Path | None, limit: int = 2500) -> str:
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:].strip()
    except OSError:
        return ""


def _process_cmdline(pid: int) -> str:
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "ignore").strip()


def _pids_using_profile(profile_dir: Path) -> set[int]:
    if not Path("/proc").exists():
        return set()
    needles = {str(profile_dir), str(profile_dir.parent)}
    pids: set[int] = set()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        cmdline = _process_cmdline(pid)
        if "overdrive-direct-chrome-" not in cmdline:
            continue
        if any(needle in cmdline for needle in needles):
            pids.add(pid)
    return pids


def terminate_profile_processes(profile_dir: Path) -> None:
    """
    Reap Chrome descendants that survive the dbus/Xvfb wrapper process.

    Chromium can leave stopped process-group members behind after DevTools
    teardown on some WSL/Chrome builds. Match on the unique temp profile so a
    cleanup pass cannot touch normal user browser windows.
    """
    for sig, wait_seconds in ((signal.SIGTERM, 0.5), (signal.SIGKILL, 0.2)):
        pids = _pids_using_profile(profile_dir)
        if not pids:
            return
        pgids: set[int] = set()
        for pid in pids:
            try:
                pgids.add(os.getpgid(pid))
            except OSError:
                continue
        for pgid in pgids:
            try:
                os.killpg(pgid, sig)
            except OSError:
                pass
        for pid in pids:
            try:
                os.kill(pid, sig)
            except OSError:
                pass

        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if not _pids_using_profile(profile_dir):
                return
            time.sleep(0.05)


def wait_for_chrome_json(url: str, proc: subprocess.Popen, timeout: int | None) -> Any:
    expiration = _expiration_or_none(timeout)
    started = time.monotonic()
    last_progress = started
    while True:
        if expiration is not None and time.monotonic() >= started + expiration:
            break
        if proc.poll() is not None:
            raise RuntimeError(f"Chromium exited early with code {proc.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                return json.load(response)
        except (OSError, json.JSONDecodeError):
            now = time.monotonic()
            if now - last_progress >= 15:
                if expiration is None:
                    print(
                        f"  … waiting for Chromium DevTools ({int(now - started)}s; no expiration)",
                        flush=True,
                    )
                else:
                    print(
                        f"  … waiting for Chromium DevTools "
                        f"({int(now - started)}s / {expiration}s safety expiration)",
                        flush=True,
                    )
                last_progress = now
            time.sleep(0.25)
    raise TimeoutError(
        f"Chromium DevTools endpoint did not become ready within {expiration}s safety expiration"
    )


def chrome_target_websocket(
    port: int,
    proc: subprocess.Popen,
    timeout: int | None,
    *,
    fallback_url: str = "about:blank",
) -> str:
    base = f"http://127.0.0.1:{port}"
    wait_for_chrome_json(f"{base}/json/version", proc, timeout)

    expiration = _expiration_or_none(timeout)
    started = time.monotonic()
    while expiration is None or time.monotonic() < started + expiration:
        targets = wait_for_chrome_json(f"{base}/json/list", proc, 5 if expiration is None else 1)
        if isinstance(targets, list):
            for target in targets:
                if (
                    isinstance(target, dict)
                    and target.get("type") == "page"
                    and target.get("webSocketDebuggerUrl")
                ):
                    return str(target["webSocketDebuggerUrl"])
        time.sleep(0.1)

    new_target = urllib.parse.quote(fallback_url, safe=":/?#[]@!$&'()*+,;=%")
    request = urllib.request.Request(f"{base}/json/new?{new_target}", method="PUT")
    with urllib.request.urlopen(request, timeout=2) as response:
        target = json.load(response)
    ws_url = target.get("webSocketDebuggerUrl") if isinstance(target, dict) else None
    if not ws_url:
        raise RuntimeError("Chromium DevTools did not expose a page websocket")
    return str(ws_url)


def websocket_connect(ws_url: str, timeout: int) -> socket.socket:
    parsed = urllib.parse.urlparse(ws_url)
    if parsed.scheme != "ws" or not parsed.hostname or not parsed.port:
        raise RuntimeError(f"Unsupported DevTools websocket URL: {ws_url}")

    sock = socket.create_connection((parsed.hostname, parsed.port), timeout=timeout)
    sock.settimeout(timeout)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}:{parsed.port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("ascii"))
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    if b" 101 " not in response.split(b"\r\n", 1)[0]:
        raise RuntimeError("DevTools websocket upgrade failed")

    accept_source = (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
    expected = base64.b64encode(hashlib.sha1(accept_source).digest()).decode("ascii")
    if f"Sec-WebSocket-Accept: {expected}".lower() not in response.decode(
        "latin1",
        "ignore",
    ).lower():
        raise RuntimeError("DevTools websocket accept key mismatch")
    return sock


def websocket_send_json(sock: socket.socket, payload: dict[str, Any]) -> None:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    header = bytearray([0x81])
    if len(data) < 126:
        header.append(0x80 | len(data))
    elif len(data) <= 0xFFFF:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", len(data)))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", len(data)))
    mask = os.urandom(4)
    header.extend(mask)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
    sock.sendall(bytes(header) + masked)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("DevTools websocket closed unexpectedly")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def websocket_recv_text(sock: socket.socket) -> str:
    fragments: list[bytes] = []
    while True:
        first, second = recv_exact(sock, 2)
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", recv_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", recv_exact(sock, 8))[0]
        mask = recv_exact(sock, 4) if masked else b""
        data = recv_exact(sock, length) if length else b""
        if masked:
            data = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))

        if opcode == 0x8:
            raise RuntimeError("DevTools websocket closed")
        if opcode == 0x9:
            continue
        if opcode in (0x1, 0x0):
            fragments.append(data)
            if fin:
                return b"".join(fragments).decode("utf-8", "replace")


def cdp_call(
    sock: socket.socket,
    message_id: int,
    method: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    websocket_send_json(
        sock,
        {"id": message_id, "method": method, "params": params or {}},
    )
    while True:
        message = json.loads(websocket_recv_text(sock))
        if message.get("id") == message_id:
            if "error" in message:
                raise RuntimeError(f"DevTools {method} failed: {message['error']}")
            return message


def chrome_command(
    chromium: str,
    port: int,
    profile_dir: Path,
    url: str = "about:blank",
    *,
    headless: bool = False,
    no_sandbox: bool = False,
    ignore_certificate_errors: bool = False,
) -> list[str]:
    args = [
        chromium,
        "--remote-debugging-address=127.0.0.1",
        f"--remote-debugging-port={port}",
        "--disable-dev-shm-usage",
        "--autoplay-policy=no-user-gesture-required",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-blink-features=AutomationControlled",
        *chromium_gl_args(chromium),
        "--lang=en-US",
        "--window-size=1920,1080",
        f"--user-agent={desktop_chrome_user_agent(chromium)}",
        f"--user-data-dir={profile_dir}",
    ]
    if headless:
        args.extend(["--headless=new", "--hide-scrollbars"])
    else:
        args.append("--ozone-platform=x11")
    if no_sandbox:
        args.append("--no-sandbox")
    if ignore_certificate_errors:
        args.append("--ignore-certificate-errors")
    args.extend(shlex.split(os.environ.get(EXTRA_ARGS_ENV, "")))
    args.append(url)
    return args


def browser_process_command(args: list[str]) -> list[str]:
    dbus_pref = (os.environ.get(USE_DBUS_RUN_SESSION_ENV) or "").strip().lower()
    if dbus_pref in {"0", "false", "no", "off"}:
        return args

    dbus_run_session = dbus_run_session_binary()
    if dbus_run_session and (dbus_pref in {"1", "true", "yes", "on"} or dbus_machine_id_present()):
        return [dbus_run_session, "--", *args]
    return args


def _env_truthy(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            value = default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def chromium_startup_timeout(total_timeout: int | None) -> int | None:
    """Safety expiration for Chromium/Xvfb/DBus becoming ready. ``None`` = forever."""
    expiration = _expiration_or_none(total_timeout)
    if expiration is None:
        env_raw = (os.environ.get(STARTUP_TIMEOUT_ENV) or "").strip()
        if env_raw:
            return _expiration_or_none(_env_int(STARTUP_TIMEOUT_ENV, 0, minimum=0))
        return _expiration_or_none(DEFAULT_STARTUP_EXPIRATION)
    default = max(expiration, DEFAULT_STARTUP_EXPIRATION or expiration)
    return _env_int(STARTUP_TIMEOUT_ENV, default, minimum=1, maximum=max(expiration, 1))


def shared_chromium_startup_timeout() -> int | None:
    env_raw = (os.environ.get(SHARED_STARTUP_TIMEOUT_ENV) or "").strip()
    if env_raw:
        return _expiration_or_none(_env_int(SHARED_STARTUP_TIMEOUT_ENV, 0, minimum=0))
    return _expiration_or_none(DEFAULT_SHARED_STARTUP_TIMEOUT)


def _terminate_process_tree(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        try:
            proc.terminate()
        except OSError:
            return
    try:
        proc.wait(timeout=3)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            return
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass


@dataclass
class SharedChromiumSession:
    port: int
    proc: subprocess.Popen
    profile_dir: Path
    _tmpdir: tempfile.TemporaryDirectory
    _xvfb_proc: subprocess.Popen | None = None
    _log_path: Path | None = None
    _env: dict[str, str] = field(default_factory=dict)


def start_shared_chromium(
    *,
    startup_timeout: int | None = None,
) -> SharedChromiumSession:
    """Launch one long-lived Chromium for the whole browser detection suite."""
    chromium = chromium_binary()
    if not chromium:
        raise RuntimeError("Chromium/Chrome is unavailable.")

    timeout = startup_timeout if startup_timeout is not None else shared_chromium_startup_timeout()
    tmpdir = tempfile.TemporaryDirectory(
        prefix="overdrive-shared-chrome-",
        ignore_cleanup_errors=True,
    )
    tmp_path = Path(tmpdir.name)
    failures: list[str] = []
    try:
        env, xvfb_proc, xvfb_log, use_headless = start_xvfb_if_needed(tmp_path)
    except Exception as exc:
        tmpdir.cleanup()
        raise RuntimeError(
            f"Shared Chromium display setup failed: {type(exc).__name__}: {exc}"
        ) from exc

    port = pick_local_port(honor_env=False)
    profile_dir = tmp_path / f"profile-{port}"
    log_path = tmp_path / f"chromium-{port}.log"
    proc: subprocess.Popen | None = None
    first_no_sandbox = chromium_needs_no_sandbox()
    no_sandbox_attempts = (True,) if first_no_sandbox else (False, True)
    started: SharedChromiumSession | None = None

    try:
        for no_sandbox in no_sandbox_attempts:
            if no_sandbox and (
                not first_no_sandbox
                and (not failures or not browser_startup_needs_no_sandbox(failures[-1]))
            ):
                break
            mode = "Chromium --no-sandbox fallback" if no_sandbox else "Chromium"
            log_handle = log_path.open("a", encoding="utf-8", errors="replace")
            try:
                proc = subprocess.Popen(
                    browser_process_command(
                        chrome_command(
                            chromium,
                            port,
                            profile_dir,
                            "about:blank",
                            headless=use_headless,
                            no_sandbox=no_sandbox,
                            ignore_certificate_errors=True,
                        )
                    ),
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    close_fds=True,
                    env=env,
                    start_new_session=True,
                )
                wait_for_chrome_json(
                    f"http://127.0.0.1:{port}/json/version",
                    proc,
                    timeout,
                )
                started = SharedChromiumSession(
                    port=port,
                    proc=proc,
                    profile_dir=profile_dir,
                    _tmpdir=tmpdir,
                    _xvfb_proc=xvfb_proc,
                    _log_path=log_path,
                    _env=env,
                )
                proc = None  # ownership transferred; do not tear down in finally
                break
            except TimeoutError as exc:
                failures.append(f"{mode}: browser/devtools timed out: {exc}")
            except Exception as exc:
                failures.append(f"{mode}: {type(exc).__name__}: {exc}")
            finally:
                try:
                    log_handle.close()
                except OSError:
                    pass
                if started is None:
                    if proc is not None and proc.poll() is None:
                        _terminate_process_tree(proc)
                    terminate_profile_processes(profile_dir)
                    proc = None
                    log_tail = read_small(log_path)
                    if failures and log_tail and "chromium log:" not in failures[-1]:
                        failures[-1] = f"{failures[-1]} | chromium log: {log_tail}"
    finally:
        if started is None:
            if xvfb_proc is not None and xvfb_proc.poll() is None:
                _terminate_process_tree(xvfb_proc)
            xvfb_tail = read_small(xvfb_log)
            if failures and xvfb_tail and "xvfb log:" not in failures[-1]:
                failures[-1] = f"{failures[-1]} | xvfb log: {xvfb_tail}"
            try:
                tmpdir.cleanup()
            except OSError:
                pass

    if started is not None:
        return started

    raise RuntimeError("Shared Chromium failed to start: " + " | ".join(failures))


def stop_shared_chromium(session: SharedChromiumSession | None) -> None:
    if session is None:
        return
    _terminate_process_tree(session.proc)
    terminate_profile_processes(session.profile_dir)
    _terminate_process_tree(session._xvfb_proc)
    try:
        session._tmpdir.cleanup()
    except OSError:
        pass


@contextmanager
def shared_chromium_session(
    *,
    startup_timeout: int | None = None,
) -> Iterator[SharedChromiumSession]:
    """Own one Chromium process and publish its DevTools port to probe subprocesses."""
    session = start_shared_chromium(startup_timeout=startup_timeout)
    previous = os.environ.get(ATTACH_PORT_ENV)
    os.environ[ATTACH_PORT_ENV] = str(session.port)
    try:
        yield session
    finally:
        if previous is None:
            os.environ.pop(ATTACH_PORT_ENV, None)
        else:
            os.environ[ATTACH_PORT_ENV] = previous
        stop_shared_chromium(session)


def run_in_attached_chromium(
    action,
    *,
    port: int,
    timeout: int,
    label: str = "direct Chromium probe",
    initial_url: str = "about:blank",
) -> tuple[Any | None, str | None]:
    """Reuse a suite-owned Chromium instead of cold-starting a new process."""
    chromium = chromium_binary()
    if not chromium:
        return None, "Chromium/Chrome is unavailable."

    expiration = resolve_probe_expiration(timeout)
    attach_wait = chromium_startup_timeout(expiration)
    connect_timeout = expiration if expiration is not None else 600
    try:
        ws_url = chrome_target_websocket(
            port,
            _AliveProc(),
            timeout=attach_wait,
            fallback_url="about:blank",
        )
        with websocket_connect(ws_url, timeout=connect_timeout) as sock:
            navigate_current_page(
                sock,
                initial_url,
                chromium=chromium,
                timeout=expiration if expiration is not None else connect_timeout,
            )
            result = action(sock, _AliveProc(), chromium)
            try:
                navigate_current_page(
                    sock,
                    "about:blank",
                    chromium=chromium,
                    timeout=60,
                )
            except Exception:
                pass
            return result, None
    except Exception as exc:
        return None, f"{label} failed (shared Chromium attach): {type(exc).__name__}: {exc}"


def start_xvfb_if_needed(
    tmp_path: Path,
) -> tuple[dict[str, str], subprocess.Popen | None, Path | None, bool]:
    env = os.environ.copy()
    env.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")
    env.setdefault("GALLIUM_DRIVER", "llvmpipe")
    env.setdefault("MESA_LOADER_DRIVER_OVERRIDE", "llvmpipe")
    if env.get("DISPLAY") and _env_truthy(USE_SYSTEM_DISPLAY_ENV):
        return env, None, None, False

    def use_headless() -> tuple[dict[str, str], None, Path | None, bool]:
        headless_env = os.environ.copy()
        headless_env.pop("DISPLAY", None)
        headless_env.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")
        headless_env.setdefault("GALLIUM_DRIVER", "llvmpipe")
        headless_env.setdefault("MESA_LOADER_DRIVER_OVERRIDE", "llvmpipe")
        return headless_env, None, None, True

    xvfb = xvfb_binary()
    if not xvfb:
        return use_headless()

    display = pick_x_display()
    env["DISPLAY"] = display
    log_path = tmp_path / "xvfb.log"
    log_handle = log_path.open("a", encoding="utf-8", errors="replace")
    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(
            [xvfb, display, "-screen", "0", "1920x1080x24", "-nolisten", "tcp"],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )
    finally:
        try:
            log_handle.close()
        except OSError:
            pass

    socket_path = Path("/tmp") / ".X11-unix" / f"X{display.lstrip(':')}"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return use_headless()
        if socket_path.exists():
            return env, proc, log_path, False
        time.sleep(0.1)

    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
    return use_headless()


def runtime_evaluate(
    sock: socket.socket,
    expression: str,
    *,
    message_id: int,
    timeout_ms: int,
    await_promise: bool = True,
) -> Any:
    response = cdp_call(
        sock,
        message_id,
        "Runtime.evaluate",
        {
            "expression": expression,
            "awaitPromise": await_promise,
            "returnByValue": True,
            "timeout": timeout_ms,
        },
    )
    result = response.get("result", {}).get("result", {})
    if "exceptionDetails" in response.get("result", {}):
        raise RuntimeError(f"DevTools evaluation failed: {response['result']['exceptionDetails']}")
    return result.get("value")


def browser_startup_needs_no_sandbox(message: str) -> bool:
    text = (message or "").lower()
    return any(
        needle in text
        for needle in (
            "no usable sandbox",
            "setuid sandbox",
            "namespace sandbox",
            "zygote_host_impl_linux",
            "running as root without --no-sandbox",
        )
    )


def chromium_needs_no_sandbox() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def navigate_current_page(
    sock: socket.socket,
    url: str,
    *,
    chromium: str | None,
    timeout: int | None,
    first_message_id: int = 2,
) -> None:
    if not url or url == "about:blank":
        return

    expiration = _expiration_or_none(timeout)
    timeout_ms = 60000 if expiration is None else max(3000, int(expiration) * 1000)
    cdp_call(sock, first_message_id, "Network.enable")
    cdp_call(
        sock,
        first_message_id + 1,
        "Network.setUserAgentOverride",
        {
            "userAgent": desktop_chrome_user_agent(chromium),
            "acceptLanguage": "en-US,en;q=0.9",
            "platform": "Windows",
            "userAgentMetadata": chrome_user_agent_metadata(chromium),
        },
    )
    cdp_call(sock, first_message_id + 2, "Page.enable")
    cdp_call(
        sock,
        first_message_id + 3,
        "Page.addScriptToEvaluateOnNewDocument",
        {"source": chrome_stealth_prelude(chromium)},
    )
    response = cdp_call(sock, first_message_id + 4, "Page.navigate", {"url": url})
    error_text = response.get("result", {}).get("errorText")
    if error_text:
        raise RuntimeError(f"Chromium navigation to {url} failed: {error_text}")

    started = time.monotonic()
    expression = """
(() => ({
  href: location.href,
  readyState: document.readyState
}))()
"""
    while expiration is None or time.monotonic() < started + expiration:
        value = runtime_evaluate(
            sock,
            expression,
            message_id=first_message_id + 5,
            timeout_ms=min(timeout_ms, 15000),
            await_promise=False,
        )
        if isinstance(value, dict):
            href = str(value.get("href") or "")
            ready_state = str(value.get("readyState") or "")
            if href != "about:blank" and ready_state in ("interactive", "complete"):
                return
        time.sleep(0.25)

    raise TimeoutError(
        f"Chromium did not finish navigating to {url} within {expiration}s safety expiration"
    )


def run_in_chromium(
    action,
    *,
    timeout: int,
    label: str = "direct Chromium probe",
    initial_url: str = "about:blank",
    ignore_certificate_errors: bool = False,
) -> tuple[Any | None, str | None]:
    chromium = chromium_binary()
    if not chromium:
        return None, "Chromium/Chrome is unavailable."

    attached_port = attach_debug_port()
    if attached_port is not None:
        return run_in_attached_chromium(
            action,
            port=attached_port,
            timeout=timeout,
            label=label,
            initial_url=initial_url,
        )

    deadline = resolve_probe_expiration(timeout)
    failures: list[str] = []
    with tempfile.TemporaryDirectory(
        prefix="overdrive-direct-chrome-",
        ignore_cleanup_errors=True,
    ) as tmpdir:
        tmp_path = Path(tmpdir)
        xvfb_proc: subprocess.Popen | None = None
        xvfb_log: Path | None = None
        proc: subprocess.Popen | None = None
        port = pick_local_port()
        profile_dir = tmp_path / f"profile-{port}"
        log_path = tmp_path / f"chromium-{port}.log"
        try:
            env, xvfb_proc, xvfb_log, use_headless = start_xvfb_if_needed(tmp_path)
        except Exception as exc:
            return None, (
                f"{label} failed: Chromium display setup failed: "
                f"{type(exc).__name__}: {exc}"
            )

        try:
            first_no_sandbox = chromium_needs_no_sandbox()
            no_sandbox_attempts = (True,) if first_no_sandbox else (False, True)
            startup_timeout = chromium_startup_timeout(deadline)
            connect_timeout = deadline if deadline is not None else 600
            for no_sandbox in no_sandbox_attempts:
                if no_sandbox and (
                    not first_no_sandbox
                    and (not failures or not browser_startup_needs_no_sandbox(failures[-1]))
                ):
                    break
                mode = "Chromium --no-sandbox fallback" if no_sandbox else "Chromium"
                log_handle = log_path.open("a", encoding="utf-8", errors="replace")
                try:
                    proc = subprocess.Popen(
                        browser_process_command(
                            chrome_command(
                                chromium,
                                port,
                                profile_dir,
                                "about:blank",
                                headless=use_headless,
                                no_sandbox=no_sandbox,
                                ignore_certificate_errors=ignore_certificate_errors,
                            )
                        ),
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        close_fds=True,
                        env=env,
                        start_new_session=True,
                    )
                    ws_url = chrome_target_websocket(
                        port,
                        proc,
                        timeout=startup_timeout,
                        fallback_url="about:blank",
                    )
                    with websocket_connect(ws_url, timeout=connect_timeout) as sock:
                        navigate_current_page(
                            sock,
                            initial_url,
                            chromium=chromium,
                            timeout=deadline if deadline is not None else connect_timeout,
                        )
                        return action(sock, proc, chromium), None
                except TimeoutError as exc:
                    failures.append(f"{mode}: browser/devtools timed out: {type(exc).__name__}: {exc}")
                except OSError as exc:
                    failures.append(
                        f"{mode}: unable to launch/connect: {type(exc).__name__}: {exc}"
                    )
                except Exception as exc:
                    failures.append(f"{mode}: {type(exc).__name__}: {exc}")
                finally:
                    try:
                        log_handle.close()
                    except OSError:
                        pass
                    if proc is not None and proc.poll() is None:
                        _terminate_process_tree(proc)
                    terminate_profile_processes(profile_dir)
                    proc = None
                    log_tail = read_small(log_path)
                    if failures and log_tail and "chromium log:" not in failures[-1]:
                        failures[-1] = f"{failures[-1]} | chromium log: {log_tail}"
        finally:
            if xvfb_proc is not None and xvfb_proc.poll() is None:
                _terminate_process_tree(xvfb_proc)
            xvfb_tail = read_small(xvfb_log)
            if failures and xvfb_tail and "xvfb log:" not in failures[-1]:
                failures[-1] = f"{failures[-1]} | xvfb log: {xvfb_tail}"

    return None, f"{label} failed: " + " | ".join(failures)


def navigate_and_read_text(
    url: str,
    *,
    timeout: int,
    ignore_certificate_errors: bool = False,
) -> tuple[str | None, str | None]:
    expiration = resolve_probe_expiration(timeout)
    timeout_ms = 60000 if expiration is None else max(30000, expiration * 1000)

    def action(sock: socket.socket, _proc: subprocess.Popen, _chromium: str) -> str | None:
        started = time.monotonic()
        expression = """
(() => {
  const body = document.body;
  return {
    readyState: document.readyState,
    text: body ? (body.innerText || body.textContent || "") : "",
  };
})()
"""
        while expiration is None or time.monotonic() < started + expiration:
            value = runtime_evaluate(
                sock,
                expression,
                message_id=11,
                timeout_ms=min(timeout_ms, 15000),
                await_promise=False,
            )
            if isinstance(value, dict):
                text = str(value.get("text") or "").strip()
                if text:
                    return text
            time.sleep(0.25)
        return None

    value, error = run_in_chromium(
        action,
        timeout=0 if expiration is None else expiration,
        label="direct Chromium navigation",
        initial_url=url,
        ignore_certificate_errors=ignore_certificate_errors,
    )
    if error:
        return None, error
    if isinstance(value, str) and value.strip():
        return value.strip(), None
    return None, "Browser navigation completed without readable page text."


def navigate(url: str, *, timeout: int) -> str | None:
    """Open a URL in Chromium and return an error string if navigation fails."""
    expiration = resolve_probe_expiration(timeout)
    timeout_ms = 60000 if expiration is None else max(30000, expiration * 1000)

    def action(sock: socket.socket, _proc: subprocess.Popen, _chromium: str) -> None:
        started = time.monotonic()
        while expiration is None or time.monotonic() < started + expiration:
            value = runtime_evaluate(
                sock,
                "document.readyState",
                message_id=21,
                timeout_ms=min(timeout_ms, 15000),
                await_promise=False,
            )
            if value in ("interactive", "complete"):
                return None
            time.sleep(0.25)
        return None

    _value, error = run_in_chromium(
        action,
        timeout=0 if expiration is None else expiration,
        label="direct Chromium navigation",
        initial_url=url,
    )
    return error


def run_async_script(
    script: str,
    *,
    timeout: int,
    url: str = "about:blank",
    ignore_certificate_errors: bool = False,
) -> tuple[Any | None, str | None]:
    """Run callback-style async JavaScript in Chromium via DevTools.

    Completion is driven by the probe calling ``finishOnce`` / ``callback``.
    By default there is no wall-clock kill around that callback.
    """
    expiration = resolve_probe_expiration(timeout)
    # CDP awaitPromise still needs a numeric timeout_ms; use a very large value when forever.
    timeout_ms = 24 * 60 * 60 * 1000 if expiration is None else max(30000, expiration * 1000)
    script_source = json.dumps(script)
    safety_js = (
        ""
        if expiration is None
        else f"""
  setTimeout(
    () => finishOnce({{ok: false, error: "direct Chromium script safety expiration"}}),
    {timeout_ms}
  );
"""
    )

    def action(sock: socket.socket, _proc: subprocess.Popen, chromium: str) -> Any:
        expression = f"""
new Promise((resolve) => {{
  {chrome_stealth_prelude(chromium)}
  let done = false;
  const finishOnce = (value) => {{
    if (!done) {{
      done = true;
      resolve(value);
    }}
  }};
  {safety_js}
  try {{
    const fn = new Function({script_source});
    fn.call(window, finishOnce);
  }} catch (err) {{
    finishOnce({{ok: false, error: String(err && err.message ? err.message : err)}});
  }}
}})
"""
        return runtime_evaluate(
            sock,
            expression,
            message_id=32,
            timeout_ms=timeout_ms + 5000,
            await_promise=True,
        )

    return run_in_chromium(
        action,
        timeout=0 if expiration is None else expiration,
        label="direct Chromium async script",
        initial_url=url,
        ignore_certificate_errors=ignore_certificate_errors,
    )


def fetch_browser_json(
    url: str,
    *,
    timeout: int = DEFAULT_PROBE_EXPIRATION,
    cache_bust: bool = False,
    ignore_certificate_errors: bool = False,
) -> tuple[dict[str, Any] | None, str | None]:
    target = url
    if cache_bust:
        sep = "&" if "?" in target else "?"
        target = f"{target}{sep}t={int(time.time())}"
    text, error = navigate_and_read_text(
        target,
        timeout=timeout,
        ignore_certificate_errors=ignore_certificate_errors,
    )
    if error:
        return None, error
    if not text:
        return None, "Could not parse JSON from browser probe page."
    try:
        data = json.loads(text)
    except Exception as exc:
        return None, f"JSON parse error: {type(exc).__name__}: {exc}"
    if isinstance(data, dict):
        return data, None
    return None, "Probe response was JSON but not an object."
