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
import socket
import struct
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEBUG_PORT_ENV = "OVERDRIVE_DIRECT_CHROME_DEBUG_PORT"
EXTRA_ARGS_ENV = "OVERDRIVE_DIRECT_CHROME_EXTRA_ARGS"
XVFB_DISPLAY_ENV = "OVERDRIVE_DIRECT_CHROME_X_DISPLAY"


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
}})();
"""


def pick_local_port(start: int = 22000, end: int = 60999) -> int:
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


def wait_for_chrome_json(url: str, proc: subprocess.Popen, timeout: int) -> Any:
    deadline = time.monotonic() + max(1, timeout)
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"Chromium exited early with code {proc.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                return json.load(response)
        except (OSError, json.JSONDecodeError):
            time.sleep(0.2)
    raise TimeoutError(f"Chromium DevTools endpoint did not become ready within {timeout}s")


def chrome_target_websocket(
    port: int,
    proc: subprocess.Popen,
    timeout: int,
    *,
    fallback_url: str = "about:blank",
) -> str:
    base = f"http://127.0.0.1:{port}"
    wait_for_chrome_json(f"{base}/json/version", proc, timeout)

    deadline = time.monotonic() + max(1, timeout)
    while time.monotonic() < deadline:
        targets = wait_for_chrome_json(f"{base}/json/list", proc, 1)
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
) -> list[str]:
    args = [
        chromium,
        "--remote-debugging-address=127.0.0.1",
        f"--remote-debugging-port={port}",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--ozone-platform=x11",
        "--autoplay-policy=no-user-gesture-required",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-breakpad",
        "--disable-crash-reporter",
        "--disable-crashpad",
        "--disable-crashpad-for-testing",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-sandbox",
        "--disable-blink-features=AutomationControlled",
        "--lang=en-US",
        "--window-size=1920,1080",
        f"--user-agent={desktop_chrome_user_agent(chromium)}",
        f"--user-data-dir={profile_dir}",
    ]
    args.extend(shlex.split(os.environ.get(EXTRA_ARGS_ENV, "")))
    args.append(url)
    return args


def browser_process_command(args: list[str]) -> list[str]:
    dbus_run_session = dbus_run_session_binary()
    if dbus_run_session:
        return [dbus_run_session, "--", *args]
    return args


def start_xvfb_if_needed(tmp_path: Path) -> tuple[dict[str, str], subprocess.Popen | None, Path | None]:
    env = os.environ.copy()
    if env.get("DISPLAY"):
        return env, None, None

    xvfb = xvfb_binary()
    if not xvfb:
        raise RuntimeError(
            "DISPLAY is unset and Xvfb is unavailable. Rebuild/provision the Alpine "
            "client image so build-time install.py stages the xvfb package."
        )

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
            raise RuntimeError(
                f"Xvfb exited early with code {proc.returncode}: {read_small(log_path)}"
            )
        if socket_path.exists():
            return env, proc, log_path
        time.sleep(0.1)

    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    raise TimeoutError(f"Xvfb did not become ready on display {display}: {read_small(log_path)}")


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


def run_in_chromium(
    action,
    *,
    timeout: int,
    label: str = "direct Chromium probe",
    initial_url: str = "about:blank",
) -> tuple[Any | None, str | None]:
    chromium = chromium_binary()
    if not chromium:
        return None, "Chromium/Chrome is unavailable."

    deadline = max(10, int(timeout))
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="overdrive-direct-chrome-") as tmpdir:
        tmp_path = Path(tmpdir)
        xvfb_proc: subprocess.Popen | None = None
        xvfb_log: Path | None = None
        proc: subprocess.Popen | None = None
        port = pick_local_port()
        profile_dir = tmp_path / f"profile-{port}"
        log_path = tmp_path / f"chromium-{port}.log"
        log_handle = log_path.open("a", encoding="utf-8", errors="replace")
        try:
            env, xvfb_proc, xvfb_log = start_xvfb_if_needed(tmp_path)
            proc = subprocess.Popen(
                browser_process_command(chrome_command(chromium, port, profile_dir, initial_url)),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                close_fds=True,
                env=env,
            )
            ws_url = chrome_target_websocket(
                port,
                proc,
                timeout=5,
                fallback_url=initial_url,
            )
            with websocket_connect(ws_url, timeout=deadline) as sock:
                return action(sock, proc, chromium), None
        except OSError as exc:
            failures.append(
                f"normal Chromium: unable to launch/connect: {type(exc).__name__}: {exc}"
            )
        except Exception as exc:
            failures.append(f"normal Chromium: {type(exc).__name__}: {exc}")
        finally:
            try:
                log_handle.close()
            except OSError:
                pass
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if xvfb_proc is not None and xvfb_proc.poll() is None:
                xvfb_proc.terminate()
                try:
                    xvfb_proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    xvfb_proc.kill()
            log_tail = read_small(log_path)
            if failures and log_tail and "chromium log:" not in failures[-1]:
                failures[-1] = f"{failures[-1]} | chromium log: {log_tail}"
            xvfb_tail = read_small(xvfb_log)
            if failures and xvfb_tail and "xvfb log:" not in failures[-1]:
                failures[-1] = f"{failures[-1]} | xvfb log: {xvfb_tail}"

    return None, f"{label} failed: " + " | ".join(failures)


def navigate_and_read_text(url: str, *, timeout: int) -> tuple[str | None, str | None]:
    timeout_ms = max(3000, int(timeout) * 1000)

    def action(sock: socket.socket, _proc: subprocess.Popen, _chromium: str) -> str | None:
        deadline = time.monotonic() + max(3, int(timeout))
        expression = """
(() => {
  const body = document.body;
  return {
    readyState: document.readyState,
    text: body ? (body.innerText || body.textContent || "") : "",
  };
})()
"""
        while time.monotonic() < deadline:
            value = runtime_evaluate(
                sock,
                expression,
                message_id=11,
                timeout_ms=min(timeout_ms, 5000),
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
        timeout=timeout,
        label="direct Chromium navigation",
        initial_url=url,
    )
    if error:
        return None, error
    if isinstance(value, str) and value.strip():
        return value.strip(), None
    return None, "Browser navigation completed without readable page text."


def navigate(url: str, *, timeout: int) -> str | None:
    """Open a URL in Chromium and return an error string if navigation fails."""
    timeout_ms = max(3000, int(timeout) * 1000)

    def action(sock: socket.socket, _proc: subprocess.Popen, _chromium: str) -> None:
        deadline = time.monotonic() + max(3, int(timeout))
        while time.monotonic() < deadline:
            value = runtime_evaluate(
                sock,
                "document.readyState",
                message_id=21,
                timeout_ms=min(timeout_ms, 5000),
                await_promise=False,
            )
            if value in ("interactive", "complete"):
                return None
            time.sleep(0.2)
        return None

    _value, error = run_in_chromium(
        action,
        timeout=timeout,
        label="direct Chromium navigation",
        initial_url=url,
    )
    return error


def run_async_script(
    script: str,
    *,
    timeout: int,
    url: str = "about:blank",
) -> tuple[Any | None, str | None]:
    """Run callback-style async JavaScript in Chromium via DevTools."""
    timeout_ms = max(3000, int(timeout) * 1000)
    script_source = json.dumps(script)

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
  setTimeout(() => finishOnce({{ok: false, error: "direct Chromium script timed out"}}), {timeout_ms});
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
            timeout_ms=timeout_ms + 1000,
            await_promise=True,
        )

    return run_in_chromium(
        action,
        timeout=timeout,
        label="direct Chromium async script",
        initial_url=url,
    )


def fetch_browser_json(
    url: str,
    *,
    timeout: int = 25,
    cache_bust: bool = False,
) -> tuple[dict[str, Any] | None, str | None]:
    target = url
    if cache_bust:
        sep = "&" if "?" in target else "?"
        target = f"{target}{sep}t={int(time.time())}"
    text, error = navigate_and_read_text(target, timeout=timeout)
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
