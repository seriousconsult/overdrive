#!/usr/bin/env python3
"""Shared browser detection helpers for ``detections/browser/*.py`` scripts."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By

try:
    import requests
except ImportError:  # Minimal guests may only need Selenium for browser probes.
    requests = None  # type: ignore[assignment]

__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_PAGE_LOAD_TIMEOUT",
    "DEFAULT_SCRIPT_TIMEOUT",
    "DRIVER_COMMAND_TIMEOUT",
    "DEFAULT_REPORT_WIDTH",
    "build_driver",
    "build_driver_with_fallback",
    "close_driver",
    "fetch_json",
    "fetch_browser_json",
    "is_browser_timeout_error",
    "normalize_ip_fields",
    "ipv4_like_strings",
    "is_private_ipv4",
    "collect_diagnostics_memory",
    "extract_json_text_from_page",
    "print_browser_detection_header",
    "print_browser_detection_score_footer",
    "print_browser_probe_error",
    "browser_runtime_diagnostics",
    "shared_chrome_session",
    "start_shared_chrome",
    "stop_shared_chrome",
]

_IS_LINUX = sys.platform.startswith("linux")


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


DEFAULT_TIMEOUT = _env_int("OVERDRIVE_BROWSER_TIMEOUT", 8)
DEFAULT_PAGE_LOAD_TIMEOUT = _env_int("OVERDRIVE_BROWSER_PAGE_LOAD_TIMEOUT", 10)
DEFAULT_SCRIPT_TIMEOUT = _env_int("OVERDRIVE_BROWSER_SCRIPT_TIMEOUT", 12)
DRIVER_COMMAND_TIMEOUT = _env_int(
    "OVERDRIVE_BROWSER_DRIVER_COMMAND_TIMEOUT",
    20 if _IS_LINUX else 15,
)
DRIVER_START_TIMEOUT = _env_int(
    "OVERDRIVE_BROWSER_DRIVER_START_TIMEOUT",
    18 if _IS_LINUX else 15,
)
SHARED_CHROME_STARTUP_TIMEOUT = _env_int(
    "OVERDRIVE_BROWSER_SHARED_STARTUP_TIMEOUT",
    18 if _IS_LINUX else 15,
)
DEFAULT_REPORT_WIDTH = 60

SHARED_DEBUGGER_ENV = "OVERDRIVE_CHROME_DEBUGGER"
SHARED_SESSION_ENV = "OVERDRIVE_BROWSER_SHARED"
SHARED_DRIVER_URL_ENV = "OVERDRIVE_CHROMEDRIVER_URL"
DEFAULT_SHARED_DEBUG_PORT = 0

_WINDOW_WIDTH = 1920
_WINDOW_HEIGHT = 1080


def _pick_local_port(
    start: int = 20000,
    end: int = 60999,
    *,
    env_name: str | None = None,
) -> int:
    """Choose a localhost TCP port without relying on Selenium's IPv6 fallback helper."""
    if env_name:
        env_port = (os.environ.get(env_name) or "").strip()
        if env_port.isdigit():
            return int(env_port)

    span = max(1, end - start)
    first = start + ((os.getpid() * 37) % span)
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

    # Last resort: avoid Selenium's port=0 path, which can raise before ChromeDriver starts.
    return 9515 + (os.getpid() % 1000)


def _make_chrome_profile_dir() -> str:
    base = os.environ.get("OVERDRIVE_BROWSER_TMPDIR") or tempfile.gettempdir()
    return tempfile.mkdtemp(prefix="overdrive-chrome-", dir=base)


def _chrome_full_version(binary: str | None) -> str:
    version = "120.0.0.0"
    if binary:
        try:
            out = subprocess.check_output(
                [binary, "--version"],
                text=True,
                timeout=8,
                stderr=subprocess.DEVNULL,
            )
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", out) or re.search(r"(\d+\.\d+\.\d+)", out)
            if match:
                version = match.group(1)
                if version.count(".") == 2:
                    version += ".0"
        except (OSError, subprocess.SubprocessError):
            pass
    return version


def _desktop_chrome_user_agent(binary: str | None) -> str:
    """Desktop Windows Chrome UA (typical home profile; no HeadlessChrome brand)."""
    version = _chrome_full_version(binary)
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{version} Safari/537.36"
    )


def _chrome_ua_metadata(version: str) -> dict[str, Any]:
    major = version.split(".", 1)[0]
    brands = [
        {"brand": "Not:A-Brand", "version": "99"},
        {"brand": "Google Chrome", "version": major},
        {"brand": "Chromium", "version": major},
    ]
    full_list = [
        {"brand": "Not:A-Brand", "version": "10.0.0.0"},
        {"brand": "Google Chrome", "version": version},
        {"brand": "Chromium", "version": version},
    ]
    return {
        "brands": brands,
        "fullVersionList": full_list,
        "fullVersion": version,
        "platform": "Windows",
        "platformVersion": "15.0.0",
        "architecture": "x86",
        "model": "",
        "mobile": False,
        "bitness": "64",
        "wow64": False,
        "formFactors": ["Desktop"],
    }


def _headless_stealth_js(user_agent: str, version: str) -> str:
    """Patch JS surfaces so probes look like desktop Windows Chrome."""
    ua = json.dumps(user_agent)
    version_js = json.dumps(version)
    major = json.dumps(version.split(".", 1)[0])
    return f"""
(() => {{
  const ua = {ua};
  const fullVersion = {version_js};
  const major = {major};
  const hide = (obj, key, value) => {{
    try {{
      Object.defineProperty(obj, key, {{
        get: () => value,
        configurable: true,
      }});
    }} catch (_err) {{}}
  }};
  hide(navigator, "webdriver", undefined);
  hide(navigator, "userAgent", ua);
  hide(navigator, "appVersion", ua.replace("Mozilla/", ""));
  hide(navigator, "vendor", "Google Inc.");
  hide(navigator, "languages", Object.freeze(["en-US", "en"]));
  hide(navigator, "language", "en-US");
  hide(navigator, "platform", "Win32");
  hide(navigator, "hardwareConcurrency", 8);
  hide(navigator, "deviceMemory", 8);
  hide(navigator, "maxTouchPoints", 0);
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
  const highEntropy = {{
    architecture: "x86",
    bitness: "64",
    brands,
    formFactors: Object.freeze(["Desktop"]),
    fullVersionList,
    mobile: false,
    model: "",
    platform: "Windows",
    platformVersion: "15.0.0",
    uaFullVersion: fullVersion,
    wow64: false,
  }};
  const uaData = {{
    brands,
    mobile: false,
    platform: "Windows",
    getHighEntropyValues: (hints) => {{
      const names = Array.isArray(hints) ? hints : [];
      const out = {{}};
      for (const name of names) {{
        if (Object.prototype.hasOwnProperty.call(highEntropy, name)) {{
          out[name] = highEntropy[name];
        }}
      }}
      return Promise.resolve(out);
    }},
    toJSON: () => ({{ brands, mobile: false, platform: "Windows" }}),
  }};
  hide(navigator, "userAgentData", uaData);
  if (!window.chrome) {{
    hide(window, "chrome", {{ runtime: {{}} }});
  }}
  const plugin = {{
    name: "PDF Viewer",
    description: "Portable Document Format",
    filename: "internal-pdf-viewer",
    length: 1,
    item: () => null,
    namedItem: () => null,
  }};
  const plugins = {{
    0: plugin,
    length: 1,
    item: (i) => (i === 0 ? plugin : null),
    namedItem: (name) => (name === plugin.name ? plugin : null),
    refresh: () => {{}},
  }};
  hide(navigator, "plugins", plugins);
  hide(navigator, "mimeTypes", {{ length: 1, 0: {{ type: "application/pdf" }} }});
  hide(window, "outerWidth", {_WINDOW_WIDTH});
  hide(window, "outerHeight", {_WINDOW_HEIGHT});
  hide(window, "innerWidth", {_WINDOW_WIDTH});
  hide(window, "innerHeight", {_WINDOW_HEIGHT});
  hide(screen, "width", {_WINDOW_WIDTH});
  hide(screen, "height", {_WINDOW_HEIGHT});
  hide(screen, "availWidth", {_WINDOW_WIDTH});
  hide(screen, "availHeight", {_WINDOW_HEIGHT});
  hide(screen, "colorDepth", 24);
  hide(screen, "pixelDepth", 24);
}})();
"""


def _apply_headless_stealth(driver: webdriver.Remote, user_agent: str, version: str) -> None:
    """Hide HeadlessChrome/webdriver so in-page probes look like desktop Windows Chrome."""
    script = _headless_stealth_js(user_agent, version)
    metadata = _chrome_ua_metadata(version)
    try:
        driver.execute_cdp_cmd(
            "Page.addScriptToEvaluateOnNewDocument",
            {"source": script},
        )
        driver.execute_cdp_cmd(
            "Network.setUserAgentOverride",
            {
                "userAgent": user_agent,
                "platform": "Windows",
                "acceptLanguage": "en-US,en;q=0.9",
                "userAgentMetadata": metadata,
            },
        )
        driver.execute_cdp_cmd("Emulation.setLocaleOverride", {"locale": "en-US"})
    except Exception:
        pass
    try:
        driver.execute_script(script)
    except Exception:
        pass


def _first_existing_path(*candidates: str) -> str | None:
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _chromium_binary() -> str | None:
    """Locate Chrome/Chromium for Selenium (Alpine uses chromium, not google-chrome)."""
    env = (os.environ.get("CHROME_BIN") or os.environ.get("CHROMIUM_BIN") or "").strip()
    if env and os.path.isfile(env):
        return env
    which = shutil.which("chromium-browser") or shutil.which("chromium") or shutil.which(
        "google-chrome"
    ) or shutil.which("google-chrome-stable")
    if which:
        return which
    return _first_existing_path(
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    )


def _chromedriver_binary() -> str | None:
    env = (os.environ.get("CHROMEDRIVER_PATH") or "").strip()
    if env and os.path.isfile(env):
        return env
    which = shutil.which("chromedriver")
    if which:
        return which
    return _first_existing_path(
        "/usr/local/bin/chromedriver",
        "/usr/bin/chromedriver",
        "/usr/lib/chromium/chromedriver",
    )


def _command_version(binary: str | None) -> str:
    if not binary:
        return "(missing)"
    try:
        out = subprocess.check_output(
            [binary, "--version"],
            text=True,
            timeout=5,
            stderr=subprocess.STDOUT,
        )
        return out.strip() or "(no version output)"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"(version check failed: {type(exc).__name__}: {exc})"


def browser_runtime_diagnostics() -> dict[str, str]:
    chromium = _chromium_binary()
    chromedriver = _chromedriver_binary()
    return {
        "chromium": chromium or "(missing)",
        "chromium_version": _command_version(chromium),
        "chromedriver": chromedriver or "(missing)",
        "chromedriver_version": _command_version(chromedriver),
    }


def _is_shared_browser_session() -> bool:
    return os.environ.get(SHARED_SESSION_ENV) == "1"


def _attach_debugger_address() -> str | None:
    debugger = (os.environ.get(SHARED_DEBUGGER_ENV) or "").strip()
    return debugger or None


def _chrome_profile(chromium: str | None) -> tuple[str, str]:
    version = _chrome_full_version(chromium)
    user_agent = _desktop_chrome_user_agent(chromium)
    return version, user_agent


def _headless_args() -> list[str]:
    configured = (os.environ.get("OVERDRIVE_CHROME_HEADLESS_ARG") or "").strip()
    if configured:
        return [configured]
    return ["--headless=new", "--headless=chrome", "--headless"]


def _chrome_launch_arguments(
    chromium: str | None,
    *,
    profile_dir: str | None = None,
    headless_arg: str | None = None,
) -> list[str]:
    """CLI flags shared by Selenium launches and the long-lived shared Chromium."""
    _version, user_agent = _chrome_profile(chromium)
    args = [
        headless_arg or _headless_args()[0],
        "--enable-webgl",
        "--ignore-gpu-blocklist",
        "--use-gl=swiftshader",
        "--enable-unsafe-swiftshader",
        "--disable-gpu-sandbox",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--autoplay-policy=no-user-gesture-required",
        "--disable-features=AudioServiceOutOfProcess",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-breakpad",
        "--disable-crash-reporter",
        "--disable-crashpad",
        "--disable-crashpad-for-testing",
        "--crash-dumps-dir=/tmp",
        "--noerrdialogs",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-zygote",
        "--password-store=basic",
        "--lang=en-US",
        "--host-resolver-rules=MAP localhost 127.0.0.1,MAP [::1] 127.0.0.1",
        f"--window-size={_WINDOW_WIDTH},{_WINDOW_HEIGHT}",
        f"--user-agent={user_agent}",
        "--disable-blink-features=AutomationControlled",
    ]
    if profile_dir:
        args.append(f"--user-data-dir={profile_dir}")
    return args


def _apply_chrome_options(
    opts: Options,
    chromium: str | None,
    *,
    profile_dir: str | None = None,
    headless_arg: str | None = None,
) -> None:
    _version, user_agent = _chrome_profile(chromium)
    opts.page_load_strategy = "eager"
    for arg in _chrome_launch_arguments(
        chromium,
        profile_dir=profile_dir,
        headless_arg=headless_arg,
    ):
        opts.add_argument(arg)
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_experimental_option("detach", True)
    if chromium:
        opts.binary_location = chromium


def close_driver(driver: webdriver.Remote | None) -> None:
    """Stop Chromium without waiting indefinitely on a stuck ChromeDriver quit."""
    if driver is None:
        return
    shared = _is_shared_browser_session()
    if shared:
        # The runner owns the shared Chromium/ChromeDriver processes. A probe
        # that attaches to that browser should not ask ChromeDriver to close it.
        return
    profile_dir = getattr(driver, "_overdrive_profile_dir", None)
    try:
        _quit_driver_with_timeout(driver, timeout=3)
    except Exception:
        pass
    try:
        driver.service.process.kill()
    except Exception:
        pass
    if isinstance(profile_dir, str) and profile_dir:
        shutil.rmtree(profile_dir, ignore_errors=True)


def _quit_driver_with_timeout(driver: webdriver.Remote, timeout: int = 3) -> None:
    done = threading.Event()

    def _quit() -> None:
        try:
            driver.quit()
        except Exception:
            pass
        finally:
            done.set()

    thread = threading.Thread(target=_quit, daemon=True, name="overdrive-driver-quit")
    thread.start()
    done.wait(timeout=max(1, timeout))


def _start_chrome_driver(opts: Options) -> webdriver.Remote:
    """Start Chrome with bounded startup wait and default page/script timeouts."""
    remote_url = (os.environ.get(SHARED_DRIVER_URL_ENV) or "").strip()
    service: ChromeService | None = None
    if not remote_url:
        driver_path = _chromedriver_binary()
        if not driver_path:
            raise RuntimeError(
                "chromedriver not found. Rerun install.py, install chromium-chromedriver "
                "on Alpine, or set CHROMEDRIVER_PATH."
            )
        service_args = ["--allowed-ips=127.0.0.1", "--allowed-origins=*"]
        port = _pick_local_port(env_name="OVERDRIVE_CHROMEDRIVER_PORT")
        service = ChromeService(
            executable_path=driver_path,
            port=port,
            service_args=service_args,
        )
    holder: dict[str, webdriver.Remote] = {}
    error_holder: dict[str, BaseException] = {}

    def _start() -> None:
        try:
            if remote_url:
                holder["driver"] = webdriver.Remote(command_executor=remote_url, options=opts)
            else:
                holder["driver"] = webdriver.Chrome(service=service, options=opts)
        except BaseException as exc:
            error_holder["error"] = exc
            if service is not None:
                try:
                    service.stop()
                except Exception:
                    pass

    thread = threading.Thread(target=_start, daemon=True, name="overdrive-chrome-start")
    thread.start()
    thread.join(timeout=DRIVER_START_TIMEOUT)
    if thread.is_alive():
        if service is not None:
            try:
                service.stop()
            except Exception:
                pass
        raise TimeoutError(
            f"Chrome did not start within {DRIVER_START_TIMEOUT}s "
            f"(ChromeDriver command timeout={DRIVER_COMMAND_TIMEOUT}s)"
        )
    if "error" in error_holder:
        raise error_holder["error"]
    if "driver" not in holder:
        raise RuntimeError("Chrome start thread finished without a driver")
    driver = holder["driver"]
    driver.set_page_load_timeout(DEFAULT_PAGE_LOAD_TIMEOUT)
    driver.set_script_timeout(DEFAULT_SCRIPT_TIMEOUT)
    return driver


def _build_attached_driver(debugger: str) -> webdriver.Chrome:
    """Attach to an already-running Chromium started with --remote-debugging-port."""
    opts = Options()
    opts.add_experimental_option("debuggerAddress", debugger)
    opts.add_experimental_option("detach", True)
    chromium = _chromium_binary()
    version, user_agent = _chrome_profile(chromium)
    driver = _start_chrome_driver(opts)
    _apply_headless_stealth(driver, user_agent, version)
    return driver


def build_driver() -> webdriver.Chrome:
    """Build a Chrome/Chromium WebDriver with common headless options for browser detection."""
    debugger = _attach_debugger_address()
    if debugger:
        return _build_attached_driver(debugger)

    opts = Options()
    chromium = _chromium_binary()
    version, user_agent = _chrome_profile(chromium)
    failures: list[str] = []
    for headless_arg in _headless_args():
        opts = Options()
        profile_dir = _make_chrome_profile_dir()
        _apply_chrome_options(
            opts,
            chromium,
            profile_dir=profile_dir,
            headless_arg=headless_arg,
        )

        try:
            driver = _start_chrome_driver(opts)
            setattr(driver, "_overdrive_profile_dir", profile_dir)
            _apply_headless_stealth(driver, user_agent, version)
            return driver
        except BaseException as exc:
            failures.append(f"{headless_arg}: {type(exc).__name__}: {exc}"[:500])
            shutil.rmtree(profile_dir, ignore_errors=True)

    raise RuntimeError("Chrome failed to start with all headless modes: " + " || ".join(failures))


@dataclass
class SharedChromeSession:
    proc: subprocess.Popen
    debugger_address: str
    profile_dir: str
    chrome_log_path: str | None = None
    driver_proc: subprocess.Popen | None = None
    driver_url: str | None = None
    driver_log_path: str | None = None


def _read_small(path: str | None, limit: int = 3000) -> str:
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            data = handle.read(limit)
    except OSError:
        return ""
    return data.strip()


def _wait_for_chromedriver(url: str, proc: subprocess.Popen, timeout: int, log_path: str) -> None:
    deadline = time.monotonic() + max(1, timeout)
    status_url = f"{url.rstrip('/')}/status"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log_tail = _read_small(log_path)
            extra = f": {log_tail}" if log_tail else ""
            raise RuntimeError(f"ChromeDriver exited early (code {proc.returncode}){extra}")
        try:
            with urllib.request.urlopen(status_url, timeout=1) as resp:
                if resp.status == 200:
                    return
        except OSError:
            time.sleep(0.25)
    log_tail = _read_small(log_path)
    extra = f": {log_tail}" if log_tail else ""
    raise TimeoutError(f"ChromeDriver did not become ready within {timeout}s{extra}")


def _start_shared_chromedriver(port: int) -> tuple[subprocess.Popen, str, str]:
    driver = _chromedriver_binary()
    if not driver:
        raise RuntimeError(
            "chromedriver not found. Rerun install.py, install chromium-chromedriver "
            "on Alpine, or set CHROMEDRIVER_PATH."
        )
    fd, log_path = tempfile.mkstemp(prefix="overdrive-chromedriver-", suffix=".log")
    os.close(fd)
    log_handle = open(log_path, "a", encoding="utf-8", errors="replace")
    args = [
        driver,
        f"--port={port}",
        "--allowed-ips=127.0.0.1",
        "--allowed-origins=*",
        "--verbose",
    ]
    proc = subprocess.Popen(
        args,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )
    try:
        log_handle.close()
    except OSError:
        pass
    url = f"http://127.0.0.1:{port}"
    _wait_for_chromedriver(url, proc, 10, log_path)
    return proc, url, log_path


def _wait_for_debugger_port(port: int, proc: subprocess.Popen, timeout: int) -> None:
    url = f"http://127.0.0.1:{port}/json/version"
    deadline = time.monotonic() + max(1, timeout)
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"Shared Chromium exited early (code {proc.returncode})"
            )
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except OSError:
            time.sleep(0.5)
    raise TimeoutError(f"Shared Chromium did not start within {timeout}s")


def _start_chromium_once(
    chromium: str,
    debug_port: int,
    profile_dir: str,
    headless_arg: str,
) -> tuple[subprocess.Popen, str]:
    fd, log_path = tempfile.mkstemp(prefix="overdrive-chromium-", suffix=".log")
    os.close(fd)
    log_handle = open(log_path, "a", encoding="utf-8", errors="replace")
    args = [
        chromium,
        "--remote-debugging-address=127.0.0.1",
        f"--remote-debugging-port={debug_port}",
        *_chrome_launch_arguments(
            chromium,
            profile_dir=profile_dir,
            headless_arg=headless_arg,
        ),
    ]
    proc = subprocess.Popen(
        args,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )
    try:
        log_handle.close()
    except OSError:
        pass
    return proc, log_path


def start_shared_chrome(
    debug_port: int = 0,
    *,
    startup_timeout: int | None = None,
) -> SharedChromeSession:
    """Launch one headless Chromium for the whole browser detection suite."""
    chromium = _chromium_binary()
    if not chromium:
        raise RuntimeError("Chromium binary not found")
    if not _chromedriver_binary():
        raise RuntimeError(
            "chromedriver not found. Rerun install.py, install chromium-chromedriver "
            "on Alpine, or set CHROMEDRIVER_PATH."
        )

    timeout = startup_timeout or SHARED_CHROME_STARTUP_TIMEOUT
    if debug_port <= 0:
        debug_port = _pick_local_port(env_name="OVERDRIVE_CHROME_DEBUG_PORT")
    failures: list[str] = []

    for headless_arg in _headless_args():
        profile_dir = _make_chrome_profile_dir()
        proc, chrome_log = _start_chromium_once(
            chromium,
            debug_port,
            profile_dir,
            headless_arg,
        )
        session = SharedChromeSession(
            proc=proc,
            debugger_address=f"127.0.0.1:{debug_port}",
            profile_dir=profile_dir,
            chrome_log_path=chrome_log,
        )
        try:
            _wait_for_debugger_port(debug_port, proc, timeout)
            driver_port = _pick_local_port(env_name="OVERDRIVE_CHROMEDRIVER_PORT")
            driver_proc, driver_url, driver_log = _start_shared_chromedriver(driver_port)
            session.driver_proc = driver_proc
            session.driver_url = driver_url
            session.driver_log_path = driver_log
            return session
        except BaseException as exc:
            log_tail = _read_small(chrome_log)
            detail = f"{headless_arg}: {type(exc).__name__}: {exc}"
            if log_tail:
                detail += f" | chromium log: {log_tail}"
            failures.append(detail[:1200])
            stop_shared_chrome(session)

    raise RuntimeError("Shared Chromium failed to start with all headless modes: " + " || ".join(failures))


def stop_shared_chrome(session: SharedChromeSession | None) -> None:
    if session is None:
        return
    if session.driver_proc is not None and session.driver_proc.poll() is None:
        session.driver_proc.terminate()
        try:
            session.driver_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            session.driver_proc.kill()
    if session.driver_log_path:
        try:
            os.unlink(session.driver_log_path)
        except OSError:
            pass
    if session.chrome_log_path:
        try:
            os.unlink(session.chrome_log_path)
        except OSError:
            pass
    proc = session.proc
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
    shutil.rmtree(session.profile_dir, ignore_errors=True)


@contextmanager
def shared_chrome_session(
    debug_port: int = DEFAULT_SHARED_DEBUG_PORT,
    *,
    startup_timeout: int | None = None,
) -> Iterator[SharedChromeSession]:
    """Context manager: one Chromium for many probe subprocesses via debugger attach."""
    session: SharedChromeSession | None = None
    previous_debugger = os.environ.get(SHARED_DEBUGGER_ENV)
    previous_shared = os.environ.get(SHARED_SESSION_ENV)
    previous_driver_url = os.environ.get(SHARED_DRIVER_URL_ENV)
    try:
        session = start_shared_chrome(debug_port, startup_timeout=startup_timeout)
        os.environ[SHARED_DEBUGGER_ENV] = session.debugger_address
        os.environ[SHARED_SESSION_ENV] = "1"
        if session.driver_url:
            os.environ[SHARED_DRIVER_URL_ENV] = session.driver_url
        yield session
    finally:
        if previous_debugger is None:
            os.environ.pop(SHARED_DEBUGGER_ENV, None)
        else:
            os.environ[SHARED_DEBUGGER_ENV] = previous_debugger
        if previous_shared is None:
            os.environ.pop(SHARED_SESSION_ENV, None)
        else:
            os.environ[SHARED_SESSION_ENV] = previous_shared
        if previous_driver_url is None:
            os.environ.pop(SHARED_DRIVER_URL_ENV, None)
        else:
            os.environ[SHARED_DRIVER_URL_ENV] = previous_driver_url
        stop_shared_chrome(session)


def build_driver_with_fallback() -> webdriver.Remote:
    """
    Build the standard Chrome WebDriver.

    Older versions tried Firefox through Selenium Manager when Chrome failed.
    In the Alpine client that fallback can hang for a long time and does not
    exercise the same browser surface, so browser detections now require the
    Chromium + ChromeDriver runtime installed by ``install.py``.
    """
    try:
        return build_driver()
    except Exception as chrome_error:
        raise RuntimeError(
            "Unable to start Chromium WebDriver. Browser detections require "
            "working chromium + chromedriver; rerun /root/install.py --non-interactive "
            f"inside the Alpine client if either is missing. Chrome error: {chrome_error}"
        ) from chrome_error


def fetch_json(
    url: str,
    params: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """GET JSON from a URL with a stable User-Agent (GeoIP / API probes)."""
    if requests is None:
        raise RuntimeError("The requests package is required for fetch_json()")
    r = requests.get(
        url,
        params=params,
        timeout=timeout,
        headers={"User-Agent": "geo-leak-check/1.0"},
    )
    r.raise_for_status()
    return r.json()


def fetch_browser_json(
    url: str,
    *,
    timeout: int = 25,
    cache_bust: bool = False,
) -> tuple[dict[str, Any] | None, str | None]:
    """
    Load a JSON-rendering page through the shared browser and parse the body/pre text.

    Returns ``(data, error)``. This is useful for probes that need the browser's
    real transport/header behavior rather than ``requests``.
    """
    driver = None
    try:
        driver = build_driver()
        bounded_timeout = max(3, int(timeout))
        page_timeout = min(bounded_timeout, DEFAULT_PAGE_LOAD_TIMEOUT)
        script_timeout = min(bounded_timeout, DEFAULT_SCRIPT_TIMEOUT, DRIVER_COMMAND_TIMEOUT)
        driver.set_page_load_timeout(page_timeout)
        driver.set_script_timeout(script_timeout)
        target = url
        if cache_bust:
            sep = "&" if "?" in url else "?"
            target = f"{url}{sep}t={int(time.time())}"
        try:
            driver.get(target)
        except TimeoutException:
            return None, f"Page load timed out after {page_timeout}s for {url}"
        # Cap JSON polling so a stuck page cannot burn the full suite budget.
        poll_timeout = min(bounded_timeout, 6)
        raw = extract_json_text_from_page(driver, timeout=poll_timeout)
        if not raw:
            return None, "Could not parse JSON from browser probe page."
        try:
            data = json.loads(raw)
        except Exception as e:
            return None, f"JSON parse error: {type(e).__name__}: {e}"
        if isinstance(data, dict):
            return data, None
        return None, "Probe response was JSON but not an object."
    except Exception as e:
        return None, f"Browser probe failed: {type(e).__name__}: {e}"
    finally:
        close_driver(driver)


def normalize_ip_fields(provider: str, raw: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize GeoIP-style fields across ipapi.co, ip-api.com, and ipapi.is.
    Output dicts always include ``provider`` for downstream summaries.
    """
    asn_raw = raw.get("asn")
    asn_val = None
    org_from_asn = None
    if isinstance(asn_raw, dict):
        asn_val = asn_raw.get("asn")
        org_from_asn = asn_raw.get("org")

    if provider == "ipapi.is":
        loc = raw.get("location", {})
        comp = raw.get("company", {})
        cc = loc.get("country")
        if isinstance(cc, str):
            cc = cc.strip().upper() if len(cc) == 2 else None
        return {
            "provider": provider,
            "ip": raw.get("ip"),
            "city": loc.get("city"),
            "region": loc.get("state"),
            "country": loc.get("country"),
            "country_code": cc,
            "timezone": loc.get("timezone"),
            "lat": loc.get("latitude"),
            "lon": loc.get("longitude"),
            "asn": asn_val,
            "org": comp.get("name") or org_from_asn,
        }

    cc_raw = raw.get("country_code") or raw.get("countryCode")
    cc = None
    if isinstance(cc_raw, str) and len(cc_raw.strip()) == 2:
        cc = cc_raw.strip().upper()
    cname = raw.get("country_name") or raw.get("country")
    return {
        "provider": provider,
        "ip": raw.get("ip") or raw.get("query"),
        "city": raw.get("city") or raw.get("cityName"),
        "country": cname,
        "country_code": cc,
        "region": raw.get("region") or raw.get("regionName"),
        "timezone": raw.get("timezone"),
        "lat": raw.get("latitude") or raw.get("lat"),
        "lon": raw.get("longitude") or raw.get("lon"),
        "asn": asn_val or raw.get("as"),
        "org": raw.get("org") or raw.get("isp") or org_from_asn,
    }


def ipv4_like_strings(text: str) -> list[str]:
    """Extract IPv4-like strings from text using regex."""
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")


def is_private_ipv4(ip: str) -> bool:
    """
    True if ``ip`` is in RFC1918 private ranges (10/8, 172.16/12, 192.168/16).
    """
    if not ip:
        return False
    try:
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        return False
    except (ValueError, TypeError):
        return False


def collect_diagnostics_memory(driver: webdriver.Chrome) -> dict[str, Any]:
    """
    Collect screenshot PNG bytes and a page-source snippet (memory only; no disk writes).
    """
    out: dict[str, Any] = {"screenshot_png": None, "page_source_snippet": None}
    try:
        out["screenshot_png"] = driver.get_screenshot_as_png()
    except Exception:
        pass
    try:
        out["page_source_snippet"] = (driver.page_source or "")[:30000]
    except Exception:
        pass
    return out


def extract_json_text_from_page(driver: webdriver.Chrome, timeout: int = 25) -> str | None:
    """
    Read JSON rendered in ``<pre>`` or raw body text (e.g. tls.peet.ws/api/all).
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            pre = driver.find_element(By.TAG_NAME, "pre")
            text = (pre.text or "").strip()
            if text.startswith("{") and text.endswith("}"):
                return text
        except Exception:
            pass

        try:
            text = driver.find_element(By.TAG_NAME, "body").text.strip()
            if text.startswith("{") and text.endswith("}"):
                return text
        except Exception:
            pass

        time.sleep(0.25)

    return None


def print_browser_detection_header(title: str, *, width: int = DEFAULT_REPORT_WIDTH) -> None:
    """Standard ``====`` banner + title (matches placeholder browser scripts)."""
    bar = "=" * width
    print(bar)
    print(title)
    print(bar)
    print()


def print_browser_detection_score_footer(
    score: int,
    description: str,
    *,
    width: int = DEFAULT_REPORT_WIDTH,
) -> None:
    """Print ``Score:`` / description / closing bar."""
    print(f"Score: {score}")
    print(f"  {description}")
    print()
    print("=" * width)


def is_browser_timeout_error(message: str | None) -> bool:
    """True when a probe failure string looks like a timeout / hung driver."""
    if not message:
        return False
    text = message.lower()
    return any(
        needle in text
        for needle in (
            "timeout",
            "timed out",
            "read timed out",
            "did not start within",
            "did not finish within",
        )
    )


def print_browser_probe_error(reason: str, *, width: int = DEFAULT_REPORT_WIDTH) -> int:
    """
    Report a non-scorable probe failure.

    Timeouts and driver crashes are not authenticity scores (1-5). Prints
    ``SCORE: Error`` and returns exit code 2 for the suite runner.
    """
    label = "TIMEOUT" if is_browser_timeout_error(reason) else "ERROR"
    print(f"SCORE: Error")
    print(f"STATUS: {label}: {reason}")
    print()
    print("=" * width)
    return 2
