#!/usr/bin/env python3
"""Shared browser detection helpers for ``detections/browser/*.py`` scripts."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from typing import Any

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
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
]

DEFAULT_TIMEOUT = 8
DEFAULT_PAGE_LOAD_TIMEOUT = 15
DEFAULT_SCRIPT_TIMEOUT = 20
DRIVER_COMMAND_TIMEOUT = 25
DRIVER_START_TIMEOUT = 25
DEFAULT_REPORT_WIDTH = 60

_WINDOW_WIDTH = 1920
_WINDOW_HEIGHT = 1080


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
    return _first_existing_path("/usr/bin/chromedriver", "/usr/lib/chromium/chromedriver")


def close_driver(driver: webdriver.Remote | None) -> None:
    """Stop Chromium without waiting indefinitely on a stuck ChromeDriver quit."""
    if driver is None:
        return
    try:
        driver.service.process.kill()
    except Exception:
        pass
    try:
        driver.quit()
    except Exception:
        pass


def _start_chrome_driver(opts: Options) -> webdriver.Remote:
    """Start Chrome with bounded startup wait and default page/script timeouts."""
    driver_path = _chromedriver_binary()
    service = (
        ChromeService(executable_path=driver_path)
        if driver_path
        else ChromeService()
    )
    holder: dict[str, webdriver.Remote] = {}
    error_holder: dict[str, BaseException] = {}

    def _start() -> None:
        try:
            holder["driver"] = webdriver.Chrome(service=service, options=opts)
        except BaseException as exc:
            error_holder["error"] = exc
            try:
                service.stop()
            except Exception:
                pass

    thread = threading.Thread(target=_start, daemon=True, name="overdrive-chrome-start")
    thread.start()
    thread.join(timeout=DRIVER_START_TIMEOUT)
    if thread.is_alive():
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


def build_driver() -> webdriver.Chrome:
    """Build a Chrome/Chromium WebDriver with common headless options for browser detection."""
    opts = Options()
    chromium = _chromium_binary()
    version = _chrome_full_version(chromium)
    user_agent = _desktop_chrome_user_agent(chromium)
    opts.page_load_strategy = "eager"
    opts.add_argument("--headless=new")
    opts.add_argument("--enable-webgl")
    opts.add_argument("--ignore-gpu-blocklist")
    opts.add_argument("--use-gl=swiftshader")
    opts.add_argument("--enable-unsafe-swiftshader")
    opts.add_argument("--disable-gpu-sandbox")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--autoplay-policy=no-user-gesture-required")
    opts.add_argument("--disable-features=AudioServiceOutOfProcess")
    opts.add_argument("--lang=en-US")
    opts.add_argument("--host-resolver-rules=MAP localhost 127.0.0.1,MAP [::1] 127.0.0.1")
    opts.add_argument(f"--window-size={_WINDOW_WIDTH},{_WINDOW_HEIGHT}")
    opts.add_argument(f"--user-agent={user_agent}")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_argument("--disable-blink-features=AutomationControlled")

    if chromium:
        opts.binary_location = chromium

    driver = _start_chrome_driver(opts)
    _apply_headless_stealth(driver, user_agent, version)
    return driver


def build_driver_with_fallback() -> webdriver.Remote:
    """
    Build the standard Chrome WebDriver, falling back to headless Firefox.

    Most browser probes prefer Chrome/Chromium because Client Hints and
    automation signals are richer there, but a Firefox fallback lets simpler
    DOM/canvas probes still run on machines without ChromeDriver.
    """
    try:
        return build_driver()
    except Exception as chrome_error:
        chrome_msg = str(chrome_error)

    try:
        opts = FirefoxOptions()
        opts.add_argument("-headless")
        return webdriver.Firefox(options=opts)
    except Exception as firefox_error:
        raise RuntimeError(
            "No suitable webdriver found. "
            f"Chrome error: {chrome_msg}; Firefox error: {firefox_error}"
        ) from firefox_error


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
        driver.set_page_load_timeout(timeout)
        driver.set_script_timeout(min(timeout, DRIVER_COMMAND_TIMEOUT))
        target = url
        if cache_bust:
            sep = "&" if "?" in url else "?"
            target = f"{url}{sep}t={int(time.time())}"
        try:
            driver.get(target)
        except TimeoutException:
            return None, f"Page load timed out after {timeout}s for {url}"
        # Cap JSON polling so a stuck page cannot burn the full suite budget.
        poll_timeout = min(timeout, 12)
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
