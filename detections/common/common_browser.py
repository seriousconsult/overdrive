#!/usr/bin/env python3
"""Shared browser detection helpers for ``detections/browser/*.py`` scripts."""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from typing import Any

import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_REPORT_WIDTH",
    "build_driver",
    "build_driver_with_fallback",
    "fetch_json",
    "fetch_browser_json",
    "normalize_ip_fields",
    "ipv4_like_strings",
    "is_private_ipv4",
    "collect_diagnostics_memory",
    "extract_json_text_from_page",
    "print_browser_detection_header",
    "print_browser_detection_score_footer",
]

DEFAULT_TIMEOUT = 8
DEFAULT_REPORT_WIDTH = 60


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


def build_driver() -> webdriver.Chrome:
    """Build a Chrome/Chromium WebDriver with common headless options for browser detection."""
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--enable-webgl")
    opts.add_argument("--ignore-gpu-blocklist")
    opts.add_argument("--use-gl=swiftshader")
    opts.add_argument("--enable-unsafe-swiftshader")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,800")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_argument("--disable-blink-features=AutomationControlled")

    chromium = _chromium_binary()
    if chromium:
        opts.binary_location = chromium

    driver_path = _chromedriver_binary()
    if driver_path:
        return webdriver.Chrome(service=ChromeService(executable_path=driver_path), options=opts)
    return webdriver.Chrome(options=opts)


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
        target = url
        if cache_bust:
            sep = "&" if "?" in url else "?"
            target = f"{url}{sep}t={int(time.time())}"
        driver.get(target)
        raw = extract_json_text_from_page(driver, timeout=timeout)
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
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass


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
    try:
        pre = WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located((By.TAG_NAME, "pre"))
        )
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
