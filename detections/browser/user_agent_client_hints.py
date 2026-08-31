#!/usr/bin/env python3
"""
User-Agent and User-Agent Client Hints identification.

Runs Chromium through DevTools, serves a local localhost page, and captures:

- Request User-Agent and Sec-CH-UA* headers seen by a server.
- JavaScript-visible navigator.userAgent and navigator.userAgentData.
- High-entropy User-Agent Client Hints from getHighEntropyValues when supported.
- Coherence checks between UA, Client Hints, platform/mobile flags, and automation signals.

Score:
  1 = coherent, ordinary browser UA + Client Hints profile
  2 = mostly coherent with minor gaps or privacy reductions
  3 = inconclusive, no browser, or limited data
  4 = strong mismatch/spoofing/automation signal
  5 = severe non-browser or automation profile
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from detections.common.common_browser import (
        DEFAULT_TIMEOUT,
        print_browser_detection_header,
    )
    from detections.common.direct_chromium import navigate

    BROWSER_HELPER_IMPORT_ERROR: Exception | None = None
except Exception as exc:
    DEFAULT_TIMEOUT = 0
    navigate = None  # type: ignore[assignment]
    BROWSER_HELPER_IMPORT_ERROR = exc

    def print_browser_detection_header(title: str, *, width: int = 64) -> None:
        bar = "=" * width
        print(bar)
        print(title)
        print(bar)
        print()


CLIENT_HINT_HEADERS = (
    "Sec-CH-UA",
    "Sec-CH-UA-Mobile",
    "Sec-CH-UA-Platform",
    "Sec-CH-UA-Platform-Version",
    "Sec-CH-UA-Arch",
    "Sec-CH-UA-Bitness",
    "Sec-CH-UA-Full-Version",
    "Sec-CH-UA-Full-Version-List",
    "Sec-CH-UA-Model",
    "Sec-CH-UA-WoW64",
    "Sec-CH-UA-Form-Factors",
)

PERMISSIONS_POLICY = (
    "ch-ua=*, ch-ua-mobile=*, ch-ua-platform=*, ch-ua-platform-version=*, "
    "ch-ua-arch=*, ch-ua-bitness=*, ch-ua-full-version=*, "
    "ch-ua-full-version-list=*, ch-ua-model=*, ch-ua-wow64=*, ch-ua-form-factors=*"
)

UA_LIBRARY_RE = re.compile(
    r"\b(?:python|httpx|requests|urllib|aiohttp|curl|wget|httpie|okhttp|go-http-client)\b",
    re.I,
)
UA_HEADLESS_RE = re.compile(r"HeadlessChrome|PhantomJS|SlimerJS", re.I)
UA_CHROME_RE = re.compile(r"\b(?:HeadlessChrome|Chrome|Chromium|CriOS|Edg|OPR)/(\d+)", re.I)
UA_FIREFOX_RE = re.compile(r"\bFirefox/(\d+)", re.I)
UA_SAFARI_RE = re.compile(r"\bVersion/(\d+).+Safari/", re.I)


def _html_page() -> bytes:
    return b"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>UA Client Hints Probe</title></head>
<body>
<pre id="status">collecting</pre>
<script>
(async function () {
  const highEntropyNames = [
    "architecture",
    "bitness",
    "brands",
    "formFactors",
    "fullVersionList",
    "mobile",
    "model",
    "platform",
    "platformVersion",
    "uaFullVersion",
    "wow64"
  ];
  const nav = navigator;
  const uaData = nav.userAgentData ? {
    brands: Array.from(nav.userAgentData.brands || []),
    mobile: nav.userAgentData.mobile,
    platform: nav.userAgentData.platform || ""
  } : null;
  let highEntropy = null;
  let highEntropyError = null;
  if (nav.userAgentData && nav.userAgentData.getHighEntropyValues) {
    try {
      highEntropy = await nav.userAgentData.getHighEntropyValues(highEntropyNames);
    } catch (e) {
      highEntropyError = String(e && (e.stack || e.message || e));
    }
  }
  const payload = {
    location: location.href,
    timestamp: Date.now(),
    navigator: {
      userAgent: nav.userAgent || "",
      appVersion: nav.appVersion || "",
      platform: nav.platform || "",
      vendor: nav.vendor || "",
      product: nav.product || "",
      productSub: nav.productSub || "",
      language: nav.language || "",
      languages: Array.from(nav.languages || []),
      webdriver: nav.webdriver,
      cookieEnabled: nav.cookieEnabled,
      doNotTrack: nav.doNotTrack || "",
      hardwareConcurrency: nav.hardwareConcurrency || null,
      deviceMemory: nav.deviceMemory || null,
      maxTouchPoints: nav.maxTouchPoints || 0,
      pdfViewerEnabled: nav.pdfViewerEnabled
    },
    userAgentData: uaData,
    highEntropyUserAgentData: highEntropy,
    highEntropyError: highEntropyError,
    screen: {
      width: screen.width,
      height: screen.height,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      colorDepth: screen.colorDepth,
      pixelDepth: screen.pixelDepth,
      devicePixelRatio: window.devicePixelRatio
    }
  };
  try {
    await fetch("/report", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
    document.getElementById("status").textContent = "complete";
  } catch (e) {
    document.getElementById("status").textContent = "report failed: " + String(e);
  }
})();
</script>
</body>
</html>
"""


def _headers_to_dict(headers) -> dict[str, str]:
    return {str(k): str(v) for k, v in headers.items()}


class ProbeState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.done = threading.Event()
        self.requests: list[dict[str, Any]] = []
        self.report: dict[str, Any] | None = None
        self.report_headers: dict[str, str] = {}

    def record_request(self, method: str, path: str, headers: dict[str, str]) -> None:
        with self.lock:
            self.requests.append(
                {
                    "ts": time.time(),
                    "method": method,
                    "path": path,
                    "headers": headers,
                }
            )

    def record_report(self, headers: dict[str, str], report: dict[str, Any]) -> None:
        with self.lock:
            self.report_headers = headers
            self.report = report
        self.done.set()


def make_handler(state: ProbeState):
    class UAProbeHandler(BaseHTTPRequestHandler):
        server_version = "OverdriveUAProbe/1.0"

        def log_message(self, _fmt: str, *_args) -> None:
            return

        def _send_common_headers(self, status: int, content_type: str = "text/plain; charset=utf-8") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Accept-CH", ", ".join(CLIENT_HINT_HEADERS))
            self.send_header("Critical-CH", ", ".join(CLIENT_HINT_HEADERS[:8]))
            self.send_header("Permissions-Policy", PERMISSIONS_POLICY)
            self.send_header("Vary", ", ".join(CLIENT_HINT_HEADERS))

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            state.record_request("GET", path, _headers_to_dict(self.headers))
            if path == "/favicon.ico":
                self._send_common_headers(204)
                self.end_headers()
                return
            self._send_common_headers(200, "text/html; charset=utf-8")
            body = _html_page()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            headers = _headers_to_dict(self.headers)
            state.record_request("POST", path, headers)
            length = int(headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8", errors="replace"))
            except Exception as exc:
                payload = {"parse_error": f"{type(exc).__name__}: {exc}", "raw": raw[:4000].decode("utf-8", "replace")}
            if path == "/report" and isinstance(payload, dict):
                state.record_report(headers, payload)
            body = b'{"ok":true}'
            self._send_common_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return UAProbeHandler


def start_probe_server() -> tuple[ThreadingHTTPServer, ProbeState, str]:
    state = ProbeState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="ua-client-hints-probe")
    thread.start()
    host, port = server.server_address
    return server, state, f"http://{host}:{port}/"


def browser_family(ua: str) -> str:
    if UA_LIBRARY_RE.search(ua or ""):
        return "library"
    if UA_CHROME_RE.search(ua or ""):
        return "chromium"
    if UA_FIREFOX_RE.search(ua or ""):
        return "firefox"
    if UA_SAFARI_RE.search(ua or "") and "Chrome" not in (ua or "") and "Chromium" not in (ua or ""):
        return "webkit"
    return "unknown"


def ua_major(ua: str) -> int | None:
    for pattern in (UA_CHROME_RE, UA_FIREFOX_RE, UA_SAFARI_RE):
        match = pattern.search(ua or "")
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
    return None


def normalize_header_map(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): str(v) for k, v in (headers or {}).items()}


def unwrap_ch_value(value: str) -> str:
    s = (value or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        s = s[1:-1]
    return s.replace('\\"', '"')


def platform_from_ua(ua: str) -> str | None:
    if re.search(r"Windows|Win64|WOW64", ua or "", re.I):
        return "windows"
    if re.search(r"Android", ua or "", re.I):
        return "android"
    if re.search(r"iPhone|iPad|iPod", ua or "", re.I):
        return "ios"
    if re.search(r"Macintosh|Mac OS X", ua or "", re.I):
        return "macos"
    if re.search(r"Linux|X11", ua or "", re.I):
        return "linux"
    return None


def platform_from_ch(value: str) -> str | None:
    s = unwrap_ch_value(value).lower()
    if "windows" in s:
        return "windows"
    if "android" in s:
        return "android"
    if "iphone" in s or "ipad" in s or "ios" in s:
        return "ios"
    if "mac" in s:
        return "macos"
    if "cros" in s or "chrome os" in s:
        return "chromeos"
    if "linux" in s:
        return "linux"
    return None


def parse_brand_version_pairs(value: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for match in re.finditer(r'"((?:\\.|[^"\\])*)"\s*;\s*v="((?:\\.|[^"\\])*)"', value or ""):
        pairs.append((match.group(1).replace('\\"', '"'), match.group(2).replace('\\"', '"')))
    return pairs


def product_major_from_brands(value: str) -> int | None:
    pairs = parse_brand_version_pairs(value)
    for wanted in ("Google Chrome", "Chromium", "Microsoft Edge", "Opera", "Brave"):
        for name, version in pairs:
            if wanted.lower() in name.lower():
                try:
                    return int(str(version).split(".", 1)[0])
                except ValueError:
                    continue
    return None


def collect_browser_probe(timeout: int) -> tuple[dict[str, Any] | None, str | None]:
    if BROWSER_HELPER_IMPORT_ERROR is not None:
        return None, (
            "browser helpers unavailable: "
            f"{type(BROWSER_HELPER_IMPORT_ERROR).__name__}: {BROWSER_HELPER_IMPORT_ERROR}"
        )
    if navigate is None:
        return None, "browser helpers unavailable"

    try:
        server, state, url = start_probe_server()
    except OSError as exc:
        return None, f"local probe server could not start: {type(exc).__name__}: {exc}"

    try:
        nav_error = navigate(url, timeout=timeout if timeout and timeout > 0 else 0)
        if nav_error:
            return None, f"browser probe failed: {nav_error}"
        if timeout and timeout > 0:
            state.done.wait(timeout=timeout)
        else:
            state.done.wait()
        with state.lock:
            result = {
                "probe_url": url,
                "requests": list(state.requests),
                "report_headers": dict(state.report_headers),
                "browser_report": dict(state.report or {}),
            }
        if not result["browser_report"]:
            return result, "Browser opened, but the in-page JavaScript report was not received."
        return result, None
    except Exception as exc:
        return None, f"browser probe failed: {type(exc).__name__}: {exc}"
    finally:
        server.shutdown()
        server.server_close()


def summarize_client_hints(headers: dict[str, str]) -> dict[str, str]:
    h = normalize_header_map(headers)
    return {
        name: h[name.lower()]
        for name in CLIENT_HINT_HEADERS
        if name.lower() in h
    }


def analyze_probe(result: dict[str, Any] | None, error: str | None) -> tuple[int, str, dict[str, Any]]:
    if not result:
        return 3, f"Could not obtain browser User-Agent data. {error or 'No data returned.'}", {}

    requests = result.get("requests") or []
    nav_request = next((r for r in requests if r.get("method") == "GET" and r.get("path") == "/"), {})
    nav_headers = normalize_header_map(nav_request.get("headers") or {})
    report_headers = normalize_header_map(result.get("report_headers") or {})
    report = result.get("browser_report") or {}
    navigator = report.get("navigator") if isinstance(report.get("navigator"), dict) else {}
    ua_data = report.get("userAgentData") if isinstance(report.get("userAgentData"), dict) else None
    high = report.get("highEntropyUserAgentData") if isinstance(report.get("highEntropyUserAgentData"), dict) else None

    request_ua = nav_headers.get("user-agent") or report_headers.get("user-agent") or ""
    js_ua = str(navigator.get("userAgent") or "")
    family = browser_family(js_ua or request_ua)
    major = ua_major(js_ua or request_ua)
    ch_headers = summarize_client_hints(nav_request.get("headers") or {})
    ch_report_headers = summarize_client_hints(result.get("report_headers") or {})

    strong: list[str] = []
    soft: list[str] = []

    if error:
        soft.append(error)
    if not request_ua and not js_ua:
        strong.append("User-Agent is empty in both request headers and navigator")
    if UA_LIBRARY_RE.search(request_ua) or UA_LIBRARY_RE.search(js_ua):
        strong.append("User-Agent names a library/non-browser client")
    if UA_HEADLESS_RE.search(request_ua) or UA_HEADLESS_RE.search(js_ua):
        strong.append("User-Agent exposes headless browser")
    if navigator.get("webdriver") is True:
        strong.append("navigator.webdriver is true")
    if request_ua and js_ua and request_ua != js_ua:
        strong.append("request User-Agent and navigator.userAgent differ")
    if family == "unknown":
        soft.append("browser family could not be identified from User-Agent")

    ua_platform = platform_from_ua(js_ua or request_ua)
    ch_platform = platform_from_ch(
        (ch_report_headers.get("Sec-CH-UA-Platform") or ch_headers.get("Sec-CH-UA-Platform") or "")
    )
    js_ch_platform = platform_from_ch(str((high or ua_data or {}).get("platform") or ""))
    if ua_platform and ch_platform and ua_platform != ch_platform:
        if {ua_platform, ch_platform} == {"ios", "macos"}:
            pass
        else:
            strong.append(f"Sec-CH-UA-Platform={ch_platform} conflicts with UA platform={ua_platform}")
    if ua_platform and js_ch_platform and ua_platform != js_ch_platform:
        if {ua_platform, js_ch_platform} == {"ios", "macos"}:
            pass
        else:
            strong.append(f"navigator.userAgentData.platform={js_ch_platform} conflicts with UA platform={ua_platform}")

    sec_ch_ua = ch_report_headers.get("Sec-CH-UA") or ch_headers.get("Sec-CH-UA") or ""
    ch_major = product_major_from_brands(sec_ch_ua)
    if major is not None and ch_major is not None and abs(major - ch_major) > 1:
        strong.append(f"Sec-CH-UA product major={ch_major} conflicts with User-Agent major={major}")

    full_list = ch_report_headers.get("Sec-CH-UA-Full-Version-List") or ch_headers.get("Sec-CH-UA-Full-Version-List") or ""
    full_major = product_major_from_brands(full_list)
    if major is not None and full_major is not None and abs(major - full_major) > 1:
        strong.append(f"Sec-CH-UA-Full-Version-List major={full_major} conflicts with User-Agent major={major}")

    mobile_header = ch_report_headers.get("Sec-CH-UA-Mobile") or ch_headers.get("Sec-CH-UA-Mobile") or ""
    mobile_js = None
    if ua_data is not None and "mobile" in ua_data:
        mobile_js = bool(ua_data.get("mobile"))
    elif high is not None and "mobile" in high:
        mobile_js = bool(high.get("mobile"))
    mobile_ua = bool(re.search(r"Mobile|Android|iPhone|iPad|webOS|BlackBerry|IEMobile", js_ua or request_ua, re.I))
    if mobile_header:
        header_mobile = "?1" in mobile_header
        header_desktop = "?0" in mobile_header
        if (mobile_ua and header_desktop) or ((not mobile_ua) and header_mobile):
            strong.append("Sec-CH-UA-Mobile conflicts with mobile/desktop User-Agent pattern")
    if mobile_js is not None and mobile_js != mobile_ua:
        if not (mobile_js is False and "ipad" in (js_ua or request_ua).lower()):
            strong.append("navigator.userAgentData.mobile conflicts with mobile/desktop User-Agent pattern")

    if family == "chromium":
        if major and major >= 89 and not (sec_ch_ua or ua_data):
            soft.append("Chromium-like browser did not expose Sec-CH-UA or navigator.userAgentData")
        if not high:
            soft.append("High-entropy Client Hints were not available from navigator.userAgentData")
    elif family in ("firefox", "webkit"):
        if sec_ch_ua or ua_data or high:
            soft.append("Client Hints present on a non-Chromium family; check for UA spoofing or embedded Chromium")

    languages = navigator.get("languages") or []
    if isinstance(languages, list) and not languages:
        soft.append("navigator.languages is empty")

    if strong:
        score = 5 if len(strong) >= 2 or any("library" in item.lower() for item in strong) else 4
    elif family in ("chromium", "firefox", "webkit"):
        score = 2 if soft else 1
    else:
        score = 3

    normalized_for_hash = {
        "request_ua": request_ua,
        "navigator_ua": js_ua,
        "family": family,
        "request_client_hints": ch_headers,
        "report_client_hints": ch_report_headers,
        "userAgentData": ua_data,
        "highEntropyUserAgentData": high,
        "navigator_platform": navigator.get("platform"),
        "navigator_vendor": navigator.get("vendor"),
        "navigator_languages": navigator.get("languages"),
    }
    fingerprint_hash = hashlib.sha256(
        json.dumps(normalized_for_hash, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:24]

    details = {
        "probe_url": result.get("probe_url"),
        "request_user_agent": request_ua,
        "navigator_user_agent": js_ua,
        "family": family,
        "major": major,
        "navigator": navigator,
        "userAgentData": ua_data,
        "highEntropyUserAgentData": high,
        "highEntropyError": report.get("highEntropyError"),
        "navigation_client_hints": ch_headers,
        "report_client_hints": ch_report_headers,
        "strong_issues": strong,
        "soft_issues": soft,
        "fingerprint_hash": fingerprint_hash,
        "request_count": len(requests),
    }

    if strong:
        status = f"UA/Client-Hints profile is inconsistent: {strong[0]}"
    elif soft:
        status = f"UA/Client-Hints profile is mostly coherent with caveats: {soft[0]}"
    elif family in ("chromium", "firefox", "webkit"):
        status = "UA and available Client Hints are coherent for the detected browser family."
    else:
        status = "UA/Client-Hints data is limited or family is unknown."
    return score, status, details


def _print_mapping(title: str, mapping: dict[str, Any], *, max_value_len: int = 180) -> None:
    print(title)
    if not mapping:
        print("  -")
        return
    for key in sorted(mapping):
        value = mapping[key]
        if isinstance(value, (dict, list)):
            text = json.dumps(value, sort_keys=True, default=str)
        else:
            text = str(value)
        if len(text) > max_value_len:
            text = text[: max_value_len - 1] + "..."
        print(f"  {key}: {text}")


def print_details(details: dict[str, Any]) -> None:
    if not details:
        return
    print(f"Detected family: {details.get('family')} major={details.get('major')}")
    print(f"Fingerprint hash: {details.get('fingerprint_hash')}")
    print(f"Probe URL: {details.get('probe_url')}")
    print(f"Requests observed by local server: {details.get('request_count')}")
    print()
    print(f"Request User-Agent:   {details.get('request_user_agent') or '-'}")
    print(f"Navigator User-Agent: {details.get('navigator_user_agent') or '-'}")
    print()
    _print_mapping("Request Client Hints on navigation:", details.get("navigation_client_hints") or {})
    print()
    _print_mapping("Request Client Hints on JS report POST:", details.get("report_client_hints") or {})
    print()
    _print_mapping("navigator.userAgentData:", details.get("userAgentData") or {})
    print()
    _print_mapping("High-entropy navigator.userAgentData:", details.get("highEntropyUserAgentData") or {})
    if details.get("highEntropyError"):
        print(f"  highEntropyError: {details.get('highEntropyError')}")
    print()
    nav = details.get("navigator") or {}
    nav_sample = {
        k: nav.get(k)
        for k in (
            "platform",
            "vendor",
            "language",
            "languages",
            "webdriver",
            "hardwareConcurrency",
            "deviceMemory",
            "maxTouchPoints",
            "cookieEnabled",
            "doNotTrack",
        )
        if k in nav
    }
    _print_mapping("Navigator profile:", nav_sample)
    issues = (details.get("strong_issues") or []) + (details.get("soft_issues") or [])
    if issues:
        print()
        print("Issues / caveats:")
        for issue in issues[:10]:
            print(f"  - {issue}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Identify browser User-Agent and User-Agent Client Hints.")
    parser.add_argument("--timeout", type=int, default=max(10, DEFAULT_TIMEOUT), help="Seconds to wait for browser report.")
    args = parser.parse_args()

    print_browser_detection_header("User-Agent and Client Hints Detection")
    print("Method: local localhost browser probe + JavaScript navigator.userAgentData")
    print()

    result, error = collect_browser_probe(args.timeout)
    score, status, details = analyze_probe(result, error)
    print_details(details)
    if error and not details:
        print(f"Browser probe error: {error}")
        print()
    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    print()
    print("=" * 64)
    return score


if __name__ == "__main__":
    main()
