#!/usr/bin/env python3
"""Browser language and timezone consistency detection.

Collects locale and timezone evidence from the browser, request headers, and
the local OS. The goal is to detect inconsistencies, not to guess a user's
identity from any single noisy signal.

Score:
  1 = browser language/timezone signals are coherent with OS evidence
  2 = mostly coherent with minor caveats
  3 = limited evidence or mixed but not strongly contradictory signals
  4 = clear timezone/language inconsistency
  5 = multiple strong inconsistencies
"""

from __future__ import annotations

import argparse
import json
import locale
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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

    def print_browser_detection_header(title: str, *, width: int = 60) -> None:
        bar = "=" * width
        print(bar)
        print(title)
        print(bar)
        print()


LOCALE_RE = re.compile(r"^\s*([A-Za-z]{2,3})(?:[-_]([A-Za-z]{2}|[0-9]{3}))?")
SAMPLE_LABELS = ("now", "jan", "jul")


def _html_page() -> bytes:
    return b"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Language Timezone Probe</title></head>
<body>
<pre id="status">collecting</pre>
<script>
(async function () {
  function dateOffsetFor(monthIndex) {
    const d = new Date(Date.UTC(new Date().getUTCFullYear(), monthIndex, 15, 12, 0, 0));
    return d.getTimezoneOffset();
  }
  function tzName(style) {
    try {
      const parts = new Intl.DateTimeFormat(undefined, {timeZoneName: style}).formatToParts(new Date());
      const part = parts.find((p) => p.type === "timeZoneName");
      return part ? part.value : "";
    } catch (e) {
      return "";
    }
  }
  function supportedTimezoneCount() {
    try {
      if (Intl.supportedValuesOf) {
        return Intl.supportedValuesOf("timeZone").length;
      }
    } catch (e) {}
    return null;
  }
  const nav = navigator;
  const intl = Intl.DateTimeFormat().resolvedOptions();
  const payload = {
    timestamp: Date.now(),
    navigator: {
      language: nav.language || "",
      languages: Array.from(nav.languages || []),
      userAgent: nav.userAgent || "",
      platform: nav.platform || "",
      webdriver: nav.webdriver === true
    },
    intl: {
      locale: intl.locale || "",
      calendar: intl.calendar || "",
      numberingSystem: intl.numberingSystem || "",
      timeZone: intl.timeZone || "",
      hourCycle: intl.hourCycle || "",
      supportedTimezoneCount: supportedTimezoneCount()
    },
    date: {
      offsetMinutesNow: new Date().getTimezoneOffset(),
      offsetMinutesJan: dateOffsetFor(0),
      offsetMinutesJul: dateOffsetFor(6),
      currentString: new Date().toString(),
      currentLocaleString: new Date().toLocaleString(),
      timezoneNameShort: tzName("short"),
      timezoneNameLong: tzName("long")
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
                {"ts": time.time(), "method": method, "path": path, "headers": headers}
            )

    def record_report(self, headers: dict[str, str], report: dict[str, Any]) -> None:
        with self.lock:
            self.report_headers = headers
            self.report = report
        self.done.set()


def make_handler(state: ProbeState):
    class LanguageTimezoneHandler(BaseHTTPRequestHandler):
        server_version = "OverdriveLanguageTimezoneProbe/1.0"

        def log_message(self, _fmt: str, *_args) -> None:
            return

        def _send_common_headers(self, status: int, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            state.record_request("GET", path, _headers_to_dict(self.headers))
            if path == "/favicon.ico":
                self._send_common_headers(204, "text/plain; charset=utf-8")
                self.end_headers()
                return
            body = _html_page()
            self._send_common_headers(200, "text/html; charset=utf-8")
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
                payload = {
                    "parse_error": f"{type(exc).__name__}: {exc}",
                    "raw": raw[:4000].decode("utf-8", "replace"),
                }
            if path == "/report" and isinstance(payload, dict):
                state.record_report(headers, payload)
            body = b'{"ok":true}'
            self._send_common_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return LanguageTimezoneHandler


def start_probe_server() -> tuple[ThreadingHTTPServer, ProbeState, str]:
    state = ProbeState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
        name="language-timezone-probe",
    )
    thread.start()
    host, port = server.server_address
    return server, state, f"http://{host}:{port}/"


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


def normalize_header_map(headers: dict[str, str]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def parse_locale_tag(value: str) -> dict[str, str]:
    text = str(value or "").strip()
    text = text.split(".", 1)[0]
    if text.upper() in {"", "C", "POSIX"}:
        return {"raw": str(value or ""), "language": "", "region": "", "normalized": ""}
    match = LOCALE_RE.match(text)
    if not match:
        return {"raw": str(value or ""), "language": "", "region": "", "normalized": ""}
    language = match.group(1).lower()
    region = (match.group(2) or "").upper()
    normalized = language + (f"-{region}" if region else "")
    return {"raw": str(value or ""), "language": language, "region": region, "normalized": normalized}


def parse_accept_language(value: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for index, chunk in enumerate(str(value or "").split(",")):
        piece = chunk.strip()
        if not piece:
            continue
        tag = piece.split(";", 1)[0].strip()
        quality = 1.0
        q_match = re.search(r"(?:^|;)\s*q=([0-9.]+)", piece, re.I)
        if q_match:
            try:
                quality = float(q_match.group(1))
            except ValueError:
                quality = 0.0
        parsed = parse_locale_tag(tag)
        if parsed["language"]:
            parsed["q"] = quality
            parsed["index"] = index
            out.append(parsed)
    return sorted(out, key=lambda item: (-float(item["q"]), int(item["index"])))


def _sample_utc_datetimes() -> dict[str, datetime]:
    now = datetime.now(timezone.utc)
    year = now.year
    return {
        "now": now,
        "jan": datetime(year, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        "jul": datetime(year, 7, 15, 12, 0, 0, tzinfo=timezone.utc),
    }


def _offset_west_minutes(dt_utc: datetime, tz: ZoneInfo | None = None) -> int | None:
    try:
        local_dt = dt_utc.astimezone(tz) if tz is not None else dt_utc.astimezone()
        offset = local_dt.utcoffset()
        if offset is None:
            return None
        return int(round(-(offset.total_seconds() / 60)))
    except Exception:
        return None


def offset_profile_for_zone(zone_name: str) -> dict[str, int] | None:
    try:
        zone = ZoneInfo(zone_name)
    except ZoneInfoNotFoundError:
        return None
    profile: dict[str, int] = {}
    for label, dt_utc in _sample_utc_datetimes().items():
        offset = _offset_west_minutes(dt_utc, zone)
        if offset is None:
            return None
        profile[label] = offset
    return profile


def offset_profile_matches(left: dict[str, Any], right: dict[str, Any], tolerance: int = 1) -> bool:
    compared = 0
    for label in SAMPLE_LABELS:
        if label not in left or label not in right:
            continue
        try:
            if abs(int(left[label]) - int(right[label])) > tolerance:
                return False
            compared += 1
        except (TypeError, ValueError):
            return False
    return compared > 0


def offset_profile_distance(left: dict[str, Any], right: dict[str, Any]) -> int | None:
    distances: list[int] = []
    for label in SAMPLE_LABELS:
        if label not in left or label not in right:
            continue
        try:
            distances.append(abs(int(left[label]) - int(right[label])))
        except (TypeError, ValueError):
            return None
    if not distances:
        return None
    return max(distances)


def localtime_zone_name() -> str:
    path = Path("/etc/localtime")
    try:
        if path.is_symlink():
            target = os.path.realpath(path)
            marker = "/zoneinfo/"
            if marker in target:
                return target.split(marker, 1)[1]
    except OSError:
        pass
    return ""


def collect_os_context() -> dict[str, Any]:
    tz_env = os.environ.get("TZ", "")
    localtime_zone = localtime_zone_name()
    profile: dict[str, int] = {}
    for label, dt_utc in _sample_utc_datetimes().items():
        offset = _offset_west_minutes(dt_utc)
        if offset is not None:
            profile[label] = offset

    env_locales = {
        "LANG": os.environ.get("LANG", ""),
        "LC_ALL": os.environ.get("LC_ALL", ""),
        "LC_MESSAGES": os.environ.get("LC_MESSAGES", ""),
        "LC_TIME": os.environ.get("LC_TIME", ""),
        "LANGUAGE": os.environ.get("LANGUAGE", ""),
    }
    try:
        default_locale = locale.getlocale()
    except Exception:
        default_locale = (None, None)
    try:
        time_locale = locale.getlocale(locale.LC_TIME)
    except Exception:
        time_locale = (None, None)

    return {
        "tz_env": tz_env,
        "localtime_zone": localtime_zone,
        "time_tzname": list(time.tzname),
        "time_daylight": bool(time.daylight),
        "offset_profile": profile,
        "env_locales": env_locales,
        "default_locale": default_locale,
        "time_locale": time_locale,
    }


def browser_offsets(report: dict[str, Any]) -> dict[str, int]:
    date = report.get("date") if isinstance(report.get("date"), dict) else {}
    keys = {
        "now": "offsetMinutesNow",
        "jan": "offsetMinutesJan",
        "jul": "offsetMinutesJul",
    }
    out: dict[str, int] = {}
    for label, key in keys.items():
        try:
            out[label] = int(date.get(key))
        except (TypeError, ValueError):
            pass
    return out


def _unique(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        clean = str(value or "").strip()
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


def analyze_probe(
    result: dict[str, Any] | None,
    browser_error: str | None,
    os_context: dict[str, Any],
) -> tuple[int, str, dict[str, Any]]:
    if not result:
        return 3, f"Could not obtain browser language/timezone data. {browser_error or 'No data returned.'}", {}

    requests = result.get("requests") or []
    nav_request = next((r for r in requests if r.get("method") == "GET" and r.get("path") == "/"), {})
    nav_headers = normalize_header_map(nav_request.get("headers") or {})
    report_headers = normalize_header_map(result.get("report_headers") or {})
    report = result.get("browser_report") or {}
    navigator = report.get("navigator") if isinstance(report.get("navigator"), dict) else {}
    intl = report.get("intl") if isinstance(report.get("intl"), dict) else {}
    date = report.get("date") if isinstance(report.get("date"), dict) else {}

    accept_language = nav_headers.get("accept-language") or report_headers.get("accept-language") or ""
    accept_locales = parse_accept_language(accept_language)
    nav_language = str(navigator.get("language") or "")
    nav_languages = [str(item) for item in (navigator.get("languages") or []) if str(item or "").strip()]
    intl_locale = str(intl.get("locale") or "")
    browser_timezone = str(intl.get("timeZone") or "")

    nav_language_tag = parse_locale_tag(nav_language)
    nav_language_tags = [parse_locale_tag(item) for item in nav_languages]
    intl_locale_tag = parse_locale_tag(intl_locale)
    first_accept_tag = accept_locales[0] if accept_locales else {}

    strong: list[str] = []
    soft: list[str] = []
    positives: list[str] = []

    if browser_error:
        soft.append(browser_error)
    if navigator.get("webdriver") is True:
        soft.append("navigator.webdriver is true; language/timezone values may come from automation context")

    if not nav_language_tag.get("language"):
        soft.append("navigator.language is empty or unparsable")
    if not nav_language_tags:
        soft.append("navigator.languages is empty")
    elif nav_language_tag.get("normalized") and nav_language_tags[0].get("normalized"):
        if nav_language_tag["normalized"].lower() != nav_language_tags[0]["normalized"].lower():
            soft.append(
                f"navigator.language={nav_language_tag['normalized']} differs from first navigator.languages={nav_language_tags[0]['normalized']}"
            )

    if first_accept_tag and nav_language_tag.get("language"):
        if str(first_accept_tag.get("language")) != str(nav_language_tag.get("language")):
            strong.append(
                f"Accept-Language primary={first_accept_tag.get('normalized')} conflicts with navigator.language={nav_language_tag.get('normalized')}"
            )
        elif first_accept_tag.get("region") and nav_language_tag.get("region"):
            if str(first_accept_tag["region"]) != str(nav_language_tag["region"]):
                soft.append(
                    f"Accept-Language region={first_accept_tag['region']} differs from navigator.language region={nav_language_tag['region']}"
                )
            else:
                positives.append("Accept-Language matches navigator.language")
        else:
            positives.append("Accept-Language primary language matches navigator.language")
    elif not accept_language:
        soft.append("Accept-Language header was not observed")

    if intl_locale_tag.get("language") and nav_language_tag.get("language"):
        if intl_locale_tag["language"] != nav_language_tag["language"]:
            soft.append(
                f"Intl locale={intl_locale_tag.get('normalized')} differs from navigator.language={nav_language_tag.get('normalized')}"
            )
        else:
            positives.append("Intl locale language matches navigator.language")

    browser_profile = browser_offsets(report)
    browser_zone_profile = offset_profile_for_zone(browser_timezone) if browser_timezone else None
    os_profile = os_context.get("offset_profile") if isinstance(os_context.get("offset_profile"), dict) else {}

    if not browser_timezone:
        strong.append("Intl timeZone is empty")
    elif browser_zone_profile is None:
        strong.append(f"Intl timeZone={browser_timezone} is not a recognized IANA timezone")
    elif browser_profile and not offset_profile_matches(browser_profile, browser_zone_profile):
        distance = offset_profile_distance(browser_profile, browser_zone_profile)
        strong.append(
            f"Intl timeZone={browser_timezone} does not match Date timezone offsets"
            + (f" (max delta {distance} minutes)" if distance is not None else "")
        )
    elif browser_timezone:
        positives.append("Intl timeZone matches JavaScript Date offsets")

    if browser_profile and os_profile:
        if offset_profile_matches(browser_profile, os_profile):
            positives.append("Browser timezone offsets match local OS offsets")
        else:
            distance = offset_profile_distance(browser_profile, os_profile)
            strong.append(
                "Browser timezone offsets differ from local OS offsets"
                + (f" (max delta {distance} minutes)" if distance is not None else "")
            )

    os_zone_candidates = _unique([str(os_context.get("tz_env") or ""), str(os_context.get("localtime_zone") or "")])
    if browser_timezone and os_zone_candidates:
        if browser_timezone in os_zone_candidates:
            positives.append("Browser timezone name matches OS timezone name")
        elif browser_profile and os_profile and offset_profile_matches(browser_profile, os_profile):
            soft.append(
                f"Browser timezone name {browser_timezone} differs from OS timezone name(s) {', '.join(os_zone_candidates)}, but offsets match"
            )

    if strong:
        score = 5 if len(strong) >= 2 else 4
    elif len(soft) >= 3:
        score = 3
    elif soft:
        score = 2
    else:
        score = 1

    if strong:
        status = f"Language/timezone inconsistency: {strong[0]}"
    elif soft:
        status = f"Language/timezone mostly coherent with caveats: {soft[0]}"
    else:
        status = "Browser language, request locale, and OS timezone are coherent."

    details = {
        "probe_url": result.get("probe_url"),
        "accept_language": accept_language,
        "navigator_language": nav_language,
        "navigator_languages": nav_languages,
        "intl_locale": intl_locale,
        "browser_timezone": browser_timezone,
        "browser_offsets": browser_profile,
        "browser_timezone_profile": browser_zone_profile,
        "timezone_names": {
            "short": date.get("timezoneNameShort"),
            "long": date.get("timezoneNameLong"),
            "date_string": date.get("currentString"),
        },
        "os_context": os_context,
        "strong_issues": strong,
        "soft_issues": soft,
        "positive_signals": positives,
    }
    return score, status, details


def _print_list(title: str, values: list[str]) -> None:
    print(title)
    if not values:
        print("  -")
        return
    for value in values:
        print(f"  - {value}")


def print_details(details: dict[str, Any]) -> None:
    if not details:
        return
    print(f"Probe URL: {details.get('probe_url')}")
    print()
    print("Browser language signals:")
    print(f"  Accept-Language:     {details.get('accept_language') or '-'}")
    print(f"  navigator.language:  {details.get('navigator_language') or '-'}")
    print(f"  navigator.languages: {', '.join(details.get('navigator_languages') or []) or '-'}")
    print(f"  Intl locale:         {details.get('intl_locale') or '-'}")
    print()
    print("Browser timezone signals:")
    print(f"  Intl timeZone:       {details.get('browser_timezone') or '-'}")
    print(f"  Date offsets:        {json.dumps(details.get('browser_offsets') or {}, sort_keys=True)}")
    names = details.get("timezone_names") or {}
    print(f"  Timezone names:      {names.get('short') or '-'} / {names.get('long') or '-'}")
    if names.get("date_string"):
        print(f"  Date string:         {names.get('date_string')}")
    print()
    os_context = details.get("os_context") or {}
    print("OS timezone/locale signals:")
    print(f"  TZ env:              {os_context.get('tz_env') or '-'}")
    print(f"  /etc/localtime:      {os_context.get('localtime_zone') or '-'}")
    print(f"  time.tzname:         {', '.join(os_context.get('time_tzname') or []) or '-'}")
    print(f"  OS offsets:          {json.dumps(os_context.get('offset_profile') or {}, sort_keys=True)}")
    env_locales = os_context.get("env_locales") or {}
    locale_bits = [f"{key}={value}" for key, value in env_locales.items() if value]
    print(f"  Locale env:          {', '.join(locale_bits) if locale_bits else '-'}")
    print()
    signals = details.get("positive_signals") or []
    if signals:
        print()
        _print_list("Positive signals:", signals[:10])
    issues = (details.get("strong_issues") or []) + (details.get("soft_issues") or [])
    if issues:
        print()
        _print_list("Issues / caveats:", issues[:12])


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect browser language and timezone consistency.")
    parser.add_argument("--timeout", type=int, default=max(10, DEFAULT_TIMEOUT), help="Seconds to wait for browser report.")
    args = parser.parse_args()

    print_browser_detection_header("Language and Timezone Consistency Detection")
    print("Method: local browser probe + OS timezone/locale comparison")
    print()

    os_context = collect_os_context()

    result, browser_error = collect_browser_probe(args.timeout)
    score, status, details = analyze_probe(
        result,
        browser_error,
        os_context,
    )
    print_details(details)
    if browser_error and not details:
        print(f"Browser probe error: {browser_error}")
        print()

    print()
    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    print()
    print("Scale: 1 = coherent language/timezone profile - 5 = strong mismatch signal")
    return score


if __name__ == "__main__":
    main()
