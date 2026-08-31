#!/usr/bin/env python3
"""
HTTP/2 SETTINGS fingerprint consistency check for the detected browser.

This probe opens a real browser through Chromium DevTools and navigates to
``tls.peet.ws/api/all`` so the observed HTTP/2/TLS fingerprints are the browser's
transport stack, not Python's ``httpx`` stack. If no browser runtime is
available, it fails with ``SCORE: Error`` (not a 1-5 authenticity score).

Score:
  1 = coherent browser-like HTTP/2 fingerprint
  2 = mostly browser-like with mild caveats
  3 = inconclusive fingerprint with observation data present
  4 = suspicious mismatch/headless downgrade
  5 = strong library/bot fingerprint
  Error = probe timed out / browser unavailable (not scored)
"""

from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from detections.common.common_browser import (
        DEFAULT_TIMEOUT,
        confirm_external_browser_probe,
        fetch_browser_json,
        print_browser_detection_header,
        print_browser_probe_error,
    )
    from detections.common.direct_chromium import run_async_script

    BROWSER_HELPER_IMPORT_ERROR: Exception | None = None
except Exception as exc:
    DEFAULT_TIMEOUT = 0
    fetch_browser_json = None  # type: ignore[assignment]
    run_async_script = None  # type: ignore[assignment]
    BROWSER_HELPER_IMPORT_ERROR = exc

    def print_browser_detection_header(title: str, *, width: int = 64) -> None:
        bar = "=" * width
        print(bar)
        print(title)
        print(bar)
        print()

    def print_browser_probe_error(reason: str, *, width: int = 64) -> int:
        print(f"SCORE: Error")
        print(f"STATUS: ERROR: {reason}")
        print()
        print("=" * width)
        return 2


DEFAULT_ENDPOINT = ""
LOCAL_H2_TIMEOUT = 600

PYTHON_LIBRARY_UA_RE = re.compile(
    r"\b(?:python|httpx|requests|urllib|aiohttp|curl|wget|httpie|okhttp|go-http-client)\b",
    re.I,
)
HEADLESS_RE = re.compile(r"HeadlessChrome|PhantomJS|SlimerJS", re.I)
CHROME_RE = re.compile(r"\b(?:HeadlessChrome|Chrome|Chromium|Edg|OPR)/(\d+)", re.I)
FIREFOX_RE = re.compile(r"\bFirefox/(\d+)", re.I)
SAFARI_RE = re.compile(r"\bVersion/(\d+).+Safari/", re.I)


def parse_akamai_fingerprint_settings(akamai_fp: str) -> dict[str, Any]:
    """
    Parse Peet's Akamai HTTP/2 fingerprint.

    Example:
      ``1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p``
    """
    if not akamai_fp:
        return {
            "settings_raw_left": "",
            "settings_kv": {},
            "settings_order": [],
            "window_update": None,
            "priority": None,
            "pseudo_header_order": "",
        }

    parts = akamai_fp.split("|")
    left = parts[0] if parts else ""
    kv: dict[int, int] = {}
    order: list[int] = []
    for item in left.split(";"):
        item = item.strip()
        if not item or ":" not in item:
            continue
        key, value = item.split(":", 1)
        if not key.isdigit():
            continue
        try:
            setting_id = int(key)
            kv[setting_id] = int(value)
            order.append(setting_id)
        except ValueError:
            continue

    def _maybe_int(value: str | None) -> int | None:
        try:
            return int(value) if value not in (None, "") else None
        except ValueError:
            return None

    return {
        "settings_raw_left": left,
        "settings_kv": kv,
        "settings_order": order,
        "window_update": _maybe_int(parts[1] if len(parts) > 1 else None),
        "priority": _maybe_int(parts[2] if len(parts) > 2 else None),
        "pseudo_header_order": parts[3] if len(parts) > 3 else "",
        "header_table_size": kv.get(1),
        "enable_push": kv.get(2),
        "max_concurrent_streams": kv.get(3),
        "initial_window_size": kv.get(4),
        "max_frame_size": kv.get(5),
        "max_header_list_size": kv.get(6),
    }


def browser_family_from_ua(user_agent: str) -> str:
    ua = user_agent or ""
    if PYTHON_LIBRARY_UA_RE.search(ua):
        return "library"
    if CHROME_RE.search(ua):
        return "chromium"
    if FIREFOX_RE.search(ua):
        return "firefox"
    if SAFARI_RE.search(ua) and "Chrome" not in ua and "Chromium" not in ua:
        return "webkit"
    return "unknown"


def classify_http2_settings(parsed: dict[str, Any], user_agent: str) -> tuple[str, list[str]]:
    """Return ``(style, reasons)`` for observed HTTP/2 SETTINGS."""
    reasons: list[str] = []
    kv: dict[int, int] = parsed.get("settings_kv") or {}
    order: list[int] = parsed.get("settings_order") or []
    family = browser_family_from_ua(user_agent)

    if not kv:
        return "unknown", ["No HTTP/2 SETTINGS fingerprint was provided by the endpoint."]

    header_table = parsed.get("header_table_size")
    initial_window = parsed.get("initial_window_size")
    max_concurrent = parsed.get("max_concurrent_streams")
    max_header_list = parsed.get("max_header_list_size")
    max_frame = parsed.get("max_frame_size")
    window_update = parsed.get("window_update")

    browser_like_votes = 0
    library_like_votes = 0

    if header_table == 65536:
        browser_like_votes += 2
        reasons.append("SETTINGS_HEADER_TABLE_SIZE=65536 is common in Chromium-class browsers.")
    elif header_table == 4096:
        library_like_votes += 2
        reasons.append("SETTINGS_HEADER_TABLE_SIZE=4096 is common in Python/Go/library clients.")
    elif header_table is not None:
        reasons.append(f"SETTINGS_HEADER_TABLE_SIZE={header_table} is not a strong standalone signal.")

    if initial_window is not None:
        if initial_window >= 1_000_000:
            browser_like_votes += 2
            reasons.append(f"Large INITIAL_WINDOW_SIZE={initial_window} is browser-like.")
        elif initial_window <= 131_072:
            library_like_votes += 1
            reasons.append(f"Small INITIAL_WINDOW_SIZE={initial_window} is library-like or conservative.")

    if max_concurrent in (100, 1000):
        browser_like_votes += 1
        reasons.append(f"MAX_CONCURRENT_STREAMS={max_concurrent} is plausible for mainstream browsers.")
    elif max_concurrent is not None and max_concurrent <= 100:
        library_like_votes += 1
        reasons.append(f"MAX_CONCURRENT_STREAMS={max_concurrent} is common in generic H2 clients.")

    if max_header_list in (262144, 65536):
        browser_like_votes += 1
        reasons.append(f"MAX_HEADER_LIST_SIZE={max_header_list} matches common browser/library ranges.")

    if max_frame == 16384 and header_table == 4096:
        library_like_votes += 1
        reasons.append("MAX_FRAME_SIZE=16384 combined with 4096 header table is library-like.")

    if window_update is not None:
        if window_update >= 10_000_000:
            browser_like_votes += 1
            reasons.append(f"Large connection WINDOW_UPDATE={window_update} is often browser-like.")
        elif window_update in (0, 65_535, 15_663_105):
            reasons.append(f"WINDOW_UPDATE={window_update} is not decisive by itself.")

    if order:
        if order[:4] in ([1, 2, 3, 4], [1, 2, 4, 6], [1, 3, 4, 6]):
            browser_like_votes += 1
            reasons.append(f"SETTINGS order {order} is plausible for browser stacks.")
        elif order[:3] == [1, 2, 4] and header_table == 4096:
            library_like_votes += 1
            reasons.append(f"SETTINGS order {order} plus 4096 table is typical of library stacks.")

    if family == "firefox" and header_table in (65536, 131072):
        browser_like_votes += 1
    if family == "webkit" and header_table and header_table >= 65536:
        browser_like_votes += 1

    if browser_like_votes >= library_like_votes + 2:
        return "browser-like", reasons
    if library_like_votes >= browser_like_votes + 2:
        return "library-like", reasons
    return "mixed", reasons


def is_local_endpoint(url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return False
    if host.lower() in {"localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _pick_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _make_localhost_cert(work_dir: Path) -> tuple[Path, Path]:
    from detections.common.localhost_tls import make_localhost_probe_cert

    return make_localhost_probe_cert(work_dir)


def _settings_fingerprint(settings_order: list[int], settings_values: dict[int, int], pseudo_order: str) -> str:
    left = ";".join(
        f"{setting}:{settings_values[setting]}"
        for setting in settings_order
        if setting in settings_values
    )
    return f"{left}||0|{pseudo_order}"


class LocalH2ObservationServer:
    def __init__(self, timeout: int = LOCAL_H2_TIMEOUT) -> None:
        self.timeout = max(5, int(timeout))
        self.work_dir_obj = tempfile.TemporaryDirectory(prefix="overdrive-h2-probe-")
        self.work_dir = Path(self.work_dir_obj.name)
        self.port = _pick_local_port()
        self.url = f"https://127.0.0.1:{self.port}/"
        self.error: str | None = None
        self._ready = threading.Event()
        self._done = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve_once, daemon=True)

    def __enter__(self) -> "LocalH2ObservationServer":
        self._thread.start()
        if not self._ready.wait(timeout=max(30, self.timeout)):
            raise RuntimeError(self.error or "local HTTP/2 observer did not start")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=0.25).close()
        self._thread.join(timeout=2)
        self.work_dir_obj.cleanup()

    def _serve_once(self) -> None:
        try:
            cert_path, key_path = _make_localhost_cert(self.work_dir)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert_path), str(key_path))
            context.set_alpn_protocols(["h2", "http/1.1"])
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", self.port))
                listener.listen(1)
                listener.settimeout(0.5)
                self._ready.set()
                deadline = time.monotonic() + self.timeout
                last_error: str | None = None
                while not self._stop.is_set() and time.monotonic() < deadline:
                    try:
                        raw_conn, _addr = listener.accept()
                    except socket.timeout:
                        continue
                    try:
                        with raw_conn:
                            raw_conn.settimeout(self.timeout)
                            with context.wrap_socket(raw_conn, server_side=True) as tls_conn:
                                tls_conn.settimeout(self.timeout)
                                alpn = tls_conn.selected_alpn_protocol() or "http/1.1"
                                if alpn == "h2":
                                    self._serve_h2(tls_conn, alpn)
                                else:
                                    self._serve_http1(tls_conn, alpn)
                                return
                    except Exception as exc:
                        last_error = f"{type(exc).__name__}: {exc}"
                        self.error = last_error
                        continue
                self.error = last_error or "local HTTP/2 observer was not contacted"
                return
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self._ready.set()
        finally:
            self._done.set()

    def _serve_http1(self, conn: ssl.SSLSocket, alpn: str) -> None:
        request = b""
        while b"\r\n\r\n" not in request and len(request) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            request += chunk
        headers: dict[str, str] = {}
        for line in request.decode("iso-8859-1", errors="replace").split("\r\n")[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        body = json.dumps(
            {
                "source": "overdrive-local-http2-observer",
                "http_version": "http/1.1",
                "tls": {"alpn": alpn},
                "http2": {},
                "user_agent": headers.get("user-agent", ""),
            }
        ).encode("utf-8")
        conn.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Access-Control-Allow-Origin: *\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
            + body
        )
        with contextlib.suppress(OSError):
            conn.shutdown(socket.SHUT_RDWR)

    def _serve_h2(self, conn: ssl.SSLSocket, alpn: str) -> None:
        try:
            import h2.config
            import h2.connection
            import h2.events
        except Exception as exc:
            raise RuntimeError(f"h2 package is required for local HTTP/2 observer: {exc}") from exc

        h2_conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
        h2_conn.initiate_connection()
        conn.sendall(h2_conn.data_to_send())

        settings_order: list[int] = []
        settings_values: dict[int, int] = {}
        user_agent = ""
        pseudo_order = ""
        stream_id: int | None = None
        window_update: int | None = None
        deadline = time.monotonic() + self.timeout

        while time.monotonic() < deadline:
            data = conn.recv(65535)
            if not data:
                break
            for event in h2_conn.receive_data(data):
                if isinstance(event, h2.events.RemoteSettingsChanged):
                    for code, changed in event.changed_settings.items():
                        setting = int(code)
                        if setting not in settings_order:
                            settings_order.append(setting)
                        settings_values[setting] = int(changed.new_value)
                elif isinstance(event, h2.events.WindowUpdated) and event.stream_id == 0:
                    window_update = int(event.delta)
                elif isinstance(event, h2.events.RequestReceived):
                    stream_id = int(event.stream_id)
                    pseudo = []
                    for raw_name, raw_value in event.headers:
                        name = raw_name.decode("ascii", "ignore") if isinstance(raw_name, bytes) else str(raw_name)
                        value = raw_value.decode("latin1", "ignore") if isinstance(raw_value, bytes) else str(raw_value)
                        if name.startswith(":"):
                            pseudo.append(name[1:2])
                        elif name.lower() == "user-agent":
                            user_agent = value
                    pseudo_order = ",".join(pseudo)
                    body_obj = {
                        "source": "overdrive-local-http2-observer",
                        "http_version": "h2",
                        "user_agent": user_agent,
                        "tls": {"alpn": alpn},
                        "http2": {
                            "settings": settings_values,
                            "settings_order": settings_order,
                            "window_update": window_update,
                            "pseudo_header_order": pseudo_order,
                            "akamai_fingerprint": _settings_fingerprint(
                                settings_order,
                                settings_values,
                                pseudo_order,
                            ),
                        },
                    }
                    body = json.dumps(body_obj).encode("utf-8")
                    h2_conn.send_headers(
                        stream_id,
                        [
                            (":status", "200"),
                            ("content-type", "application/json"),
                            ("access-control-allow-origin", "*"),
                            ("cache-control", "no-store"),
                        ],
                    )
                    h2_conn.send_data(stream_id, body, end_stream=True)
                    h2_conn.close_connection(error_code=0)
                    conn.sendall(h2_conn.data_to_send())
                    time.sleep(0.25)
                    return
                elif isinstance(event, h2.events.StreamEnded) and stream_id == event.stream_id:
                    body_obj = {
                        "source": "overdrive-local-http2-observer",
                        "http_version": "h2",
                        "user_agent": user_agent,
                        "tls": {"alpn": alpn},
                        "http2": {
                            "settings": settings_values,
                            "settings_order": settings_order,
                            "window_update": window_update,
                            "pseudo_header_order": pseudo_order,
                            "akamai_fingerprint": _settings_fingerprint(
                                settings_order,
                                settings_values,
                                pseudo_order,
                            ),
                        },
                    }
                    body = json.dumps(body_obj).encode("utf-8")
                    h2_conn.send_headers(
                        stream_id,
                        [
                            (":status", "200"),
                            ("content-type", "application/json"),
                            ("access-control-allow-origin", "*"),
                            ("cache-control", "no-store"),
                        ],
                    )
                    h2_conn.send_data(stream_id, body, end_stream=True)
                    h2_conn.close_connection(error_code=0)
                    conn.sendall(h2_conn.data_to_send())
                    time.sleep(0.25)
                    return
            outbound = h2_conn.data_to_send()
            if outbound:
                conn.sendall(outbound)

        raise TimeoutError("local HTTP/2 observer did not receive a complete browser request")


def fetch_browser_observation(endpoint: str, timeout: int) -> tuple[dict[str, Any] | None, str | None]:
    if BROWSER_HELPER_IMPORT_ERROR is not None:
        return None, (
            "browser helpers unavailable: "
            f"{type(BROWSER_HELPER_IMPORT_ERROR).__name__}: {BROWSER_HELPER_IMPORT_ERROR}"
        )
    if fetch_browser_json is None:
        return None, "browser helpers unavailable"
    if not endpoint:
        if run_async_script is None:
            return None, "direct Chromium async helpers unavailable"
        try:
            with LocalH2ObservationServer(timeout=max(LOCAL_H2_TIMEOUT, timeout)) as server:
                target = json.dumps(f"{server.url}?t={int(time.time())}")
                script = f"""
const callback = arguments[arguments.length - 1];
(async () => {{
  try {{
    const response = await fetch({target}, {{ cache: "no-store" }});
    const text = await response.text();
    let data = null;
    try {{ data = JSON.parse(text); }} catch (_err) {{}}
    callback({{ ok: response.ok, status: response.status, data, text }});
  }} catch (err) {{
    callback({{ ok: false, error: String(err && err.message ? err.message : err) }});
  }}
}})();
"""
                result, error = run_async_script(
                    script,
                    timeout=timeout,
                    ignore_certificate_errors=True,
                )
                if error:
                    server._done.wait(timeout=1)
                if error and server.error:
                    return None, f"{error}; local HTTP/2 observer: {server.error}"
                if error:
                    return None, error
                if not isinstance(result, dict):
                    return None, f"browser fetch returned unexpected result: {result!r}"
                if result.get("ok") is False:
                    return None, str(result.get("error") or "browser fetch failed")
                data = result.get("data")
                if not isinstance(data, dict):
                    text = str(result.get("text") or "")
                    return None, f"browser fetch did not return JSON: {text[:160]}"
                return data, None
        except Exception as exc:
            return None, f"local HTTP/2 observer failed: {type(exc).__name__}: {exc}"
    if not is_local_endpoint(endpoint):
        allowed, deny_reason = confirm_external_browser_probe(
            "HTTP/2 browser fingerprint",
            endpoint,
        )
        if not allowed:
            return None, f"external HTTP/2 probe not run: {deny_reason}"

    bounded = max(5, min(timeout, 12))
    return fetch_browser_json(
        endpoint,
        timeout=bounded,
        cache_bust=True,
        ignore_certificate_errors=is_local_endpoint(endpoint),
    )


def score_http2_browser_observation(data: dict[str, Any] | None, error: str | None) -> tuple[int, str, dict[str, Any]]:
    if not data:
        # Caller must treat timeouts as Error, not score 3.
        return 3, f"Could not obtain browser HTTP/2 observation. {error or 'No data returned.'}", {}

    user_agent = str(data.get("user_agent") or "")
    http_version = str(data.get("http_version") or "").lower()
    http2 = data.get("http2") if isinstance(data.get("http2"), dict) else {}
    tls = data.get("tls") if isinstance(data.get("tls"), dict) else {}
    akamai_fp = str(http2.get("akamai_fingerprint") or "")
    parsed = parse_akamai_fingerprint_settings(akamai_fp)
    style, reasons = classify_http2_settings(parsed, user_agent)
    family = browser_family_from_ua(user_agent)
    is_headless = bool(HEADLESS_RE.search(user_agent))
    is_library_ua = family == "library"
    ja3_hash = str(tls.get("ja3_hash") or "")
    ja4 = str(tls.get("ja4") or "")

    details = {
        "user_agent": user_agent,
        "http_version": http_version,
        "family": family,
        "akamai_fingerprint": akamai_fp,
        "akamai_fingerprint_hash": http2.get("akamai_fingerprint_hash") or "",
        "parsed": parsed,
        "style": style,
        "style_reasons": reasons,
        "ja3_hash": ja3_hash,
        "ja4": ja4,
    }

    if is_library_ua:
        return 5, "Observed User-Agent names a library client, not a browser.", details

    if not user_agent.strip():
        return 4, "Observed User-Agent is empty; this is unusual for a normal browser.", details

    if "h2" not in http_version and not akamai_fp:
        if family in ("chromium", "firefox", "webkit"):
            return 3, "Browser was detected, but HTTP/2 fingerprint data was absent or downgraded.", details
        return 4, "Unknown client family and no HTTP/2 fingerprint data was available.", details

    if style == "library-like":
        if family in ("chromium", "firefox", "webkit"):
            return 4, "Browser-like UA with library-like HTTP/2 SETTINGS fingerprint.", details
        return 5, "Non-browser or unknown UA with library-like HTTP/2 SETTINGS fingerprint.", details

    if is_headless:
        if style == "browser-like":
            return 4, "HTTP/2 SETTINGS are browser-like, but User-Agent exposes HeadlessChrome automation.", details
        return 5, "Headless browser with non-browser-like HTTP/2 SETTINGS.", details

    if family in ("chromium", "firefox", "webkit") and style == "browser-like":
        return 1, "HTTP/2 SETTINGS fingerprint is coherent for the detected browser family.", details

    if family in ("chromium", "firefox", "webkit") and style == "mixed":
        return 2, "Detected browser has mostly plausible but not fully distinctive HTTP/2 SETTINGS.", details

    if style == "browser-like":
        return 2, "HTTP/2 SETTINGS look browser-like, but the browser family could not be identified confidently.", details

    return 3, "HTTP/2 SETTINGS fingerprint is inconclusive.", details


def print_observation(details: dict[str, Any]) -> None:
    if not details:
        return
    parsed = details.get("parsed") or {}
    settings = parsed.get("settings_kv") or {}
    print("Observed browser/network values:")
    print(f"  User-Agent: {details.get('user_agent') or '-'}")
    print(f"  Family: {details.get('family') or 'unknown'}")
    print(f"  HTTP version: {details.get('http_version') or '-'}")
    print(f"  HTTP/2 style: {details.get('style') or 'unknown'}")
    print(f"  Akamai fingerprint: {details.get('akamai_fingerprint') or '-'}")
    print(f"  Akamai hash: {details.get('akamai_fingerprint_hash') or '-'}")
    print(f"  SETTINGS order: {parsed.get('settings_order') or '-'}")
    print(f"  SETTINGS values: {settings or '-'}")
    print(f"  Window update: {parsed.get('window_update')}")
    print(f"  Pseudo-header order: {parsed.get('pseudo_header_order') or '-'}")
    print(f"  JA3 hash: {details.get('ja3_hash') or '-'}")
    print(f"  JA4: {details.get('ja4') or '-'}")
    reasons = details.get("style_reasons") or []
    if reasons:
        print()
        print("Fingerprint notes:")
        for reason in reasons[:8]:
            print(f"  - {reason}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check HTTP/2 SETTINGS for the detected browser.")
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help="Local JSON observation endpoint. External endpoints require explicit opt-in.",
    )
    parser.add_argument("--timeout", type=int, default=max(12, DEFAULT_TIMEOUT), help="Browser wait timeout.")
    args = parser.parse_args()

    print_browser_detection_header("HTTP/2 SETTINGS Browser Fingerprint Check")
    print(f"Endpoint: {args.endpoint or '(none; local-only default)'}")
    print("Method: Chromium DevTools browser fetch/navigation; no Python HTTP client fallback is scored.")
    print()

    data, error = fetch_browser_observation(args.endpoint, args.timeout)
    if error and not data:
        if "disabled by default" in error or "not configured" in error:
            print("SCORE: N/A")
            print(f"STATUS: Skipped: {error}")
            print()
            print("=" * 64)
            return 0
        return print_browser_probe_error(error)

    score, status, details = score_http2_browser_observation(data, error)
    print_observation(details)

    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    print()
    print("=" * 64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
