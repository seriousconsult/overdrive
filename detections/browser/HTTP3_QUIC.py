#!/usr/bin/env python3
"""
When you connect via QUIC, your client sends Transport Parameters. These are tiny technical details that vary depending on which software is being used:

    Initial Packet Size: How big is the very first piece of data sent?

    Max Data Limits: How much data can the server send before you acknowledge it?

    Stream Concurrency: How many parallel "conversations" can happen at once?

    Error Handling: How does the client react if a packet is lost?

A standard Chrome browser on Windows has one specific pattern of these settings. A Python script (bot) pretending to be Chrome usually has a different pattern,
"""

from __future__ import annotations

import argparse
import contextlib
import json
import ipaddress
import os
import re
import socket
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_browser import (
    DEFAULT_TIMEOUT,
    confirm_external_browser_probe,
    fetch_browser_json,
    print_browser_probe_error,
)
from detections.common.direct_chromium import run_async_script

DEFAULT_ENDPOINT = ""
TIMEOUT = max(12, DEFAULT_TIMEOUT)
LOCAL_QUIC_TIMEOUT = 600


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


def _pick_local_port(kind: int) -> int:
    sock_type = socket.SOCK_DGRAM if kind == socket.SOCK_DGRAM else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _make_localhost_cert(work_dir: str) -> tuple[str, str]:
    from detections.common.localhost_tls import make_localhost_probe_cert

    cert_path, key_path = make_localhost_probe_cert(work_dir)
    return str(cert_path), str(key_path)


class LocalQuicAltSvcProbe:
    def __init__(self, timeout: int = LOCAL_QUIC_TIMEOUT) -> None:
        self.timeout = max(5, int(timeout))
        self.tcp_port = _pick_local_port(socket.SOCK_STREAM)
        self.udp_port = _pick_local_port(socket.SOCK_DGRAM)
        self.url = f"https://127.0.0.1:{self.tcp_port}/"
        self.error: str | None = None
        self.udp_packet_size: int | None = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._tmp = tempfile.TemporaryDirectory(prefix="overdrive-h3-probe-")
        self._tcp_thread = threading.Thread(target=self._serve_https, daemon=True)
        self._udp_thread = threading.Thread(target=self._listen_udp, daemon=True)

    def __enter__(self) -> "LocalQuicAltSvcProbe":
        self._udp_thread.start()
        self._tcp_thread.start()
        if not self._ready.wait(timeout=max(30, self.timeout)):
            raise RuntimeError(self.error or "local HTTP/3 Alt-Svc observer did not start")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            socket.create_connection(("127.0.0.1", self.tcp_port), timeout=0.25).close()
        with contextlib.suppress(OSError):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"\0", ("127.0.0.1", self.udp_port))
        self._tcp_thread.join(timeout=2)
        self._udp_thread.join(timeout=2)
        self._tmp.cleanup()

    def _listen_udp(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", self.udp_port))
                sock.settimeout(0.25)
                deadline = time.monotonic() + self.timeout
                while not self._stop.is_set() and time.monotonic() < deadline:
                    try:
                        data, _addr = sock.recvfrom(4096)
                    except socket.timeout:
                        continue
                    if data and data != b"\0":
                        self.udp_packet_size = len(data)
                        return
        except Exception as exc:
            self.error = f"UDP observer failed: {type(exc).__name__}: {exc}"

    def _serve_https(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                body = json.dumps(
                    {
                        "source": "overdrive-local-quic-alt-svc",
                        "ok": True,
                        "path": self.path,
                        "user_agent": self.headers.get("user-agent", ""),
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("cache-control", "no-store")
                self.send_header("alt-svc", f'h3=":{outer.udp_port}"; ma=60')
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _fmt: str, *_args: Any) -> None:
                return

        try:
            cert_path, key_path = _make_localhost_cert(self._tmp.name)
            httpd = HTTPServer(("127.0.0.1", self.tcp_port), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            context.set_alpn_protocols(["http/1.1"])
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            httpd.timeout = 0.25
            self._ready.set()
            deadline = time.monotonic() + self.timeout
            while not self._stop.is_set() and time.monotonic() < deadline:
                httpd.handle_request()
                if self.udp_packet_size is not None:
                    return
        except Exception as exc:
            self.error = f"HTTPS Alt-Svc observer failed: {type(exc).__name__}: {exc}"
            self._ready.set()


def fetch_local_quic_observation(timeout: int) -> tuple[dict[str, Any] | None, str | None]:
    script = """
const callback = arguments[arguments.length - 1];
function done(value) { callback(value); }
(async () => {
  try {
    await new Promise(resolve => setTimeout(resolve, 500));
    const first = await fetch("/first?x=" + Date.now(), {cache: "no-store"});
    await first.text();
    await new Promise(resolve => setTimeout(resolve, 1500));
    const second = await fetch("/second?x=" + Date.now(), {cache: "no-store"});
    const text = await second.text();
    let parsed = {};
    try { parsed = JSON.parse(text); } catch (_) {}
    done({ok: true, userAgent: navigator.userAgent || "", second: parsed});
  } catch (err) {
    done({ok: false, error: String(err && err.message ? err.message : err), userAgent: navigator.userAgent || ""});
  }
})();
"""
    try:
        with LocalQuicAltSvcProbe(timeout=max(timeout, LOCAL_QUIC_TIMEOUT)) as server:
            result, error = run_async_script(
                script,
                timeout=timeout,
                url=server.url,
                ignore_certificate_errors=True,
            )
            deadline = time.monotonic() + min(5, max(1, timeout // 4))
            while server.udp_packet_size is None and time.monotonic() < deadline:
                time.sleep(0.1)
            user_agent = ""
            if isinstance(result, dict):
                user_agent = str(result.get("userAgent") or "")
            observed = server.udp_packet_size is not None
            data = {
                "source": "overdrive-local-quic-alt-svc",
                "http_version": "h3-attempted" if observed else "http/1.1-alt-svc",
                "user_agent": user_agent,
                "tls": {"alpn": "h3-alt-svc" if observed else "http/1.1"},
                "quic": {
                    "udp_initial_seen": observed,
                    "initial_packet_size": server.udp_packet_size,
                    "alt_svc_udp_port": server.udp_port,
                },
                "transport": {
                    "local_alt_svc_quic_packet": server.udp_packet_size,
                }
                if observed
                else {},
            }
            if error:
                return data, error
            if isinstance(result, dict) and result.get("ok") is False:
                return data, str(result.get("error") or "browser fetch failed")
            if server.error:
                return data, server.error
            return data, None
    except Exception as exc:
        return None, f"local HTTP/3 Alt-Svc observer failed: {type(exc).__name__}: {exc}"


def fetch_browser_observation(endpoint: str, timeout: int) -> tuple[dict[str, Any] | None, str | None]:
    if not endpoint:
        return fetch_local_quic_observation(timeout)
    if not is_local_endpoint(endpoint):
        allowed, deny_reason = confirm_external_browser_probe(
            "HTTP/3 QUIC browser fingerprint",
            endpoint,
        )
        if not allowed:
            return None, f"external HTTP/3/QUIC probe not run: {deny_reason}"
    bounded = max(5, min(timeout, 12))
    return fetch_browser_json(endpoint, timeout=bounded, cache_bust=True)


def _walk_key_values(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            out.append((path, v))
            out.extend(_walk_key_values(v, path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]"
            out.extend(_walk_key_values(v, path))
    return out


def extract_quic_signals(data: dict[str, Any]) -> dict[str, Any]:
    kv = _walk_key_values(data)

    key_pat = re.compile(
        r"(?:^|\.)(quic|http3|h3|transport|alpn|grease|max_data|max_streams|"
        r"ack_delay|initial|max_udp_payload|active_connection_id_limit|disable_active_migration)",
        re.I,
    )
    str_pat = re.compile(r"\b(h3|http/3|quic)\b", re.I)

    matched_entries: list[tuple[str, Any]] = []
    for k, v in kv:
        if key_pat.search(k):
            matched_entries.append((k, v))
            continue
        if isinstance(v, str) and str_pat.search(v):
            matched_entries.append((k, v))

    http_version = str(data.get("http_version", "") or "").lower()
    ua = str(data.get("user_agent", "") or "")

    tls = data.get("tls", {})
    alpn = ""
    if isinstance(tls, dict):
        alpn = str(tls.get("alpn", "") or "").lower()

    has_h3 = ("h3" in http_version) or ("h3" in alpn) or ("quic" in http_version)

    transport_param_paths = []
    for k, _v in matched_entries:
        lk = k.lower()
        if "transport" in lk or "max_data" in lk or "max_streams" in lk:
            transport_param_paths.append(k)

    return {
        "source": data.get("source") or "",
        "http_version": http_version,
        "alpn": alpn,
        "user_agent": ua,
        "quic": data.get("quic") if isinstance(data.get("quic"), dict) else {},
        "has_h3_or_quic": has_h3,
        "matched_entries": matched_entries[:80],
        "transport_param_paths": transport_param_paths[:40],
        "transport_param_count": len(transport_param_paths),
    }


def score_quic_fingerprint(sig: dict[str, Any], probe_error: str | None) -> tuple[int, str]:
    """
    1 = Browser-like and coherent QUIC/HTTP3 evidence
    2 = Mostly coherent, minor uncertainty
    3 = Inconclusive / partial evidence
    4 = Suspicious mismatch (automation-like behavior or missing expected evidence)
    5 = Strong non-browser / bot-like inconsistency
    """
    source = str(sig.get("source") or "")
    if source == "overdrive-local-quic-alt-svc":
        quic = sig.get("quic") if isinstance(sig.get("quic"), dict) else {}
        if quic.get("udp_initial_seen"):
            size = quic.get("initial_packet_size")
            return (
                2,
                f"Chromium attempted QUIC to a local Alt-Svc endpoint (initial UDP packet {size} bytes).",
            )
        if probe_error:
            return 3, f"Local Alt-Svc probe ran, but no QUIC attempt was observed ({probe_error})."
        return 3, "Local Alt-Svc probe ran, but Chromium did not attempt QUIC on loopback."

    if probe_error:
        return 3, f"Could not complete browser observation ({probe_error})"

    ua = (sig.get("user_agent") or "").lower()
    has_h3 = bool(sig.get("has_h3_or_quic"))
    tp_count = int(sig.get("transport_param_count") or 0)
    http_version = str(sig.get("http_version", ""))
    alpn = str(sig.get("alpn", ""))

    is_headless = "headlesschrome" in ua
    is_library_ua = any(tok in ua for tok in ("python", "httpx", "requests", "curl/", "aiohttp"))
    has_chrome_ua = ("chrome/" in ua) or ("edg/" in ua) or ("chromium" in ua)
    ua_windows = "windows nt" in ua
    ua_linux = ("x11;" in ua and "linux" in ua) or ("linux" in ua and not ua_windows)
    ua_mac = "macintosh" in ua or "mac os x" in ua

    if is_library_ua:
        return 5, "User-Agent looks like a script/library client instead of a browser."

    # Strong automation signal: headless Chromium with no QUIC/H3 evidence.
    # This should not score as neutral because it is a high-confidence non-human profile in many environments.
    if is_headless and not has_h3 and tp_count == 0:
        return 5, (
            "HeadlessChrome observed with HTTP/2 fallback and no QUIC transport-parameter evidence "
            "(strong automation/non-standard client signal)."
        )

    # Headless still carries substantial bot signal even when H3 appears.
    if is_headless and has_h3:
        if tp_count >= 2:
            return 4, "HeadlessChrome with QUIC/H3 present, but automation fingerprint remains strong."
        return 5, "HeadlessChrome with weak QUIC evidence (high-confidence automation profile)."

    # Optional environment heuristic from UA only:
    # baseline expectation in this repo comment is "standard Chrome on Windows".
    if has_chrome_ua and not ua_windows and (ua_linux or ua_mac) and not has_h3 and tp_count == 0:
        return 4, (
            "Chrome-like UA is non-Windows and no QUIC transport evidence was observed "
            "(possible downgraded or non-standard stack)."
        )

    if has_h3 and tp_count >= 3 and has_chrome_ua and not is_headless:
        return 1, "HTTP/3 + QUIC transport-parameter evidence looks coherent for a normal browser."

    if has_h3 and tp_count >= 1 and has_chrome_ua:
        if is_headless:
            return 2, "HTTP/3/QUIC observed, but headless browser context reduces confidence."
        return 2, "HTTP/3/QUIC observed with partial transport-parameter evidence."

    if (("h2" in http_version) or ("h2" in alpn)) and has_chrome_ua and tp_count == 0:
        return 4, (
            "Chrome-like UA negotiated HTTP/2 and exposed no QUIC transport-parameter evidence "
            "(suspicious for an H3-capable client path)."
        )

    if has_chrome_ua and not has_h3 and tp_count == 0:
        return 4, "Browser-like UA without QUIC/HTTP3 transport evidence (possible downgrade or stack mismatch)."

    return 4, "QUIC/HTTP3 fingerprint evidence is sparse or inconsistent for the claimed client profile."


def main() -> None:
    parser = argparse.ArgumentParser(description="Check HTTP/3/QUIC signals for the detected browser.")
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help="Local JSON observation endpoint. External endpoints require explicit opt-in.",
    )
    parser.add_argument("--timeout", type=int, default=TIMEOUT, help="Browser wait timeout.")
    args = parser.parse_args()

    print("=" * 64)
    print("HTTP/3 (QUIC) Fingerprint Detection")
    print("=" * 64)
    print()
    print("Probe endpoint:", args.endpoint or "(none; local-only default)")
    print("Method: Chromium DevTools browser probe + recursive QUIC signal extraction")
    print()

    data, err = fetch_browser_observation(args.endpoint, args.timeout)
    if not data:
        if err and ("disabled by default" in err or "not configured" in err):
            print("SCORE: N/A")
            print(f"STATUS: Skipped: {err}")
            print()
            print("=" * 64)
            return
        raise SystemExit(print_browser_probe_error(err or "no data returned"))

    sig = extract_quic_signals(data)
    score, status = score_quic_fingerprint(sig, None)

    print("[Observed]")
    print(f"- http_version: {sig.get('http_version') or '(empty)'}")
    print(f"- tls.alpn:     {sig.get('alpn') or '(empty)'}")
    print(f"- user_agent:   {sig.get('user_agent') or '(empty)'}")
    print(f"- h3/quic seen: {sig.get('has_h3_or_quic')}")
    print(f"- transport-parameter key hits: {sig.get('transport_param_count')}")
    print()

    hits = sig.get("matched_entries") or []
    if hits:
        print("[Matched QUIC/HTTP3 Signals]")
        for k, v in hits[:15]:
            vs = str(v)
            if len(vs) > 120:
                vs = vs[:117] + "..."
            print(f"  - {k}: {vs}")
        if len(hits) > 15:
            print(f"  - ... and {len(hits) - 15} more")
        print()
    else:
        print("[Matched QUIC/HTTP3 Signals]")
        print("  - none")
        print()

    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    print("Scale: 1 = coherent browser-like QUIC profile · 5 = strong bot/mismatch signal")
    print()
    print("=" * 64)


if __name__ == "__main__":
    main()
