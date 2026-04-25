#!/usr/bin/env python3
"""
Proxy Detection

1) Environment: HTTP_PROXY, HTTPS_PROXY, ALL_PROXY (requests/urllib honors these).
2) Echo request: asks an HTTP echo service what headers arrived on the wire.
   Corporate / transparent proxies often inject X-Forwarded-For, Via, Forwarded, etc.

Score (1–5), higher = stronger evidence of a proxy on the HTTP path:
  5 — Env proxy configured and forwarding headers seen on echo, or multiple strong headers
  4 — Clear forwarding headers (X-Forwarded-For, Forwarded, X-Real-IP, …)
  3 — Weak / single ambiguous header (e.g. Via only) or partial errors
  2 — Proxy env vars set but echo shows no added forward headers (or echo failed one mirror)
  1 — No proxy env and no forward headers observed
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

import requests

ECHO_URLS = (
    "https://httpbin.org/get",
    "https://postman-echo.com/get",
)
TIMEOUT = 12
UA = {"User-Agent": "overdrive-proxy-detect/1.0"}

# Headers often added by proxies / load balancers (lowercase keys).
FORWARD_STRONG = frozenset(
    {
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-port",
        "forwarded",
        "x-real-ip",
        "true-client-ip",
        "x-client-ip",
        "client-ip",
        "x-cluster-client-ip",
        "x-original-url",
    }
)
FORWARD_WEAK = frozenset(
    {
        "via",
        "x-proxy-connection",
        "proxy-connection",
        "x-originating-ip",
    }
)


def _env_proxy_info() -> tuple[bool, list[str]]:
    found: list[str] = []
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        v = os.environ.get(key)
        if v:
            try:
                host = urlparse(v).hostname or v[:40]
            except Exception:
                host = v[:40]
            found.append(f"{key}={host}")
    return bool(found), found


def _fetch_echo_headers() -> tuple[dict[str, str] | None, str | None]:
    last_err: str | None = None
    for url in ECHO_URLS:
        try:
            r = requests.get(url, headers=UA, timeout=TIMEOUT)
            r.raise_for_status()
            data = r.json()
        except (requests.RequestException, ValueError) as e:
            last_err = str(e)
            continue

        headers: dict[str, str] | None = None
        if isinstance(data, dict):
            if "headers" in data and isinstance(data["headers"], dict):
                headers = {str(k).lower(): str(v) for k, v in data["headers"].items()}
            elif url.endswith("postman-echo.com/get"):
                # postman-echo nests similarly
                h = data.get("headers")
                if isinstance(h, dict):
                    headers = {str(k).lower(): str(v) for k, v in h.items()}

        if headers:
            return headers, None

    return None, last_err or "no echo"


def check_proxy_headers() -> tuple[int, str]:
    env_on, env_lines = _env_proxy_info()
    echo_headers, echo_err = _fetch_echo_headers()

    strong = sorted(k for k in (echo_headers or {}) if k in FORWARD_STRONG)
    weak = sorted(k for k in (echo_headers or {}) if k in FORWARD_WEAK)

    parts: list[str] = []
    if env_on:
        parts.append("Proxy env: " + "; ".join(env_lines[:4]))

    if echo_err and not echo_headers:
        parts.append(f"Echo failed ({echo_err}); forward headers unknown.")
        if env_on:
            return 3, " | ".join(parts)
        return 3, " | ".join(parts)

    if echo_headers:
        if strong:
            parts.append("Echo saw: " + ", ".join(strong))
        if weak:
            parts.append("Echo saw (weak): " + ", ".join(weak))

    # Scoring
    if env_on and len(strong) >= 1:
        return 5, " | ".join(parts)
    if len(strong) >= 2 or ("forwarded" in strong and "x-forwarded-for" in strong):
        return 5, " | ".join(parts)
    if len(strong) == 1:
        return 4, " | ".join(parts)
    if weak and not strong:
        return 3, " | ".join(parts) if parts else "Only Via-style headers (ambiguous)."
    if env_on:
        return 2, " | ".join(parts)

    if echo_err:
        return 3, " | ".join(parts)

    return 1, "No proxy env vars; echo showed no common forward headers."


def main():
    print("=" * 60)
    print("Proxy Detection")
    print("=" * 60)

    env_on, env_lines = _env_proxy_info()
    print("\n[Environment]")
    if env_on:
        for line in env_lines:
            print(f"  {line}")
    else:
        print("  (no HTTP(S)_PROXY / ALL_PROXY)")

    echo_headers, echo_err = _fetch_echo_headers()
    print("\n[Echo headers seen by server]")
    if echo_headers:
        for k in sorted(echo_headers):
            if k in FORWARD_STRONG or k in FORWARD_WEAK:
                print(f"  {k}: {echo_headers[k][:120]}")
        if not any(k in FORWARD_STRONG or k in FORWARD_WEAK for k in echo_headers):
            print("  (no X-Forwarded*/Via/Forwarded-style keys in subset checked)")
    else:
        print(f"  (unavailable: {echo_err})")

    score, description = check_proxy_headers()

    print("\n" + "-" * 40)
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print("-" * 40)
    print("=" * 60)


if __name__ == "__main__":
    main()
