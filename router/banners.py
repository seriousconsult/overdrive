#!/usr/bin/env python3
"""
(Layer 7)
Port 80/443 "Banners"
Most home routers have a web-based management page. They often leak information:
Service Banners: Server: httpd/2.0 (AsusWRT) or Server: TP-LINK HTTPD.

Default `--paths` is a small multi-vendor list (/, login pages, LuCI, etc.) so `/` alone is not the only probe.

Unified suspicion score **1–5** (aligned with Overdrive): **higher** = stronger router-like banner signal.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import urllib3
from typing import Any

import requests

ROUTER_SERVER_KEYWORDS = [
    "httpd",
    "wrt",
    "tp-link",
    "netgear",
    "asuswrt",
    "asustek",
    "gateway",
    "cisco",
    "router",
    "boa",
    "lighttpd",
]

BANNER_HEADERS = ["Server", "X-Powered-By", "WWW-Authenticate", "Location", "Content-Type"]

# Common admin / login / firmware paths (many routers omit Server on `/` but not on legacy CGI).
DEFAULT_BANNER_PATHS: tuple[str, ...] = (
    "/",
    "/login.html",
    "/login.cgi",
    "/cgi-bin/luci",
    "/admin/",
    "/webpages/login.html",
    "/home.asp",
    "/goform/login",
)


def default_ipv4_gateway() -> str | None:
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0 and out.stdout:
            m = re.search(r"default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})", out.stdout)
            if m:
                return m.group(1)
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def score_server_banner(server_value: str | None) -> tuple[int, list[str]]:
    """Returns (score 1–5, matched keywords). 1 = no router-like banner signal."""
    if not server_value:
        return 1, []

    sv = server_value.lower()
    matched = [kw for kw in ROUTER_SERVER_KEYWORDS if kw in sv]
    if not matched:
        return 1, []

    n = len(matched)
    if n == 1:
        score = 3
    elif n == 2:
        score = 4
    else:
        score = 5
    return score, matched


def request_with_method(
    session: requests.Session, method: str, url: str, timeout: float, insecure: bool
) -> dict[str, Any]:
    resp = session.request(
        method=method,
        url=url,
        timeout=timeout,
        verify=(not insecure),
        allow_redirects=False,
        headers={
            "User-Agent": "banner-probe/1.0",
            "Accept": "*/*",
            "Connection": "close",
        },
    )

    headers = dict(resp.headers)
    server = headers.get("Server")

    score, matched = score_server_banner(server)

    banner_subset = {k: headers.get(k) for k in BANNER_HEADERS if k in headers}

    return {
        "method": method,
        "url": url,
        "status_code": resp.status_code,
        "server": server,
        "matched_keywords": matched,
        "banner_headers": banner_subset,
        "score": score,
    }


def probe(ip: str, port: int, path: str, timeout: float, insecure: bool, max_tries: int = 2) -> dict[str, Any]:
    scheme = "https" if port in (443,) else "http"
    url = f"{scheme}://{ip}:{port}{path}"

    session = requests.Session()
    results: list[dict[str, Any]] = []

    tried = 0
    for method in ["HEAD", "GET"]:
        tried += 1
        try:
            r = request_with_method(session, method, url, timeout=timeout, insecure=insecure)
            results.append(r)

            if method == "HEAD" and r.get("server"):
                break

        except requests.RequestException as e:
            results.append(
                {
                    "method": method,
                    "url": url,
                    "error": str(e),
                }
            )

        if tried >= max_tries:
            break

    final_score = max((r.get("score", 1) for r in results if isinstance(r, dict)), default=1)
    return {
        "ip": ip,
        "port": port,
        "scheme": scheme,
        "path": path,
        "attempts": results,
        "final_score": final_score,
    }


def _banner_status_line(results: list[dict[str, Any]], overall: int) -> str:
    """One line for STATUS: (today only `Server:` keyword hits raise score)."""
    if overall > 1:
        for r in results:
            if int(r.get("final_score", 1)) <= 1:
                continue
            for a in r.get("attempts") or []:
                if isinstance(a, dict):
                    srv = (a.get("server") or "").strip()
                    if srv:
                        return srv[:200]
        return f"Banner score {overall}"
    return f"No Server banner ({len(results)} probes)"


def main() -> None:
    ap = argparse.ArgumentParser(description="Banner-only router likelihood probe (HTTP(S) headers only).")
    ap.add_argument(
        "--ip",
        default=None,
        help="Target IP (e.g., 192.168.1.1). Default: IPv4 default gateway from `ip route` when available.",
    )
    ap.add_argument(
        "--paths",
        nargs="+",
        default=None,
        metavar="PATH",
        help="Paths to probe (default: built-in multi-vendor admin/login list). Pass e.g. --paths / to probe only /.",
    )
    ap.add_argument("--ports", nargs="+", type=int, default=[80, 443], help="Ports to probe (default: 80 443)")
    ap.add_argument("--timeout", type=float, default=2.5, help="Request timeout (seconds).")
    ap.add_argument(
        "--insecure",
        action="store_true",
        help="Allow insecure HTTPS (self-signed certs). Banner-only headers; user-controlled.",
    )
    ap.add_argument("--out-json", default=None, help="Optional JSON output file.")
    ap.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print every path/port attempt (default: one-line summary).",
    )
    args = ap.parse_args()

    target_ip = args.ip or default_ipv4_gateway()
    if not target_ip:
        print("--- Banner-only probe ---")
        print("Could not determine target IP (pass --ip or ensure `ip -4 route show default` works).")
        print("-" * 30)
        print("SCORE: 1")
        print(" No default gateway; no probe performed.")
        return

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    paths = list(args.paths) if args.paths is not None else list(DEFAULT_BANNER_PATHS)

    evidence: dict[str, Any] = {
        "target_ip": target_ip,
        "ports": args.ports,
        "paths": paths,
        "timeout": args.timeout,
        "insecure": args.insecure,
        "results": [],
        "overall_score": 1,
        "verdict": "Unknown/Insufficient banner evidence",
    }

    overall = 1
    for port in args.ports:
        for path in paths:
            r = probe(
                ip=target_ip,
                port=port,
                path=path,
                timeout=args.timeout,
                insecure=args.insecure,
            )
            evidence["results"].append(r)
            overall = max(overall, r["final_score"])

    evidence["overall_score"] = overall

    if overall >= 5:
        evidence["verdict"] = "High suspicion: strong router-like banner headers (heuristic)"
    elif overall >= 4:
        evidence["verdict"] = "Elevated suspicion: router-like banner headers (heuristic)"
    elif overall >= 3:
        evidence["verdict"] = "Moderate suspicion: some router-like banner keywords (heuristic)"
    elif overall >= 2:
        evidence["verdict"] = "Low suspicion: weak banner signal (heuristic)"
    else:
        evidence["verdict"] = "No router-like Server: header"

    status_line = _banner_status_line(evidence["results"], overall)

    print(f"--- Banner probe {target_ip} | score={overall} ---")
    if not args.verbose:
        codes: dict[int, int] = {}
        for r in evidence["results"]:
            for a in r.get("attempts") or []:
                if isinstance(a, dict) and "status_code" in a:
                    c = int(a["status_code"])
                    codes[c] = codes.get(c, 0) + 1
        bits = ",".join(f"{k}×{v}" for k, v in sorted(codes.items())[:10])
        print(f"probes={len(evidence['results'])} HTTP codes [{bits}] | {evidence['verdict']}")
    else:
        print(f"Verdict: {evidence['verdict']} | overall_score={evidence['overall_score']}")
        for r in evidence["results"]:
            print(f"\n[{r['scheme']}://{r['ip']}:{r['port']}{r['path']}] score={r['final_score']}")
            for a in r["attempts"]:
                if "error" in a:
                    print(f"  - {a['method']}: ERROR: {a['error']}")
                    continue
                print(f"  - {a['method']}: status={a['status_code']} Server={a.get('server')!r}")
                if a.get("matched_keywords"):
                    print(f"    matched_keywords={a['matched_keywords']}")
                if a.get("banner_headers"):
                    print(f"    banner_headers={a['banner_headers']}")

    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)
        print(f"\n[+] Wrote JSON evidence to: {args.out_json}")

    print("-" * 30)
    print(f"SCORE: {overall}")
    print(f"STATUS: {status_line}")


if __name__ == "__main__":
    main()
