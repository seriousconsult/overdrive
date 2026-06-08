#!/usr/bin/env python3
"""
(Layer 7)
Port 80/443 (and common alt admin ports) HTTP(S) **header + light body** probes.

Most home/SOHO CPE exposes a web UI. Evidence often appears in:
``Server``, ``WWW-Authenticate`` (realm), ``Location`` redirects, a few other headers,
and sometimes HTML ``<title>`` / branding when ``Server`` is generic (nginx only).

Host-authenticity score **1-5**:
1 = authentic residential / not alerting; 5 = definitely artificial host.
This script internally measures router/CPE banner confidence, then maps strong
router/CPE evidence to a low exported SCORE because it supports a home setup.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import urllib3
from typing import Any
import requests

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_router_gateway import default_ipv4_gateway
from detections.common.common_router_upnp import extract_realm

# --- Header: Server (substring match, lowercase) ---
# SOHO CPE vendors, firmware names, and tiny HTTP stacks common on routers.
ROUTER_SERVER_KEYWORDS = [
    # Stacks / firmware
    "httpd",
    "uhttpd",
    "boa",
    "busybox",
    "goahead",
    "alphapd",
    "mini_httpd",
    "mathopd",
    "thttpd",
    "cherokee",
    "lighttpd",
    "mongoose",
    "rompager",
    "httpd/1.0",
    "httpd/2",
    "openwrt",
    "lede",
    "luci",
    "asuswrt",
    "asustek",
    "dd-wrt",
    "tomato",
    "gargoyle",
    "routeros",
    "mikrotik",
    "edgeos",
    "edgeswitch",
    "unifi",
    "ubiquiti",
    "airties",
    "ruijie",
    "peplink",
    "sophos",
    "zyxel",
    "zywall",
    "d-link",
    "dlink",
    "dir-",
    "netgear",
    "genie",
    "orbilogin",
    "tplink",
    "tp-link",
    "archer",
    "ax",
    "deco",
    "linksys",
    "velop",
    "eero",
    "google",
    "onhub",
    "nest wifi",
    "fritz",
    "avm",
    "fritzbox",
    "vodafone",
    "speedport",
    "telekom",
    "huawei",
    "hilink",
    "hicloud",
    "zte",
    "fiberhome",
    "tenda",
    "ip-com",
    "ipcom",
    "mercusys",
    "keewifi",
    "synology",
    "srm",
    "fortigate",
    "fortios",
    "pfsense",
    "opnsense",
    "ipfire",
    "zeroshell",
    "cisco",
    "catalyst",
    "gateway",
    "router",
    "wrt",
    "wireless",
    "firewall",
    "nginx",  # weak alone; combined with Location/realm elsewhere
]

# Generic stacks: weak signal unless corroborated by realm/Location/body.
_WEAK_SERVER_ONLY = frozenset(
    {
        "nginx",
        "busybox",
        "httpd",
        "mini_httpd",
        "thttpd",
        "mathopd",
        "mongoose",
    }
)

# Strong when seen in Server (vendor/firmware-specific).
_STRONG_SERVER_KEYWORDS = frozenset(
    {
        "openwrt",
        "lede",
        "luci",
        "asuswrt",
        "asustek",
        "routeros",
        "mikrotik",
        "edgeos",
        "unifi",
        "ubiquiti",
        "fritz",
        "avm",
        "fritzbox",
        "netgear",
        "tplink",
        "tp-link",
        "linksys",
        "d-link",
        "dlink",
        "zyxel",
        "huawei",
        "tenda",
        "gargoyle",
        "dd-wrt",
        "tomato",
        "orbilogin",
        "genie",
        "uhttpd",
        "goahead",
        "alphapd",
        "rompager",
        "boa",
        "lighttpd",
    }
)

BANNER_HEADERS = [
    "Server",
    "X-Powered-By",
    "WWW-Authenticate",
    "Location",
    "Content-Type",
    "Set-Cookie",
    "Refresh",
]

# Redirect or login paths typical of CPE admin UIs.
ROUTER_LOCATION_MARKERS = [
    "/login",
    "/logon",
    "/signin",
    "/auth",
    "/cgi-bin/",
    "/cgi-bin/luci",
    "/luci",
    "/webpages/",
    "/home.asp",
    "/home.htm",
    "/goform/",
    "/userRpm/",
    "/stattbl",
    "/main.cgi",
    "/webproc",
    "/portal",
    "/admin",
    "/ui/",
    "/manage",
    "/status",
    "/net/",
    "/wizard",
    "/quickset",
    "/default.html",
    "/index_login",
    "/login.asp",
    "/login.cgi",
    "/login.html",
    "/web_login",
]

# Realm substrings (Basic/Digest) often name the box or firmware.
ROUTER_REALM_MARKERS = [
    "router",
    "gateway",
    "wireless",
    "fritz",
    "fritz!",
    "avm",
    "netgear",
    "tplink",
    "tp-link",
    "asus",
    "linksys",
    "d-link",
    "dlink",
    "zyxel",
    "mikrotik",
    "routeros",
    "openwrt",
    "luci",
    "huawei",
    "zte",
    "vodafone",
    "speedport",
    "telekom",
    "arris",
    "sagem",
    "technicolor",
    "sercomm",
    "rt-ac",
    "rt-ax",
    "rut",
    "dir-",
    "archer",
    "deco",
    "orbi",
    "eero",
    "unifi",
    "edgeos",
    "airties",
    "fiberhome",
    "tenda",
    "mercusys",
    "keewifi",
    "synology",
    "httpd",
    "uhttp",
    "admin",
]

# Cookie name hints (OpenWrt LuCI, some OEMs).
ROUTER_COOKIE_MARKERS = [
    "sysauth",
    "luci",
    "sessionid",
    "sessid",
    "userid",
    "csrftoken",
    "wlsr",
    "acookie",
]

# Optional HTML/title fingerprints (GET body, first chunk only).
_BODY_TITLE_PAT = re.compile(
    r"<title[^>]*>([^<]{1,200})</title>",
    re.I | re.DOTALL,
)
_BODY_MARKERS: list[tuple[int, re.Pattern[str], str]] = [
    (5, re.compile(r"\bluci\b", re.I), "LuCI"),
    (5, re.compile(r"openwrt", re.I), "OpenWrt"),
    (4, re.compile(r"fritz!box|fritz\.os|avm", re.I), "FRITZ!OS/AVM"),
    (4, re.compile(r"routeros|mikrotik", re.I), "MikroTik"),
    (4, re.compile(r"unifi\s*(network|os)?|ubiquiti", re.I), "UniFi"),
    (4, re.compile(r"asuswrt|rt-[anax][xc]", re.I), "ASUS"),
    (4, re.compile(r"netgear|genie|orbilogin", re.I), "NETGEAR"),
    (4, re.compile(r"tp-?link|archer|deco", re.I), "TP-Link"),
    (4, re.compile(r"linksys|velop", re.I), "Linksys"),
    (4, re.compile(r"d-?link|dir-\d", re.I), "D-Link"),
    (4, re.compile(r"zyxel|zywall", re.I), "Zyxel"),
    (4, re.compile(r"huawei|hilink", re.I), "Huawei"),
    (4, re.compile(r"vodafone|speedport", re.I), "ISP CPE"),
    (3, re.compile(r"wireless\s+router|wifi\s+router|broadband\s+router", re.I), "generic router UI"),
    (3, re.compile(r"router\s+login|gateway\s+login|admin\s+login", re.I), "login branding"),
]

# Common admin / login / firmware paths (multi-vendor).
DEFAULT_BANNER_PATHS: tuple[str, ...] = (
    "/",
    "/index.html",
    "/login.html",
    "/login.asp",
    "/login.cgi",
    "/web_login.html",
    "/cgi-bin/luci",
    "/cgi-bin/luci/",
    "/admin/",
    "/admin/index.php",
    "/webpages/login.html",
    "/home.asp",
    "/goform/login",
    "/userRpm/Login.htm",
    "/status",
    "/portal",
    "/ui/",
    "/net/",
    "/wizard",
)


def score_server_banner(server_value: str | None) -> tuple[int, list[str]]:
    """Score from Server: only. Uses strong vs weak keyword tiers."""
    if not server_value:
        return 1, []

    sv = server_value.lower()
    matched = [kw for kw in ROUTER_SERVER_KEYWORDS if kw in sv]
    if not matched:
        return 1, []

    if any(k in sv for k in _STRONG_SERVER_KEYWORDS):
        # Distinct strong tokens only for count
        strong_hits = [k for k in _STRONG_SERVER_KEYWORDS if k in sv]
        n = len(set(strong_hits))
        if n >= 2:
            return 5, matched
        return 4, matched

    # Only weak generic tokens
    if matched and all(m in _WEAK_SERVER_ONLY for m in matched):
        return 2, matched

    n = len(set(matched))
    if n >= 3:
        return 5, matched
    if n == 2:
        return 4, matched
    return 3, matched


def score_location(location_value: str | None) -> tuple[int, list[str]]:
    if not location_value:
        return 1, []
    loc = location_value.lower()
    hits = [m for m in ROUTER_LOCATION_MARKERS if m in loc]
    if not hits:
        return 1, []
    if any(x in loc for x in ("/cgi-bin/luci", "/luci", "/webpages/", "/userRpm/", "/goform/")):
        return 4, hits
    if len(hits) >= 2:
        return 4, hits
    return 3, hits


def score_realm(www_auth: str | None) -> tuple[int, list[str]]:
    if not www_auth:
        return 1, []
    realm = extract_realm(www_auth).lower()
    hits = [m for m in ROUTER_REALM_MARKERS if m in realm]
    if not hits:
        return 1, []
    if any(
        x in realm
        for x in (
            "fritz",
            "netgear",
            "tplink",
            "tp-link",
            "asus",
            "mikrotik",
            "routeros",
            "openwrt",
            "luci",
            "zyxel",
            "d-link",
            "dlink",
            "linksys",
            "huawei",
            "rt-ac",
            "rt-ax",
            "dir-",
            "archer",
            "unifi",
            "edgeos",
        )
    ):
        return 5, hits
    if len(hits) >= 2:
        return 4, hits
    return 3, hits


def score_set_cookie(cookie_header: str | None) -> tuple[int, list[str]]:
    if not cookie_header:
        return 1, []
    ch = cookie_header.lower()
    hits = [m for m in ROUTER_COOKIE_MARKERS if m in ch]
    if not hits:
        return 1, []
    if "sysauth" in ch and "luci" in ch:
        return 5, hits
    if "sysauth" in ch or "luci" in ch:
        return 4, hits
    return 2, hits


def score_body_fingerprint(body: str | None) -> tuple[int, list[str]]:
    if not body:
        return 1, []
    chunk = body[:16384]
    reasons: list[str] = []
    best = 1
    t_m = _BODY_TITLE_PAT.search(chunk)
    if t_m:
        title = re.sub(r"\s+", " ", t_m.group(1).strip())[:120]
        if title:
            reasons.append(f"title:{title}")
    for weight, pat, label in _BODY_MARKERS:
        if pat.search(chunk):
            if weight > best:
                best = weight
            if label not in reasons:
                reasons.append(label)
    if best <= 1 and reasons:
        return 2, reasons
    return best, reasons


def combine_banner_scores(
    parts: list[tuple[int, str, list[str]]],
) -> tuple[int, list[str]]:
    """
    Merge independent signals. Corroboration bumps by 1 (cap 5).
    ``parts``: (score, label, detail_strings).
    """
    if not parts:
        return 1, []
    base = max(p[0] for p in parts)
    labels = [p[1] for p in parts if p[0] > 1]
    if len(set(labels)) >= 2 and base >= 2:
        base = min(5, base + 1)
    detail: list[str] = []
    for _s, lab, d in parts:
        if d:
            detail.append(f"{lab}:{'/'.join(d[:5])}")
    return base, detail


def cpe_confidence_to_host_score(cpe_score: int) -> int:
    """Map router/CPE confidence onto the global host-authenticity score."""
    if cpe_score >= 4:
        return 1
    if cpe_score >= 2:
        return 2
    return 3


def request_with_method(
    session: requests.Session,
    method: str,
    url: str,
    timeout: float,
    insecure: bool,
    scan_body: bool,
) -> dict[str, Any]:
    resp = session.request(
        method=method,
        url=url,
        timeout=timeout,
        verify=(not insecure),
        allow_redirects=False,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; banner-probe/1.1; SOHO router survey)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        },
    )

    headers = dict(resp.headers)
    server = headers.get("Server")
    loc = headers.get("Location")
    auth = headers.get("WWW-Authenticate")
    cookies = headers.get("Set-Cookie")

    parts: list[tuple[int, str, list[str]]] = []
    s_score, s_kw = score_server_banner(server)
    if s_score > 1:
        parts.append((s_score, "server", s_kw))
    l_score, l_h = score_location(loc)
    if l_score > 1:
        parts.append((l_score, "location", l_h))
    r_score, r_h = score_realm(auth)
    if r_score > 1:
        parts.append((r_score, "realm", r_h))
    c_score, c_h = score_set_cookie(cookies)
    if c_score > 1:
        parts.append((c_score, "cookie", c_h))

    body_score, body_reasons = (1, [])
    body_snippet = ""
    if method == "GET" and scan_body and resp.text:
        body_score, body_reasons = score_body_fingerprint(resp.text)
        if body_reasons:
            parts.append((body_score, "body", body_reasons))
        body_snippet = resp.text[:400].replace("\n", " ").replace("\r", " ")

    score, combined_detail = combine_banner_scores(parts)

    banner_subset = {k: headers.get(k) for k in BANNER_HEADERS if k in headers}

    out: dict[str, Any] = {
        "method": method,
        "url": url,
        "status_code": resp.status_code,
        "server": server,
        "matched_keywords": s_kw if s_score > 1 else [],
        "banner_headers": banner_subset,
        "score": score,
        "signals": {
            "server": {"score": s_score, "keywords": s_kw},
            "location": {"score": l_score, "markers": l_h},
            "realm": {"score": r_score, "markers": r_h},
            "cookie": {"score": c_score, "markers": c_h},
            "body": {"score": body_score, "markers": body_reasons},
        },
        "combined_detail": combined_detail,
    }
    if method == "GET" and scan_body and body_snippet:
        out["body_prefix"] = body_snippet[:280] + ("…" if len(body_snippet) > 280 else "")
    return out


def probe(
    ip: str,
    port: int,
    path: str,
    timeout: float,
    insecure: bool,
    max_tries: int = 2,
    scan_body: bool = True,
) -> dict[str, Any]:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}{path}"

    session = requests.Session()
    results: list[dict[str, Any]] = []

    tried = 0
    for method in ["HEAD", "GET"]:
        tried += 1
        try:
            body_on_get = scan_body and method == "GET"
            r = request_with_method(
                session, method, url, timeout=timeout, insecure=insecure, scan_body=body_on_get
            )
            results.append(r)

            if method == "HEAD" and r.get("server"):
                break
            # Strong signal from headers alone — skip body GET if HEAD already high
            if method == "HEAD" and int(r.get("score", 1)) >= 4:
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

    cpe_score = max((r.get("score", 1) for r in results if isinstance(r, dict)), default=1)
    final_score = cpe_confidence_to_host_score(int(cpe_score))
    return {
        "ip": ip,
        "port": port,
        "scheme": scheme,
        "path": path,
        "attempts": results,
        "cpe_score": cpe_score,
        "final_score": final_score,
    }


def _banner_status_line(results: list[dict[str, Any]], overall: int) -> str:
    """One line for STATUS: after SCORE."""
    if overall >= 3:
        return f"No strong CPE banner signal ({len(results)} probes)"
    for r in results:
        if int(r.get("cpe_score", 1)) <= 1:
            continue
        for a in r.get("attempts") or []:
            if not isinstance(a, dict) or "error" in a:
                continue
            srv = (a.get("server") or "").strip()
            if srv:
                return srv[:200]
            bh = a.get("banner_headers") or {}
            auth = (bh.get("WWW-Authenticate") or "").strip()
            if auth:
                return extract_realm(auth)[:200]
            loc = (bh.get("Location") or "").strip()
            if loc:
                return loc[:200]
            det = a.get("combined_detail") or []
            if det:
                return "; ".join(det)[:200]
    return f"Residential banner evidence score {overall}"


def main() -> None:
    ap = argparse.ArgumentParser(
        description="HTTP(S) banner probe for home/SOHO CPE (headers + optional body hints)."
    )
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
        help="Paths to probe (default: built-in multi-vendor admin/login list).",
    )
    ap.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=[80, 443, 8080, 8443],
        help="Ports to probe (default: 80 443 8080 8443)",
    )
    ap.add_argument("--timeout", type=float, default=2.5, help="Request timeout (seconds).")
    ap.add_argument(
        "--insecure",
        action="store_true",
        help="Allow invalid/self-signed HTTPS (typical for LAN gateways).",
    )
    ap.add_argument(
        "--no-body",
        action="store_true",
        help="Disable GET body/title fingerprinting (headers only).",
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
        print("SCORE: 3")
        print("STATUS: No default gateway; no residential banner evidence available.")
        return

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    paths = list(args.paths) if args.paths is not None else list(DEFAULT_BANNER_PATHS)
    scan_body = not args.no_body

    evidence: dict[str, Any] = {
        "target_ip": target_ip,
        "ports": args.ports,
        "paths": paths,
        "timeout": args.timeout,
        "insecure": args.insecure,
        "body_scan": scan_body,
        "results": [],
        "overall_score": 3,
        "cpe_confidence": 1,
        "verdict": "Unknown/Insufficient banner evidence",
    }

    overall = 3
    cpe_overall = 1
    for port in args.ports:
        for path in paths:
            r = probe(
                ip=target_ip,
                port=port,
                path=path,
                timeout=args.timeout,
                insecure=args.insecure,
                scan_body=scan_body,
            )
            evidence["results"].append(r)
            overall = min(overall, r["final_score"])
            cpe_overall = max(cpe_overall, int(r.get("cpe_score", 1)))

    evidence["overall_score"] = overall
    evidence["cpe_confidence"] = cpe_overall

    if overall <= 1:
        evidence["verdict"] = "Residential: strong multi-signal CPE/router-like evidence"
    elif overall == 2:
        evidence["verdict"] = "Likely residential: weak router/CPE banner evidence"
    else:
        evidence["verdict"] = "Ambiguous: no router-like banner evidence"

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
        print(
            f"Verdict: {evidence['verdict']} | overall_score={evidence['overall_score']} "
            f"| cpe_confidence={evidence['cpe_confidence']}"
        )
        for r in evidence["results"]:
            print(
                f"\n[{r['scheme']}://{r['ip']}:{r['port']}{r['path']}] "
                f"score={r['final_score']} cpe_confidence={r.get('cpe_score')}"
            )
            for a in r["attempts"]:
                if "error" in a:
                    print(f"  - {a['method']}: ERROR: {a['error']}")
                    continue
                print(f"  - {a['method']}: status={a['status_code']} Server={a.get('server')!r}")
                sig = a.get("signals") or {}
                print(f"    signals: {json.dumps(sig, default=str)[:500]}")
                if a.get("combined_detail"):
                    print(f"    combined: {a['combined_detail']}")
                if a.get("body_prefix"):
                    print(f"    body_prefix: {a['body_prefix']!r}")

    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)
        print(f"\n[+] Wrote JSON evidence to: {args.out_json}")

    print("-" * 30)
    print(f"SCORE: {overall}")
    print(f"STATUS: {status_line}")


if __name__ == "__main__":
    main()
