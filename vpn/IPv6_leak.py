#!/usr/bin/env python3
"""
IPv6 Leak Detection

Many VPNs tunnel only IPv4. If the host still has working IPv6 to the Internet,
traffic (or DNS) can bypass the VPN.

Heuristics (no admin / no extra packages):
  - Public IPv4 vs IPv6 as seen by ipify-style HTTPS endpoints
  - Optional: global IPv6 addresses on local interfaces (ip / PowerShell)
  - ip-api.com metadata: country + ISP; mismatch suggests split routing / leak

Score (1–5):
  5 = Strong signs of IPv6 taking a different exit than IPv4 (likely leak)
  4 = IPv6 egress works; could not fully validate or only soft mismatch
  3 = Inconclusive (partial failures, odd local vs egress)
  2 = No working IPv6 egress / effectively no global IPv6 path
  1 = IPv4 and IPv6 exits look consistent (same country, similar ISP string)
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import Any

import requests

IPV4_URL = "https://api.ipify.org?format=json"
IPV6_URL = "https://api6.ipify.org?format=json"
IP_API = "http://ip-api.com/json/{ip}"
TIMEOUT = 10
UA = {"User-Agent": "overdrive-ipv6-leak/1.0"}


def _fetch_json(url: str) -> dict[str, Any] | None:
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError):
        return None


def public_ipv4() -> str | None:
    data = _fetch_json(IPV4_URL)
    if not data:
        return None
    ip = data.get("ip")
    return str(ip).strip() if ip else None


def public_ipv6() -> str | None:
    """Only succeeds when the host can complete HTTPS over IPv6 to api6."""
    data = _fetch_json(IPV6_URL)
    if not data:
        return None
    ip = data.get("ip")
    if not ip or ":" not in str(ip):
        return None
    return str(ip).strip()


def local_global_ipv6_hint() -> bool | None:
    """
    True  = at least one non-loopback global IPv6 seen locally
    False = checked and saw none
    None  = could not determine (no ip/PowerShell)
    """
    if sys.platform == "win32":
        try:
            ps = (
                "$a = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
                "Where-Object { $_.IPAddress -notlike 'fe80:*' -and $_.IPAddress -ne '::1' }; "
                "if ($a) { 'yes' } else { 'no' }"
            )
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=12,
            )
            t = (out.stdout or "").strip().lower()
            if "yes" in t:
                return True
            if "no" in t:
                return False
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None

    try:
        out = subprocess.run(
            ["ip", "-6", "addr", "show", "scope", "global"],
            capture_output=True,
            text=True,
            timeout=6,
        )
        if out.returncode != 0:
            return None
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet6 ") and not line.startswith("inet6 fe80:"):
                return True
        return False
    except (OSError, subprocess.TimeoutExpired):
        return None


def ip_metadata(ip: str) -> dict[str, Any]:
    try:
        r = requests.get(IP_API.format(ip=ip), headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError):
        return {}


def _norm_org(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"\s+", " ", s)
    return s


def _orgs_consistent(a: str, b: str) -> bool:
    a, b = _norm_org(a), _norm_org(b)
    if not a or not b:
        return True
    if a == b:
        return True
    if a in b or b in a:
        return True
    # Same first token (short AS name / brand)
    ta, tb = a.split()[:1], b.split()[:1]
    return bool(ta and tb and ta == tb)


def check_ipv6_leak() -> tuple[int, str]:
    v4 = public_ipv4()
    v6 = public_ipv6()
    local_v6 = local_global_ipv6_hint()

    if v4 is None and v6 is None:
        return 3, "Could not reach ipify over IPv4 or IPv6 (offline or blocked)."

    if v6 is None:
        if local_v6 is True:
            return (
                3,
                "Global IPv6 present locally but HTTPS to api6.ipify.org failed "
                "(broken v6 route, firewall, or split stack).",
            )
        if local_v6 is False:
            return (
                2,
                "No global IPv6 on host and no IPv6 egress to ipify — low IPv6 leak surface.",
            )
        return (
            3,
            "No IPv6 address from ipify; could not inspect local interfaces — inconclusive.",
        )

    if v4 is None:
        return (
            3,
            "IPv6 egress works but IPv4 check failed — cannot compare paths.",
        )

    m4, m6 = ip_metadata(v4), ip_metadata(v6)
    ok4 = m4.get("status") == "success"
    ok6 = m6.get("status") == "success"

    if not ok4 or not ok6:
        return (
            4,
            f"Both exits respond ({v4} / {v6}) but ISP lookup incomplete; "
            "enable HTTP to ip-api or retry.",
        )

    cc4 = (m4.get("countryCode") or "").upper()
    cc6 = (m6.get("countryCode") or "").upper()
    isp4 = m4.get("isp") or m4.get("org") or ""
    isp6 = m6.get("isp") or m6.get("org") or ""

    if cc4 and cc6 and cc4 != cc6:
        return (
            5,
            f"Likely IPv6 leak: IPv4 in {cc4}, IPv6 in {cc6} ({v4} vs {v6}).",
        )

    if cc4 and cc6 and cc4 == cc6 and _orgs_consistent(isp4, isp6):
        return (
            1,
            f"IPv4/IPv6 agree ({cc4}); ISP metadata similar — no obvious split exit.",
        )

    if cc4 and cc6 and cc4 == cc6 and isp4 and isp6 and not _orgs_consistent(isp4, isp6):
        return (
            5,
            f"Same country but different ISP labels (IPv4: {isp4[:50]} vs IPv6: {isp6[:50]}) — "
            "possible v6 bypass of VPN.",
        )

    return (
        4,
        f"IPv6 enabled ({v6}); same region but metadata partially missing — verify manually.",
    )


def main():
    print("=" * 60)
    print("IPv6 Leak Detection")
    print("=" * 60)

    v4 = public_ipv4()
    v6 = public_ipv6()
    print("\n[Observed public addresses]")
    print(f"  IPv4 (ipify): {v4 or '(unavailable)'}")
    print(f"  IPv6 (ipify): {v6 or '(unavailable)'}")
    hint = local_global_ipv6_hint()
    if hint is not None:
        print(f"  Local global IPv6 hint: {'yes' if hint else 'no'}")
    else:
        print("  Local global IPv6 hint: (not checked / unknown)")

    score, description = check_ipv6_leak()

    print("\n" + "-" * 40)
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print("-" * 40)
    print("=" * 60)


if __name__ == "__main__":
    main()
