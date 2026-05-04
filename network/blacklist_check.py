#!/usr/bin/env python3
from __future__ import annotations
import socket
from typing import Any
import requests

"""
IP Blacklist Check

Queries public IPv4 against several DNS blocklists (DNSBL / RBL).
Uses ip-api metadata (hosting/datacenter) as a secondary signal.

Score (1–5):
  5 — Listed on Spamhaus ZEN with a high-severity code (SBL/XBL/DROP/CSS, etc.)
  4 — Listed on ZEN PBL only, or on other DNSBLs, or multiple hits
  3 — Could not complete checks (no IPv4, DNS failures)
  2 — Not on queried lists, but ip-api marks IP as hosting/datacenter
  1 — Clean on queried lists and not flagged as hosting
"""
#!/usr/bin/env python3
"""
IP Blacklist Check

Queries public IPv4 against several DNS blocklists (DNSBL / RBL).
Uses ip-api metadata (hosting/datacenter) as a secondary signal.

Score (1–5):
  5 — Listed on Spamhaus ZEN with a high-severity code (SBL/XBL/DROP/CSS, etc.)
  4 — Listed on ZEN PBL only, or on other DNSBLs, or multiple hits
  3 — Could not complete checks (no IPv4, DNS failures, or DNSBL Service Blocked)
  2 — Not on queried lists, but ip-api marks IP as hosting/datacenter
  1 — Clean on queried lists and not flagged as hosting
"""



IPIFY = "https://api.ipify.org?format=json"
IP_API = "http://ip-api.com/json/{ip}"
TIMEOUT = 8
UA = {"User-Agent": "overdrive-blacklist-check/1.0"}

# (zone, label) — IPv4 reverse DNSBL only
DNSBL_ZONES: tuple[tuple[str, str], ...] = (
    ("zen.spamhaus.org", "spamhaus-zen"),
    ("bl.spamcop.net", "spamcop"),
    ("b.barracudacentral.org", "barracuda"),
)

# Spamhaus ZEN last-octet meanings (127.0.0.X)
ZEN_SEVERE_OCTETS = frozenset({2, 3, 4, 9, 11})  # SBL, CSS, XBL, DROP, extended CSS
ZEN_PBL_OCTET = 10
# Spamhaus Service Error Codes (127.255.255.X)
ZEN_BLOCKED_RESOLVER = "127.255.255.254"


def public_ipv4() -> str | None:
    try:
        r = requests.get(IPIFY, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        ip = r.json().get("ip")
        if not ip or ":" in str(ip):
            return None
        return str(ip).strip()
    except (requests.RequestException, ValueError, KeyError):
        return None


def reverse_ipv4_for_dnsbl(ip: str) -> str | None:
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        nums = [int(p) for p in parts]
        if any(n < 0 or n > 255 for n in nums):
            return None
    except ValueError:
        return None
    return ".".join(reversed(parts))


def dnsbl_lookup(ip: str, zone: str) -> tuple[str, str | None]:
    rev = reverse_ipv4_for_dnsbl(ip)
    if not rev:
        return "error", "not-ipv4"
    query = f"{rev}.{zone}"
    try:
        resolved = socket.gethostbyname(query)
    except socket.gaierror:
        return "clean", None
    except OSError as e:
        return "error", str(e)

    # Check specifically for Spamhaus block codes
    if resolved == ZEN_BLOCKED_RESOLVER:
        return "error", "dns-resolver-blocked-by-spamhaus"
    
    return "listed", resolved


def zen_severity(list_return: str) -> str:
    if list_return == ZEN_BLOCKED_RESOLVER:
        return "blocked"
    try:
        last = int(list_return.rsplit(".", 1)[-1])
    except ValueError:
        return "unknown"
    if last in ZEN_SEVERE_OCTETS:
        return "severe"
    if last == ZEN_PBL_OCTET:
        return "pbl"
    return "other"


def ip_api_meta(ip: str) -> dict[str, Any]:
    try:
        r = requests.get(IP_API.format(ip=ip), headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError):
        return {}


def check_ip_blacklist() -> tuple[int, str]:
    ip = public_ipv4()
    if not ip:
        return 3, "Could not get public IPv4 (need IPv4 for DNSBL queries)."

    hits: list[str] = []
    zen_hit: str | None = None
    errors = 0
    dns_blocked = False

    for zone, label in DNSBL_ZONES:
        status, detail = dnsbl_lookup(ip, zone)
        if status == "error":
            errors += 1
            if detail == "dns-resolver-blocked-by-spamhaus":
                dns_blocked = True
            if detail:
                hits.append(f"{label}:error({detail})")
            continue
        if status == "listed" and detail:
            hits.append(f"{label}:{detail}")
            if label == "spamhaus-zen":
                zen_hit = detail

    if dns_blocked:
        return (
            3,
            "Spamhaus query blocked: Using a public DNS resolver (e.g. Google/Cloudflare) is not supported for ZEN queries."
        )

    if errors == len(DNSBL_ZONES):
        return (
            3,
            "All DNSBL lookups failed (resolver blocked, offline, or policy).",
        )

    if zen_hit:
        sev = zen_severity(zen_hit)
        if sev == "severe":
            return (
                5,
                f"Listed on Spamhaus ZEN ({zen_hit}) — high-severity reputation hit.",
            )
        non_err_hits = [h for h in hits if ":error" not in h]
        if sev == "pbl":
            if len(non_err_hits) <= 1:
                return (
                    4,
                    f"Spamhaus PBL only ({zen_hit}) — often dynamic/residential ranges; verify context.",
                )
            return (
                4,
                "PBL plus other DNSBL signals: " + "; ".join(non_err_hits[:4]),
            )
        return 4, f"Listed on Spamhaus ZEN ({zen_hit})."

    other_listed = [h for h in hits if "spamhaus-zen" not in h and ":error" not in h]
    if other_listed:
        return (
            4,
            "Listed on at least one DNSBL: " + "; ".join(other_listed[:3]),
        )

    if hits and all(":error" in h or h.startswith("spamhaus-zen:error") for h in hits):
        meta = ip_api_meta(ip)
        hosting = meta.get("hosting") is True if meta.get("status") == "success" else None
        if hosting:
            return 2, "DNSBL inconclusive; ip-api flags hosting/datacenter."
        return 3, "DNSBL lookups mostly failed; could not confirm clean status."

    meta = ip_api_meta(ip)
    hosting = meta.get("hosting") is True if meta.get("status") == "success" else False

    if hosting:
        return (
            2,
            "Not listed on queried DNSBLs; ip-api marks this IP as hosting/datacenter.",
        )

    return (
        1,
        "Not listed on queried DNSBLs (zen, spamcop, barracuda); no hosting flag from ip-api.",
    )


def main():
    print("=" * 60)
    print("IP Blacklist Check")
    print("=" * 60)

    ip = public_ipv4()
    print(f"\nPublic IPv4: {ip or '(unavailable)'}\n")

    if ip:
        print("DNSBL queries (IPv4 reverse):")
        for zone, label in DNSBL_ZONES:
            status, detail = dnsbl_lookup(ip, zone)
            if status == "clean":
                print(f"  {label}: clean")
            elif status == "listed":
                print(f"  {label}: LISTED -> {detail}")
            else:
                print(f"  {label}: error -> {detail}")

    score, description = check_ip_blacklist()

    print("\n" + "-" * 40)
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print("-" * 40)
    print("=" * 60)


if __name__ == "__main__":
    main()