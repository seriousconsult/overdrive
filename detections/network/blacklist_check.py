#!/usr/bin/env python3
"""IP Blacklist Check — DNSBL / RBL queries and ip-api hosting signal.

Queries public IPv4 against several DNS blocklists (DNSBL / RBL).
Uses ip-api metadata (hosting/datacenter) as a secondary signal.

Score (1–5):
  5 — Listed on Spamhaus ZEN with a high-severity code (SBL/XBL/DROP/CSS, etc.)
  4 — Listed on ZEN PBL only, or on other DNSBLs, or multiple hits
  3 — Could not complete checks (no IPv4, DNS failures, or DNSBL Service Blocked)
  2 — Not on queried lists, but ip-api marks IP as hosting/datacenter
  1 — Clean on queried lists and not flagged as hosting

Reliability:
  - Consensus public IPv4 (multiple probes)
  - DNSBL answers validated as 127.0.0.0/8; Spamhaus policy blocks detected
  - Transient DNS failures retried; listings confirmed with a second lookup
  - Single pass (no double-query in main)
  - Short TTL disk cache so back-to-back runs stay stable

Uses ``common.common_network`` for public IPv4 and reverse-DNSBL host construction.
"""
from __future__ import annotations

import ipaddress
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import requests

from detections.common.common_cache import (
    env_cache_disabled,
    env_cache_ttl_s,
    read_ip_score_cache,
    write_ip_score_cache,
)
from detections.common.common_config import (
    BLACKLIST_TIMEOUT,
    DNSBL_ZONES,
    IP_API_URL_WITH_FIELDS,
    OVERDRIVE_CACHE_DIR,
    USER_AGENTS,
    ZEN_BLOCKED_RESOLVER,
    ZEN_PBL_OCTET,
    ZEN_SEVERE_OCTETS,
)
from detections.common.common_network import (
    resolve_egress_ipv4,
    reverse_ipv4_for_dnsbl,
)

UA = {"User-Agent": USER_AGENTS["blacklist"]}

# Confirm listings / retry flaky DNS without hammering RBLs on every re-run.
_DNS_ATTEMPTS = 3
_DNS_RETRY_SLEEP_S = 0.35
_LISTING_CONFIRM_SLEEP_S = 0.2
_DEFAULT_CACHE_TTL_S = 120
_CACHE_NAME = "blacklist_check.json"


@dataclass(frozen=True)
class DnsblResult:
    zone: str
    label: str
    status: str  # clean | listed | error
    detail: str | None
    codes: tuple[str, ...] = ()


def _cache_ttl_s() -> int:
    return env_cache_ttl_s("OVERDRIVE_BLACKLIST_CACHE_TTL", _DEFAULT_CACHE_TTL_S)


def _cache_disabled() -> bool:
    return env_cache_disabled("OVERDRIVE_BLACKLIST_NO_CACHE")


def _cache_path() -> Path:
    return OVERDRIVE_CACHE_DIR / _CACHE_NAME


def _read_cache(ip: str) -> tuple[int, str, list[dict[str, Any]]] | None:
    data = read_ip_score_cache(
        _cache_path(),
        ip=ip,
        ttl_s=_cache_ttl_s(),
        disabled=_cache_disabled(),
    )
    if not data:
        return None
    results = data.get("results")
    if not isinstance(results, list):
        results = []
    return int(data["score"]), str(data["description"]), results


def _write_cache(
    ip: str,
    score: int,
    description: str,
    results: list[DnsblResult],
) -> None:
    write_ip_score_cache(
        _cache_path(),
        ip=ip,
        score=score,
        description=description,
        disabled=_cache_disabled(),
        ttl_s=_cache_ttl_s(),
        results=[
            {
                "zone": r.zone,
                "label": r.label,
                "status": r.status,
                "detail": r.detail,
                "codes": list(r.codes),
            }
            for r in results
        ],
    )


def public_ipv4() -> tuple[str | None, str]:
    """Return ``(ipv4, note)`` using multi-probe consensus when possible."""
    ip, strong, note = resolve_egress_ipv4(
        user_agent=UA["User-Agent"],
        timeout=BLACKLIST_TIMEOUT,
    )
    if ip and not strong and note:
        return ip, note
    if ip:
        return ip, ""
    return None, note or "Could not get public IPv4 (need IPv4 for DNSBL queries)."


def _is_dnsbl_positive(addr: str) -> bool:
    """True for conventional DNSBL positives in 127.0.0.0/8 (excl. policy block)."""
    if addr == ZEN_BLOCKED_RESOLVER:
        return False
    try:
        return ipaddress.ip_address(addr) in ipaddress.ip_network("127.0.0.0/8")
    except ValueError:
        return False


def _dnsbl_lookup_once(ip: str, zone: str) -> tuple[str, str | None, tuple[str, ...]]:
    rev = reverse_ipv4_for_dnsbl(ip)
    if not rev:
        return "error", "not-ipv4", ()
    query = f"{rev}.{zone}"
    try:
        infos = socket.getaddrinfo(query, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        # NXDOMAIN / no answer → not listed (normal clean path)
        return "clean", None, ()
    except OSError as e:
        return "error", str(e), ()

    addrs: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            addrs.append(sockaddr[0])
    uniq = list(dict.fromkeys(addrs))

    if not uniq:
        return "clean", None, ()

    if ZEN_BLOCKED_RESOLVER in uniq:
        return "error", "dns-resolver-blocked-by-spamhaus", (ZEN_BLOCKED_RESOLVER,)

    positives = [a for a in uniq if _is_dnsbl_positive(a)]
    if positives:
        return "listed", positives[0], tuple(positives)

    # Non-127 answers are not trustworthy DNSBL positives (hijack / captive DNS).
    return "error", f"unexpected-dnsbl-answer:{uniq[0]}", tuple(uniq)


def dnsbl_lookup(ip: str, zone: str) -> tuple[str, str | None]:
    """Public helper: ``(status, detail)`` with retries + listing confirmation."""
    result = _dnsbl_query(ip, zone)
    return result.status, result.detail


def _dnsbl_query(ip: str, zone: str, *, label: str | None = None) -> DnsblResult:
    lbl = label or zone
    last_status, last_detail, last_codes = "error", "no-attempt", ()

    for attempt in range(_DNS_ATTEMPTS):
        status, detail, codes = _dnsbl_lookup_once(ip, zone)
        last_status, last_detail, last_codes = status, detail, codes

        if status == "clean":
            return DnsblResult(zone, lbl, "clean", None, ())

        if status == "error":
            # Policy blocks will not clear on retry; other OS/DNS errors might.
            if detail == "dns-resolver-blocked-by-spamhaus":
                return DnsblResult(zone, lbl, "error", detail, codes)
            if attempt + 1 < _DNS_ATTEMPTS:
                time.sleep(_DNS_RETRY_SLEEP_S * (attempt + 1))
                continue
            return DnsblResult(zone, lbl, "error", detail, codes)

        # status == listed — confirm once to reduce flapping / poison answers
        time.sleep(_LISTING_CONFIRM_SLEEP_S)
        status2, detail2, codes2 = _dnsbl_lookup_once(ip, zone)
        if status2 == "listed":
            merged = tuple(dict.fromkeys([*codes, *codes2]))
            return DnsblResult(zone, lbl, "listed", detail2 or detail, merged)
        if status2 == "clean":
            # Unstable listing → treat as inconclusive for this zone
            return DnsblResult(
                zone,
                lbl,
                "error",
                "listing-unconfirmed",
                codes,
            )
        if detail2 == "dns-resolver-blocked-by-spamhaus":
            return DnsblResult(zone, lbl, "error", detail2, codes2)
        if attempt + 1 < _DNS_ATTEMPTS:
            time.sleep(_DNS_RETRY_SLEEP_S * (attempt + 1))
            continue
        return DnsblResult(zone, lbl, "error", detail2 or "listing-unconfirmed", codes2)

    return DnsblResult(zone, lbl, last_status, last_detail, last_codes)


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


def _worst_zen_code(codes: tuple[str, ...]) -> str | None:
    """Pick the most severe ZEN return code from a multi-A answer set."""
    if not codes:
        return None
    rank = {"severe": 3, "other": 2, "pbl": 1, "unknown": 0, "blocked": -1}
    best = codes[0]
    best_rank = -2
    for c in codes:
        sev = zen_severity(c)
        r = rank.get(sev, 0)
        if r > best_rank:
            best = c
            best_rank = r
    return best


def ip_api_meta(ip: str) -> dict[str, Any]:
    try:
        r = requests.get(
            IP_API_URL_WITH_FIELDS.format(ip=ip),
            headers=UA,
            timeout=BLACKLIST_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, dict) else {}
    except (requests.RequestException, ValueError):
        return {}


def _query_all_dnsbls(ip: str) -> list[DnsblResult]:
    return [
        _dnsbl_query(ip, zone, label=label)
        for zone, label in DNSBL_ZONES
    ]


def _score_from_results(
    ip: str,
    results: list[DnsblResult],
    *,
    ip_note: str = "",
) -> tuple[int, str]:
    hits: list[str] = []
    zen_hit: str | None = None
    zen_codes: tuple[str, ...] = ()
    errors = 0
    dns_blocked = False
    listed_count = 0

    for r in results:
        if r.status == "error":
            errors += 1
            if r.detail == "dns-resolver-blocked-by-spamhaus":
                dns_blocked = True
            if r.detail:
                hits.append(f"{r.label}:error({r.detail})")
            continue
        if r.status == "listed" and r.detail:
            listed_count += 1
            code_s = ",".join(r.codes) if r.codes else r.detail
            hits.append(f"{r.label}:{code_s}")
            if r.label == "spamhaus-zen":
                zen_hit = _worst_zen_code(r.codes) or r.detail
                zen_codes = r.codes

    prefix = f"{ip_note} " if ip_note else ""

    # Spamhaus policy block: inconclusive for ZEN, but other lists may still count.
    if dns_blocked and listed_count == 0:
        other_ok = any(r.status == "clean" for r in results if r.label != "spamhaus-zen")
        if other_ok:
            meta = ip_api_meta(ip)
            hosting = (
                meta.get("hosting") is True if meta.get("status") == "success" else None
            )
            if hosting:
                return (
                    2,
                    prefix
                    + "Spamhaus ZEN blocked (public resolver); other DNSBLs clean; "
                    "ip-api flags hosting/datacenter.",
                )
            return (
                3,
                prefix
                + "Spamhaus ZEN query blocked (public/shared DNS not allowed); "
                "other queried DNSBLs clean — ZEN inconclusive.",
            )
        return (
            3,
            prefix
            + "Spamhaus query blocked: public DNS resolvers (e.g. Google/Cloudflare) "
            "are not supported for ZEN; other lookups also failed.",
        )

    if errors == len(results):
        return (
            3,
            prefix + "All DNSBL lookups failed (resolver blocked, offline, or policy).",
        )

    if zen_hit:
        sev = zen_severity(zen_hit)
        if sev == "severe":
            return (
                5,
                prefix
                + f"Listed on Spamhaus ZEN ({zen_hit}"
                + (f"; codes={','.join(zen_codes)}" if len(zen_codes) > 1 else "")
                + ") — high-severity reputation hit.",
            )
        non_err_hits = [h for h in hits if ":error" not in h]
        if sev == "pbl":
            if len(non_err_hits) <= 1:
                return (
                    4,
                    prefix
                    + f"Spamhaus PBL only ({zen_hit}) — often dynamic/residential "
                    "ranges; verify context.",
                )
            return (
                4,
                prefix + "PBL plus other DNSBL signals: " + "; ".join(non_err_hits[:4]),
            )
        return 4, prefix + f"Listed on Spamhaus ZEN ({zen_hit})."

    other_listed = [
        h for h in hits if "spamhaus-zen" not in h and ":error" not in h
    ]
    if other_listed:
        return (
            4,
            prefix + "Listed on at least one DNSBL: " + "; ".join(other_listed[:3]),
        )

    usable = [r for r in results if r.status in ("clean", "listed")]
    if not usable:
        meta = ip_api_meta(ip)
        hosting = meta.get("hosting") is True if meta.get("status") == "success" else None
        if hosting:
            return 2, prefix + "DNSBL inconclusive; ip-api flags hosting/datacenter."
        return 3, prefix + "DNSBL lookups mostly failed; could not confirm clean status."

    # At least one clean/listed result and no confirmed listings.
    meta = ip_api_meta(ip)
    if meta.get("status") != "success":
        # Prefer clean DNSBL evidence over a failed secondary signal.
        clean_n = sum(1 for r in results if r.status == "clean")
        if clean_n >= 2:
            return (
                1,
                prefix
                + "Not listed on queried DNSBLs (zen, spamcop, barracuda); "
                "ip-api unavailable.",
            )
        return (
            3,
            prefix + "Partial DNSBL clean; ip-api unavailable — weak confirmation.",
        )

    hosting = meta.get("hosting") is True
    proxy = meta.get("proxy") is True
    if hosting or proxy:
        flag = "proxy" if proxy and not hosting else "hosting/datacenter"
        if proxy and hosting:
            flag = "proxy+hosting"
        return (
            2,
            prefix
            + f"Not listed on queried DNSBLs; ip-api marks this IP as {flag}.",
        )

    return (
        1,
        prefix
        + "Not listed on queried DNSBLs (zen, spamcop, barracuda); "
        "no hosting flag from ip-api.",
    )


def check_ip_blacklist() -> tuple[int, str]:
    ip, note = public_ipv4()
    if not ip:
        return 3, note

    cached = _read_cache(ip)
    if cached:
        score, description, _ = cached
        return score, f"[cached ≤{_cache_ttl_s()}s] {description}"

    results = _query_all_dnsbls(ip)
    score, description = _score_from_results(ip, results, ip_note=note)
    _write_cache(ip, score, description, results)
    return score, description


def main() -> None:
    print("=" * 60)
    print("IP Blacklist Check")
    print("=" * 60)

    ip, note = public_ipv4()
    print(f"\nPublic IPv4: {ip or '(unavailable)'}")
    if note:
        print(f"Note: {note}")
    print()

    if not ip:
        score, description = 3, note
        print("-" * 40)
        print(f"SCORE: {score}")
        print(f"STATUS: {description}")
        print("-" * 40)
        print("=" * 60)
        return

    cached = _read_cache(ip)
    if cached:
        score, description, cached_results = cached
        print(f"DNSBL queries (cached, TTL {_cache_ttl_s()}s):")
        for row in cached_results:
            label = row.get("label", "?")
            status = row.get("status", "?")
            detail = row.get("detail")
            codes = row.get("codes") or []
            if status == "clean":
                print(f"  {label}: clean")
            elif status == "listed":
                shown = ",".join(codes) if codes else detail
                print(f"  {label}: LISTED -> {shown}")
            else:
                print(f"  {label}: error -> {detail}")
        print("\n" + "-" * 40)
        print(f"SCORE: {score}")
        print(f"STATUS: [cached ≤{_cache_ttl_s()}s] {description}")
        print("-" * 40)
        print("=" * 60)
        return

    print("DNSBL queries (IPv4 reverse, confirmed listings):")
    results = _query_all_dnsbls(ip)
    for r in results:
        if r.status == "clean":
            print(f"  {r.label}: clean")
        elif r.status == "listed":
            shown = ",".join(r.codes) if r.codes else r.detail
            print(f"  {r.label}: LISTED -> {shown}")
        else:
            print(f"  {r.label}: error -> {r.detail}")

    score, description = _score_from_results(ip, results, ip_note=note)
    _write_cache(ip, score, description, results)

    print("\n" + "-" * 40)
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print("-" * 40)
    print("=" * 60)


if __name__ == "__main__":
    main()
