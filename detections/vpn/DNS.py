#!/usr/bin/env python3
"""DNS leak probe via bash.ws (IPv4/IPv6 resolver visibility).

Purpose: Detect whether DNS appears to exit through non-VPN / non-provider paths when VPN claims
to tunnel traffic, and print the resolver data that was collected.

Score (1-5), aligned with Overdrive: 1 = no leak pattern observed (best case). 5 = strong
leak signal (IPv4 and/or IPv6 resolvers look non-VPN). Middle scores = mixed or partial exposure.

Environment: Any OS with Python requests and outbound HTTPS; uses third-party bash.ws. Rate
limits or blocking yield inconclusive errors.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import sys
import uuid
from pathlib import Path
from typing import Any

import requests

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_dns import classify_resolver, resolv_nameservers

API_DOMAIN = "bash.ws"
TRIGGER_COUNT = 10
REQUEST_TIMEOUT = 4
RESULT_TIMEOUT = 12


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.split("%", 1)[0]).version == 6
    except ValueError:
        return ":" in value


def _ip_scope(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_link_local:
        return "link-local"
    if addr.is_reserved:
        return "reserved"
    if addr.is_multicast:
        return "multicast"
    return "public"


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip.split("%", 1)[0])[0]
    except (OSError, socket.herror, socket.gaierror):
        return None


def _compact(value: Any, limit: int = 120) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True, default=str)
    else:
        text = str(value)
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 1] + "..."
    return text


def _pick(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def normalize_bashws_rows(payload: Any) -> tuple[list[dict[str, Any]], str | None]:
    """Return resolver rows from bash.ws JSON, tolerating a few response shapes."""
    if isinstance(payload, list):
        rows = [row for row in payload if isinstance(row, dict)]
        return rows, None
    if isinstance(payload, dict):
        for key in ("servers", "dns_servers", "dns", "results", "result"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)], None
        if any(key in payload for key in ("ip", "type", "country", "asn", "provider", "org", "isp")):
            return [payload], None
        message = _pick(payload, "error", "message", "status")
        return [], message or "JSON object did not contain resolver rows"
    return [], f"Unexpected JSON type: {type(payload).__name__}"


def row_ip(row: dict[str, Any]) -> str:
    return _pick(row, "ip", "address", "resolver", "dns_ip", "server_ip")


def row_type(row: dict[str, Any]) -> str:
    return _pick(row, "type", "status", "leak", "privacy")


def row_is_vpn(row: dict[str, Any]) -> bool:
    value = row.get("type")
    if isinstance(value, str) and value.lower() == "vpn":
        return True
    for key in ("vpn", "is_vpn", "mullvad_dns", "protected"):
        value = row.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in ("true", "yes", "1", "vpn"):
            return True
    return False


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    unique_by_ip: dict[str, dict[str, Any]] = {}
    unknown_rows: list[dict[str, Any]] = []
    for row in rows:
        ip = row_ip(row)
        if ip:
            unique_by_ip.setdefault(ip, row)
        else:
            unknown_rows.append(row)

    unique_rows = list(unique_by_ip.values()) + unknown_rows
    non_vpn_rows = [row for row in unique_rows if not row_is_vpn(row)]
    vpn_rows = [row for row in unique_rows if row_is_vpn(row)]
    non_vpn_ipv4 = [
        row for row in non_vpn_rows if row_ip(row) and not _is_ipv6(row_ip(row))
    ]
    non_vpn_ipv6 = [
        row for row in non_vpn_rows if row_ip(row) and _is_ipv6(row_ip(row))
    ]

    return {
        "unique_rows": unique_rows,
        "vpn_rows": vpn_rows,
        "non_vpn_rows": non_vpn_rows,
        "total_servers": len(unique_rows),
        "vpn_servers": len(vpn_rows),
        "non_vpn_servers": len(non_vpn_rows),
        "has_ipv4_leak": bool(non_vpn_ipv4),
        "has_ipv6_leak": bool(non_vpn_ipv6),
        "non_vpn_ipv4_count": len(non_vpn_ipv4),
        "non_vpn_ipv6_count": len(non_vpn_ipv6),
    }


def score_dns_leak(summary: dict[str, Any]) -> tuple[int, str]:
    has_ipv4_leak = bool(summary["has_ipv4_leak"])
    has_ipv6_leak = bool(summary["has_ipv6_leak"])
    non_vpn_servers = int(summary["non_vpn_servers"])
    total_servers = int(summary["total_servers"])

    if total_servers == 0:
        return 3, "Inconclusive: bash.ws returned no DNS resolver rows."
    if has_ipv4_leak and has_ipv6_leak:
        return 5, "Certain leak of IPv4 AND IPv6."
    if has_ipv4_leak and not has_ipv6_leak:
        return 5, "Certain leak of IPv4."
    if has_ipv6_leak and not has_ipv4_leak:
        return 5, "Certain leak of IPv6."
    if non_vpn_servers > 0 and non_vpn_servers == total_servers:
        return 5, "Certain leak: all observed DNS resolvers are non-VPN."
    if non_vpn_servers > (total_servers / 2):
        return 4, "Probable leak: majority of observed resolvers are non-VPN."
    if non_vpn_servers > 0:
        return 3, "Possible leak: mixed VPN and non-VPN resolver results."
    return 1, "Connection secure by bash.ws signal: no non-VPN resolvers reported."


def print_local_dns_context() -> None:
    nameservers = resolv_nameservers()
    print("\nLocal configured DNS from /etc/resolv.conf:")
    if not nameservers:
        print("  (none found)")
        return
    for idx, ns in enumerate(nameservers, start=1):
        print(f"  [{idx}] {ns} - {classify_resolver(ns)}")


def print_bashws_rows(rows: list[dict[str, Any]]) -> None:
    print("\nbash.ws observed DNS resolvers:")
    if not rows:
        print("  (no resolver rows returned)")
        return

    for idx, row in enumerate(rows, start=1):
        ip = row_ip(row) or "(no ip field)"
        typ = row_type(row) or ("vpn" if row_is_vpn(row) else "non-vpn/unknown")
        family = "IPv6" if ip != "(no ip field)" and _is_ipv6(ip) else "IPv4"
        scope = _ip_scope(ip) if ip != "(no ip field)" else "unknown"
        ptr = _reverse_dns(ip) if ip != "(no ip field)" and scope == "public" else None
        provider = _pick(
            row,
            "provider",
            "org",
            "organization",
            "isp",
            "asn_org",
            "company",
            "hostname",
            "host",
        )
        country = _pick(row, "country", "country_name", "countryCode", "country_code")
        city = _pick(row, "city", "region", "region_name")
        leak_state = "VPN/protected" if row_is_vpn(row) else "NON-VPN/LEAK"
        print(f"  [{idx}] {ip}  {family}  {leak_state}  type={typ or '-'}  scope={scope}")
        if provider or country or city or ptr:
            bits = []
            if provider:
                bits.append(f"provider={provider}")
            if ptr:
                bits.append(f"ptr={ptr}")
            if country:
                bits.append(f"country={country}")
            if city:
                bits.append(f"city/region={city}")
            print("      " + "  ".join(bits))
        extra_keys = [
            key
            for key in sorted(row.keys())
            if key
            not in {
                "ip",
                "address",
                "resolver",
                "dns_ip",
                "server_ip",
                "type",
                "status",
                "leak",
                "privacy",
                "vpn",
                "is_vpn",
                "mullvad_dns",
                "protected",
                "provider",
                "org",
                "organization",
                "isp",
                "asn_org",
                "company",
                "hostname",
                "host",
                "country",
                "country_name",
                "countryCode",
                "country_code",
                "city",
                "region",
                "region_name",
            }
        ]
        if extra_keys:
            rendered = ", ".join(f"{key}={_compact(row.get(key), 80)}" for key in extra_keys[:8])
            print(f"      extra: {rendered}")


def print_summary(summary: dict[str, Any]) -> None:
    print("\nDNS leak summary:")
    print(f"  Total unique resolver rows: {summary['total_servers']}")
    print(f"  VPN/protected rows:        {summary['vpn_servers']}")
    print(f"  Non-VPN rows:              {summary['non_vpn_servers']}")
    print(f"  Non-VPN IPv4 rows:         {summary['non_vpn_ipv4_count']}")
    print(f"  Non-VPN IPv6 rows:         {summary['non_vpn_ipv6_count']}")


def trigger_dns_queries(session: requests.Session, session_id: str) -> None:
    for i in range(1, TRIGGER_COUNT + 1):
        try:
            session.get(f"http://{i}.{session_id}.{API_DOMAIN}", timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            pass


def fetch_bashws_results(session: requests.Session, session_id: str) -> tuple[list[dict[str, Any]], str | None, Any]:
    response = session.get(
        f"https://{API_DOMAIN}/dnsleak/test/{session_id}?json",
        timeout=RESULT_TIMEOUT,
        headers={"Accept": "application/json", "User-Agent": "overdrive-dns-leak/1.0"},
    )
    response.raise_for_status()
    try:
        payload = response.json()
    except ValueError:
        return [], "bash.ws response was not valid JSON", response.text[:2000]
    rows, shape_error = normalize_bashws_rows(payload)
    return rows, shape_error, payload


def run_dns_leak_test() -> int:
    session_id = str(uuid.uuid4().hex)[:10]
    print(f"--- Running DNS Leak Test: Session {session_id} ---")
    print(f"Provider: https://{API_DOMAIN}/dnsleak/test/{session_id}?json")
    print(f"Trigger queries: {TRIGGER_COUNT} unique subdomains under {API_DOMAIN}")

    print_local_dns_context()

    session = requests.Session()
    trigger_dns_queries(session, session_id)

    rows: list[dict[str, Any]] = []
    shape_error: str | None = None
    raw_payload: Any = None
    fetch_error: str | None = None
    try:
        rows, shape_error, raw_payload = fetch_bashws_results(session, session_id)
    except requests.RequestException as exc:
        fetch_error = f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        fetch_error = f"{type(exc).__name__}: {exc}"

    print("-" * 40)
    if fetch_error:
        print(f"bash.ws result fetch failed: {fetch_error}")
        print("SCORE: 3")
        print(f"STATUS: Inconclusive - could not complete bash.ws analysis ({fetch_error}).")
        print("-" * 40)
        return 0

    if shape_error:
        print(f"bash.ws response note: {shape_error}")
        if raw_payload is not None:
            print(f"Raw response sample: {_compact(raw_payload, 800)}")

    summary = summarize_rows(rows)
    print_bashws_rows(summary["unique_rows"])
    print_summary(summary)

    score, message = score_dns_leak(summary)
    print("-" * 40)
    print(f"SCORE: {score}")
    print(f"STATUS: {message}")
    print("-" * 40)
    return 0


def main() -> int:
    return run_dns_leak_test()


if __name__ == "__main__":
    sys.exit(main())
