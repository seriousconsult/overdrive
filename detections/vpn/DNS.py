#!/usr/bin/env python3
"""DNS resolver authenticity probe via bash.ws + local resolv.conf.

Collects which resolvers answer DNS for this host (bash.ws) and classifies them
for residential vs VPN/privacy/datacenter-like DNS.

Score (1-5), higher = less like a typical home PC/network DNS path:
  1 — LAN/router or residential-ISP-like resolvers dominate
  2 — Common public resolvers (Google/Cloudflare/…) or mild mix
  3 — Inconclusive / mixed / no rows
  4 — Privacy-VPN DNS (e.g. Mullvad) or mostly non-home resolvers
  5 — Strong VPN/anonymizer or hosting/datacenter DNS footprint

Note: this is NOT “VPN leak = bad”. Plain ISP/LAN DNS is the home-like outcome.
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

from detections.common.common_dns import (
    KNOWN_PUBLIC_DNS,
    classify_resolver,
    is_mullvad_dot_ip,
    mullvad_dot_whoami_pop,
    resolv_nameservers,
    reverse_dns,
)

API_DOMAIN = "bash.ws"
TRIGGER_COUNT = 10
REQUEST_TIMEOUT = 4
RESULT_TIMEOUT = 12

_PUBLIC_RESOLVER_IPS = frozenset(KNOWN_PUBLIC_DNS.keys()) if KNOWN_PUBLIC_DNS else frozenset()
_VPN_DNS_HINTS = (
    "mullvad",
    "nordvpn",
    "expressvpn",
    "proton",
    "windscribe",
    "ivpn",
    "pia.",
    "privateinternetaccess",
)
_HOSTING_DNS_HINTS = (
    "amazon",
    "aws",
    "googleusercontent",
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "ovh",
    "cloudflare-dns",  # anycast public is handled separately
)

_KNOWN_MULLVAD_DNS_POP_IPS = frozenset(
    {
        # Mullvad public encrypted DNS anycast PoPs commonly observed by leak tests.
        "193.148.18.30",
        "2a0d:5600:24:1382::2",
    }
)


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address((value or "").split("%", 1)[0])
    except ValueError:
        return None


def _ip_scope(value: str) -> str:
    addr = _parse_ip(value)
    if addr is None:
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


def row_is_dns_resolver(row: dict[str, Any]) -> bool:
    """True for bash.ws rows that describe DNS resolvers, not client IP/conclusion rows."""
    typ = row_type(row).strip().lower()
    if typ in {"ip", "conclusion"}:
        return False
    if typ:
        return "dns" in typ or typ == "vpn"
    return bool(row_ip(row))


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


def _row_text(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True, default=str).lower()


def row_is_protected(
    row: dict[str, Any],
    *,
    mullvad_pop_reference: str | None = None,
) -> bool:
    """True when bash.ws or local heuristics identify a protected/Mullvad row."""
    if row_is_vpn(row):
        return True
    ip = row_ip(row)
    if not ip:
        return False
    bucket = _classify_resolver_bucket(
        ip,
        bashws_vpn=False,
        mullvad_pop_reference=mullvad_pop_reference,
        row=row,
    )
    return bucket == "vpn"


def summarize_rows(
    rows: list[dict[str, Any]],
    *,
    mullvad_pop_reference: str | None = None,
) -> dict[str, Any]:
    unique_by_ip: dict[str, dict[str, Any]] = {}
    unknown_rows: list[dict[str, Any]] = []
    metadata_rows: list[dict[str, Any]] = []
    for row in rows:
        if not row_is_dns_resolver(row):
            metadata_rows.append(row)
            continue
        ip = row_ip(row)
        if ip and _parse_ip(ip) is not None:
            unique_by_ip.setdefault(ip, row)
        else:
            unknown_rows.append(row)

    unique_rows = list(unique_by_ip.values()) + unknown_rows
    non_vpn_rows = [
        row for row in unique_rows
        if not row_is_protected(row, mullvad_pop_reference=mullvad_pop_reference)
    ]
    vpn_rows = [
        row for row in unique_rows
        if row_is_protected(row, mullvad_pop_reference=mullvad_pop_reference)
    ]
    non_vpn_ipv4 = [
        row for row in non_vpn_rows
        if row_ip(row)
        and (addr := _parse_ip(row_ip(row))) is not None
        and addr.version == 4
    ]
    non_vpn_ipv6 = [
        row for row in non_vpn_rows
        if row_ip(row)
        and (addr := _parse_ip(row_ip(row))) is not None
        and addr.version == 6
    ]

    return {
        "unique_rows": unique_rows,
        "vpn_rows": vpn_rows,
        "non_vpn_rows": non_vpn_rows,
        "total_servers": len(unique_rows),
        "vpn_servers": len(vpn_rows),
        "non_vpn_servers": len(non_vpn_rows),
        "metadata_rows": metadata_rows,
        "metadata_row_count": len(metadata_rows),
        "has_ipv4_leak": bool(non_vpn_ipv4),
        "has_ipv6_leak": bool(non_vpn_ipv6),
        "non_vpn_ipv4_count": len(non_vpn_ipv4),
        "non_vpn_ipv6_count": len(non_vpn_ipv6),
        "mullvad_pop_reference": mullvad_pop_reference,
    }


def _classify_resolver_bucket(
    ip: str,
    *,
    bashws_vpn: bool = False,
    mullvad_pop_reference: str | None = None,
    row: dict[str, Any] | None = None,
) -> str:
    """Return one of: lan, public, vpn, hosting, isp_public, unknown."""
    if bashws_vpn:
        return "vpn"
    base = (ip or "").split("%", 1)[0].strip()
    if not base:
        return "unknown"
    addr = _parse_ip(base)
    if addr is None:
        return "unknown"
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return "lan"
    if is_mullvad_dot_ip(base):
        return "vpn"
    if base in _KNOWN_MULLVAD_DNS_POP_IPS:
        return "vpn"
    if mullvad_pop_reference and base == mullvad_pop_reference:
        return "vpn"
    if row is not None and "mullvad" in _row_text(row):
        return "vpn"
    if base in _PUBLIC_RESOLVER_IPS or base in {
        "1.1.1.1",
        "1.0.0.1",
        "8.8.8.8",
        "8.8.4.4",
        "9.9.9.9",
        "208.67.222.222",
        "208.67.220.220",
    }:
        return "public"
    ptr = (reverse_dns(base) or "").lower()
    if any(h in ptr for h in _VPN_DNS_HINTS):
        return "vpn"
    if any(h in ptr for h in _HOSTING_DNS_HINTS) and "fios" not in ptr and "verizon" not in ptr:
        return "hosting"
    if any(
        tok in ptr
        for tok in ("fios", "verizon", "comcast", "xfinity", "rr.com", "cox.net", "charter")
    ):
        return "isp_public"
    if "pool" in ptr or "dsl" in ptr or "cable" in ptr or "dynamic" in ptr:
        return "isp_public"
    return "unknown"


def score_dns_authenticity(
    summary: dict[str, Any],
    *,
    mullvad_pop_reference: str | None = None,
) -> tuple[int, str]:
    """Score whether DNS paths look like a normal home setup (low) vs VPN/DC (high)."""
    rows = list(summary.get("unique_rows") or [])
    mullvad_pop_reference = mullvad_pop_reference or summary.get("mullvad_pop_reference")
    local = resolv_nameservers()
    local_buckets: list[str] = []
    row_buckets: list[str] = []
    for ns in local:
        local_buckets.append(
            _classify_resolver_bucket(
                ns,
                mullvad_pop_reference=mullvad_pop_reference,
            )
        )
    for row in rows:
        ip = row_ip(row)
        if not ip:
            continue
        row_buckets.append(
            _classify_resolver_bucket(
                ip,
                bashws_vpn=row_is_vpn(row),
                mullvad_pop_reference=mullvad_pop_reference,
                row=row,
            )
        )

    buckets = local_buckets + row_buckets
    if not buckets and int(summary.get("total_servers") or 0) == 0:
        return 3, "Inconclusive: no local nameservers and bash.ws returned no resolver rows."
    if not buckets:
        return 3, "Inconclusive: could not classify any DNS resolvers."

    counts = {k: buckets.count(k) for k in ("lan", "isp_public", "public", "vpn", "hosting", "unknown")}
    row_counts = {k: row_buckets.count(k) for k in counts}

    if counts["vpn"] or counts["hosting"]:
        row_non_vpn = (
            row_counts["isp_public"]
            + row_counts["public"]
            + row_counts["hosting"]
            + row_counts["unknown"]
        )
        if row_counts["vpn"] and not row_non_vpn:
            if counts["lan"]:
                return (
                    4,
                    "Privacy-VPN DNS resolvers observed behind a local LAN forwarder; "
                    "expected for router-to-Mullvad DNS.",
                )
            return (
                4,
                f"Privacy-VPN DNS resolvers observed ({counts['vpn']}); "
                "uncommon for a vanilla home PC.",
            )
        if row_counts["vpn"] and row_non_vpn:
            return (
                4,
                f"Mixed Mullvad/VPN DNS and non-Mullvad DNS resolver rows observed "
                f"(vpn={row_counts['vpn']}, other={row_non_vpn}); possible DNS leak.",
            )
        if counts["vpn"] and counts["hosting"]:
            return (
                5,
                f"DNS uses VPN and hosting/datacenter resolvers "
                f"(vpn={counts['vpn']}, hosting={counts['hosting']}).",
            )
        if counts["vpn"]:
            return (
                4,
                f"Privacy-VPN DNS resolvers observed ({counts['vpn']}); "
                "uncommon for a vanilla home PC.",
            )
        return 5, f"Hosting/datacenter DNS resolvers observed ({counts['hosting']})."

    homeish = counts["lan"] + counts["isp_public"]
    if homeish and not counts["public"]:
        where = "LAN/router" if counts["lan"] else "residential-ISP"
        return 1, f"DNS looks home-like ({where} resolvers dominate; n={homeish})."
    if homeish and counts["public"]:
        return (
            2,
            f"Mostly home-like DNS with some public resolvers "
            f"(homeish={homeish}, public={counts['public']}).",
        )
    if counts["public"] and not homeish:
        return 2, f"Only well-known public resolvers observed (n={counts['public']}); common at home."
    if counts["unknown"]:
        return (
            2,
            f"Public resolvers without strong VPN/hosting fingerprints (n={counts['unknown']}); "
            "consistent with ISP DNS.",
        )
    return 3, "DNS resolver mix inconclusive for residential vs non-home classification."


def score_dns_leak(
    summary: dict[str, Any],
    *,
    mullvad_pop_reference: str | None = None,
) -> tuple[int, str]:
    """Backward-compatible name — residential authenticity scoring."""
    return score_dns_authenticity(summary, mullvad_pop_reference=mullvad_pop_reference)


def print_local_dns_context() -> None:
    nameservers = resolv_nameservers()
    print("\nLocal configured DNS from /etc/resolv.conf:")
    if not nameservers:
        print("  (none found)")
        return
    for idx, ns in enumerate(nameservers, start=1):
        print(f"  [{idx}] {ns} - {classify_resolver(ns)}")


def _row_bucket_label(
    row: dict[str, Any],
    *,
    mullvad_pop_reference: str | None = None,
) -> str:
    ip = row_ip(row)
    bucket = _classify_resolver_bucket(
        ip,
        bashws_vpn=row_is_vpn(row),
        mullvad_pop_reference=mullvad_pop_reference,
        row=row,
    )
    if bucket == "vpn":
        base = ip.split("%", 1)[0]
        if is_mullvad_dot_ip(base):
            return "Mullvad anycast/protected"
        if mullvad_pop_reference and base == mullvad_pop_reference:
            return "Mullvad DoT PoP/protected"
        return "VPN/protected"
    if bucket == "isp_public":
        return "ISP/public leak"
    if bucket == "lan":
        return "LAN/local"
    if bucket == "public":
        return "public DNS"
    if bucket == "hosting":
        return "hosting/datacenter"
    return "unknown"


def print_bashws_dns_rows(
    rows: list[dict[str, Any]],
    *,
    mullvad_pop_reference: str | None = None,
) -> None:
    print("\nbash.ws DNS resolver rows (COUNTED for DNS leak verdict):")
    if not rows:
        print("  (no resolver rows returned)")
        return

    for idx, row in enumerate(rows, start=1):
        ip = row_ip(row) or "(no ip field)"
        typ = row_type(row) or ("vpn" if row_is_vpn(row) else "non-vpn/unknown")
        addr = _parse_ip(ip) if ip != "(no ip field)" else None
        family = f"IPv{addr.version}" if addr is not None else "unknown-family"
        scope = _ip_scope(ip) if ip != "(no ip field)" else "unknown"
        ptr = _reverse_dns(ip) if addr is not None and scope == "public" else None
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
        leak_state = (
            "VPN/protected"
            if row_is_protected(row, mullvad_pop_reference=mullvad_pop_reference)
            else "NON-VPN/LEAK"
        )
        label = _row_bucket_label(row, mullvad_pop_reference=mullvad_pop_reference)
        print(
            f"  [{idx}] {ip}  {family}  {leak_state}  "
            f"type={typ or '-'}  scope={scope}  class={label}"
        )
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


def print_bashws_metadata_rows(rows: list[dict[str, Any]]) -> None:
    print("\nbash.ws non-DNS metadata rows (NOT counted as DNS leaks):")
    if not rows:
        print("  (none)")
        return

    for idx, row in enumerate(rows, start=1):
        ip = row_ip(row) or "(no ip field)"
        typ = row_type(row) or "unknown"
        scope = _ip_scope(ip) if _parse_ip(ip) is not None else "unknown"
        ptr = _reverse_dns(ip) if _parse_ip(ip) is not None and scope == "public" else None
        note = "metadata row"
        if typ.strip().lower() == "ip":
            note = (
                "your public web/HTTP egress IP, not a DNS resolver. "
                "With Mullvad DNS-only this may still be your ISP."
            )
        elif typ.strip().lower() == "conclusion":
            note = "bash.ws conclusion text, not a resolver."
        print(f"  [{idx}] {ip}  type={typ}  scope={scope}")
        print(f"      note: {note}")
        if ptr:
            print(f"      ptr={ptr}")


def print_summary(summary: dict[str, Any]) -> None:
    print("\nDNS leak summary:")
    print(f"  Total unique resolver rows: {summary['total_servers']}")
    if summary.get("metadata_row_count"):
        print(
            "  Ignored non-resolver rows:  "
            f"{summary['metadata_row_count']} (client IP/conclusion metadata)"
        )
    print(f"  VPN/protected rows:        {summary['vpn_servers']}")
    print(f"  Non-VPN rows:              {summary['non_vpn_servers']}")
    print(f"  Non-VPN IPv4 rows:         {summary['non_vpn_ipv4_count']}")
    print(f"  Non-VPN IPv6 rows:         {summary['non_vpn_ipv6_count']}")


def print_plain_english_verdict(summary: dict[str, Any]) -> None:
    total = int(summary.get("total_servers") or 0)
    protected = int(summary.get("vpn_servers") or 0)
    non_vpn = int(summary.get("non_vpn_servers") or 0)
    metadata_count = int(summary.get("metadata_row_count") or 0)

    print("\nPlain-English DNS result:")
    if total == 0:
        print("  RESULT: INCONCLUSIVE - bash.ws did not return DNS resolver rows.")
    elif protected and not non_vpn:
        print("  RESULT: OK - DNS resolver rows are Mullvad/protected.")
        print(
            "  Meaning: client -> local router DNS is fine; router -> upstream DNS "
            "appears to be Mullvad."
        )
    elif protected and non_vpn:
        print("  RESULT: POSSIBLE DNS LEAK - both Mullvad and non-Mullvad DNS resolvers appeared.")
        print("  Meaning: some DNS queries may be bypassing the Mullvad path.")
    else:
        print("  RESULT: NOT MULLVAD - DNS resolver rows are not identified as Mullvad/protected.")

    if metadata_count:
        print(
            "  Note: ignored metadata rows can include your public web IP. "
            "That is not a DNS resolver and is normal when using DNS-only instead of a VPN tunnel."
        )


def print_manual_verification_hints() -> None:
    print("\nManual verification:")
    print("  dig +short whoami.akamai.net")
    print("  dig +short @192.168.50.1 whoami.akamai.net")
    print(
        "  Expected in this lab: both commands return the same Mullvad DNS PoP "
        "(for example 193.148.18.30), not a Verizon/FiOS resolver."
    )


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
    mullvad_pop_reference, mullvad_pop_detail = mullvad_dot_whoami_pop(timeout=3.0)
    if mullvad_pop_reference:
        print(
            "\nMullvad DoT reference:"
            f" whoami.akamai.net via 194.242.2.2 -> {mullvad_pop_reference}"
            f" ({mullvad_pop_detail})"
        )
    else:
        print(f"\nMullvad DoT reference unavailable: {mullvad_pop_detail}")

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

    summary = summarize_rows(rows, mullvad_pop_reference=mullvad_pop_reference)
    print_bashws_dns_rows(summary["unique_rows"], mullvad_pop_reference=mullvad_pop_reference)
    print_bashws_metadata_rows(summary["metadata_rows"])
    print_summary(summary)
    print_plain_english_verdict(summary)
    print_manual_verification_hints()

    score, message = score_dns_leak(summary, mullvad_pop_reference=mullvad_pop_reference)
    print("-" * 40)
    print(
        "Detection heuristic score: higher means less like plain home/ISP DNS; "
        "Mullvad DNS-only is expected to score higher and is not a leak by itself."
    )
    print(f"SCORE: {score}")
    print(f"STATUS: {message}")
    print("-" * 40)
    return 0


def main() -> int:
    return run_dns_leak_test()


if __name__ == "__main__":
    sys.exit(main())
