"""Shared helpers for ``detections/network/*.py`` scripts (public IPv4, DNSBL helpers)."""

from __future__ import annotations

import ipaddress
import json
import os

from detections.common.common_config import IPIFY_URL

__all__ = [
    "IPIFY_URL",
    "IPV4_ICANHAZIP_URL",
    "IPV4_IFCONFIGME_URL",
    "parse_ipv4",
    "fetch_public_ipv4_ipify",
    "fetch_plain_ipv4",
    "resolve_egress_ipv4",
    "reverse_ipv4_for_dnsbl",
    "ipv4_listed_in_netset",
]


IPV4_ICANHAZIP_URL = "https://ipv4.icanhazip.com/"
IPV4_IFCONFIGME_URL = "https://ifconfig.me/ip"


def parse_ipv4(s: str | None) -> str | None:
    """Normalize a string to dotted IPv4, or None if invalid / not IPv4."""
    if not s:
        return None
    s = s.strip().split()[0]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.version != 4:
        return None
    return str(a)


def fetch_public_ipv4_ipify(
    *,
    user_agent: str,
    timeout: float,
    session: "requests.Session | None" = None,
) -> str | None:
    """
    GET ``IPIFY_URL`` JSON and return normalized IPv4 from the ``ip`` field.
    """
    import requests

    getter = session.get if session is not None else requests.get
    headers = {"User-Agent": user_agent}
    try:
        r = getter(IPIFY_URL, headers=headers, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return parse_ipv4(str(data.get("ip")) if data.get("ip") else None)
    except (requests.RequestException, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def fetch_plain_ipv4(
    url: str,
    *,
    user_agent: str,
    timeout: float,
    session: "requests.Session | None" = None,
) -> str | None:
    """GET a plaintext endpoint and return a normalized IPv4 from the response body."""
    import requests

    getter = session.get if session is not None else requests.get
    try:
        r = getter(url, headers={"User-Agent": user_agent}, timeout=timeout)
        r.raise_for_status()
        return parse_ipv4(r.text)
    except (requests.RequestException, ValueError, TypeError):
        return None


def resolve_egress_ipv4(
    *,
    user_agent: str,
    timeout: float,
    override_env: str = "OVERDRIVE_IP",
    session: "requests.Session | None" = None,
) -> tuple[str | None, bool, str]:
    """
    Resolve public IPv4 from multiple providers.

    Returns ``(ip, strong_consensus, note)``. Consensus is strong when an
    override is supplied or at least two probes return the same IPv4.
    """
    override = parse_ipv4(os.environ.get(override_env))
    if override:
        return override, True, ""

    probes: list[tuple[str, str | None]] = [
        (
            "ipify",
            fetch_public_ipv4_ipify(
                user_agent=user_agent,
                timeout=timeout,
                session=session,
            ),
        ),
        (
            "icanhazip",
            fetch_plain_ipv4(
                IPV4_ICANHAZIP_URL,
                user_agent=user_agent,
                timeout=timeout,
                session=session,
            ),
        ),
        (
            "ifconfig.me",
            fetch_plain_ipv4(
                IPV4_IFCONFIGME_URL,
                user_agent=user_agent,
                timeout=timeout,
                session=session,
            ),
        ),
    ]
    successes = [(name, ip) for name, ip in probes if ip]
    if not successes:
        return None, False, "all IPv4 probes failed"

    by_ip: dict[str, list[str]] = {}
    for name, ip in successes:
        by_ip.setdefault(ip, []).append(name)

    if len(by_ip) > 1:
        parts = [f"{ip} ({', '.join(names)})" for ip, names in sorted(by_ip.items())]
        return None, False, "IPv4 probes disagree: " + "; ".join(parts)

    ip = next(iter(by_ip))
    if len(successes) >= 2:
        return ip, True, ""

    lone = successes[0][0]
    return ip, False, f"only one IPv4 probe succeeded ({lone}); need 2+ agreeing for strong consensus"


def reverse_ipv4_for_dnsbl(ip: str) -> str | None:
    """Reverse dotted IPv4 octets for DNSBL queries (``1.2.3.4`` → ``4.3.2.1``)."""
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


def ipv4_listed_in_netset(ip: str, body: str) -> bool:
    """True if ``ip`` matches a line in a netset/ipset (IPv4 CIDR or single address)."""
    addr = ipaddress.ip_address(ip)
    for line in body.splitlines():
        raw = line.split("#", 1)[0].strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                if addr in ipaddress.ip_network(raw, strict=False):
                    return True
            elif addr == ipaddress.ip_address(raw):
                return True
        except ValueError:
            continue
    return False
