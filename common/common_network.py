"""Shared helpers for ``network/*.py`` scripts (public IPv4, DNSBL helpers)."""

from __future__ import annotations

import ipaddress
import json

__all__ = [
    "IPIFY_URL",
    "parse_ipv4",
    "fetch_public_ipv4_ipify",
    "reverse_ipv4_for_dnsbl",
    "ipv4_listed_in_netset",
]


IPIFY_URL = "https://api.ipify.org?format=json"


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
