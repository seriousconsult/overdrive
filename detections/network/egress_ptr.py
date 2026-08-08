#!/usr/bin/env python3
"""Egress PTR / reverse-DNS classification for the public IPv4.

Looks up the PTR for the consensus egress address, forward-confirms it (FCrDNS),
and classifies the hostname as residential ISP pool vs cloud/VPS/hosting/VPN-ish.

Complements ASN org classification with a DNS-name signal.

Score (1–5), higher = more non-residential / suspicious egress naming:
  5 — FCrDNS-confirmed PTR strongly matches hosting/cloud/VPS (or VPN-ish) naming
  4 — Hosting-ish PTR without FCrDNS, or hosting flag + generic PTR
  3 — No public IPv4, PTR lookup failed, or name/class inconclusive
  2 — No PTR, or generic/unclassified PTR without hosting signals; weak IP consensus
  1 — Strong IP consensus + FCrDNS-confirmed residential/ISP-pool PTR

Environment:
  OVERDRIVE_IP                   — optional IPv4 override (strong consensus)
  OVERDRIVE_EGRESS_PTR_NO_CACHE  — set 1/true/yes to skip result cache
  OVERDRIVE_EGRESS_PTR_CACHE_TTL — result cache seconds (default 120)
"""

from __future__ import annotations

import json
import os
import re
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

from detections.common.common_config import (
    IP_API_URL_WITH_FIELDS,
    OVERDRIVE_CACHE_DIR,
    USER_AGENTS,
)
from detections.common.common_network import resolve_egress_ipv4

TIMEOUT = 8.0
UA = {"User-Agent": USER_AGENTS["egress_ptr"]}
_CACHE_NAME = "egress_ptr.json"
_DEFAULT_CACHE_TTL_S = 120
_DNS_ATTEMPTS = 3

# Hostname / zone tokens (matched against lowercased PTR)
RESIDENTIAL_TOKEN_RE = re.compile(
    r"(?:^|[.\-_])("
    r"pool|dhcp|dynamic|dyn|cable|dsl|adsl|vdsl|fiber|ftth|fios|res|residential|"
    r"cpe|customer|cust|home|hsd|broadband|bb|dialup|ppp|ip-\d"
    r")(?:[.\-_]|$)",
    re.IGNORECASE,
)

RESIDENTIAL_ZONE_RE = re.compile(
    r"(?:^|\.)("
    r"verizon\.net|myvzw\.com|fios\.verizon\.net|"
    r"comcast\.net|comcastbusiness\.net|"
    r"rr\.com|charter\.com|spectrum\.com|"
    r"cox\.net|sbcglobal\.net|att\.net|bellsouth\.net|"
    r"centurylink\.net|qwest\.net|frontiernet\.net|windstream\.net|"
    r"suddenlink\.net|rcn\.com|optimum\.net|optonline\.net|"
    r"t-?mobile\.com|sprint(pcs)?\.com|verizonwireless\.com|"
    r"shawcable\.net|rogers\.com|bell\.ca|"
    r"virginmedia\.com|sky\.com|btinternet\.com|plus\.net|"
    r"telstra\.net|optusnet\.com\.au|bigpond\.net\.au|"
    r"wanadoo\.fr|orange\.fr|free\.fr|sfr\.fr|"
    r"t-online\.de|vodafone\.de|telefonica\.[a-z.]+"
    r")(?:\.|$)",
    re.IGNORECASE,
)

HOSTING_TOKEN_RE = re.compile(
    r"(?:^|[.\-_])("
    r"amazonaws|aws|googleusercontent|cloudapp|azure|linode|akamai|"
    r"digitalocean|vultr|ovh|hetzner|contabo|colocrossing|leaseweb|"
    r"choopa|softlayer|ibmcloud|oraclecloud|aliyun|tencent|"
    r"compute|vps|dedicated|server|hosting|datacenter|data-center|"
    r"colocation|colo|cloud|ecs|ec2|gce|lightsail|droplet"
    r")(?:[.\-_]|$)",
    re.IGNORECASE,
)

HOSTING_ZONE_RE = re.compile(
    r"(?:^|\.)("
    r"amazonaws\.com|compute\.amazonaws\.com|"
    r"googleusercontent\.com|bc\.googleusercontent\.com|"
    r"cloudapp\.azure\.com|azure\.com|"
    r"linode\.com|linodeobjects\.com|"
    r"digitaloceanspaces\.com|digitalocean\.com|"
    r"vultr\.com|choose\.vultr\.com|"
    r"ovh\.net|ovhcloud\.com|hetzner\.com|hetzner\.de|"
    r"contabo\.net|contabo\.com|leaseweb\.net|"
    r"softlayer\.com|amazonaws\.com\.cn"
    r")(?:\.|$)",
    re.IGNORECASE,
)

VPN_TOKEN_RE = re.compile(
    r"(?:^|[.\-_])("
    r"mullvad|nordvpn|expressvpn|surfshark|cyberghost|protonvpn|proton\.me|"
    r"windscribe|ivpn|azire|airvpn|torguard|ipvanish|vyprvpn|purevpn|"
    r"hide\.me|pia\.|privateinternetaccess|tunnelbear|hotspotshield|"
    r"vpn|exit|anon|anonymizer"
    r")(?:[.\-_]|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PtrEvidence:
    ip: str
    ip_strong: bool
    ip_note: str
    ptr: str | None
    ptr_error: str | None
    forward_ips: tuple[str, ...]
    fcrdns: bool
    name_class: str  # residential | hosting | vpn | generic | none | error
    class_reason: str
    hosting_flag: bool | None
    org: str | None


def _cache_ttl_s() -> int:
    raw = (os.environ.get("OVERDRIVE_EGRESS_PTR_CACHE_TTL") or "").strip()
    if raw.isdigit():
        return max(0, int(raw))
    return _DEFAULT_CACHE_TTL_S


def _cache_disabled() -> bool:
    return (os.environ.get("OVERDRIVE_EGRESS_PTR_NO_CACHE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _read_cache(ip: str) -> tuple[int, str, dict[str, Any]] | None:
    if _cache_disabled() or _cache_ttl_s() <= 0:
        return None
    path = OVERDRIVE_CACHE_DIR / _CACHE_NAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("ip") != ip:
        return None
    try:
        ts = float(data["ts"])
        score = int(data["score"])
        description = str(data["description"])
    except (KeyError, TypeError, ValueError):
        return None
    if time.time() - ts > _cache_ttl_s():
        return None
    evidence = data.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    return score, description, evidence


def _write_cache(ip: str, score: int, description: str, evidence: PtrEvidence) -> None:
    if _cache_disabled() or _cache_ttl_s() <= 0:
        return
    path = OVERDRIVE_CACHE_DIR / _CACHE_NAME
    payload = {
        "ip": ip,
        "ts": time.time(),
        "score": score,
        "description": description,
        "evidence": {
            "ip": evidence.ip,
            "ip_strong": evidence.ip_strong,
            "ip_note": evidence.ip_note,
            "ptr": evidence.ptr,
            "ptr_error": evidence.ptr_error,
            "forward_ips": list(evidence.forward_ips),
            "fcrdns": evidence.fcrdns,
            "name_class": evidence.name_class,
            "class_reason": evidence.class_reason,
            "hosting_flag": evidence.hosting_flag,
            "org": evidence.org,
        },
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def _normalize_hostname(name: str | None) -> str | None:
    if not name:
        return None
    host = name.strip().rstrip(".").lower()
    if not host or host == "localhost":
        return None
    return host


def lookup_ptr(ip: str) -> tuple[str | None, str | None]:
    """Return ``(ptr_hostname, error)``. NXDOMAIN/no PTR → ``(None, None)``."""
    last_err: str | None = None
    for attempt in range(_DNS_ATTEMPTS):
        try:
            # Prefer getnameinfo (works well for IPv4 PTR).
            host, _ = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
            norm = _normalize_hostname(host)
            if norm and norm != ip:
                return norm, None
            # Some stacks echo the IP when no PTR exists.
            return None, None
        except socket.gaierror as e:
            # EAI_NONAME / EAI_NODATA ≈ no PTR
            errno = getattr(e, "errno", None)
            if errno in {
                getattr(socket, "EAI_NONAME", -2),
                getattr(socket, "EAI_NODATA", -5),
                getattr(socket, "EAI_AGAIN", -3),
            }:
                if errno == getattr(socket, "EAI_AGAIN", -3) and attempt + 1 < _DNS_ATTEMPTS:
                    last_err = str(e)
                    time.sleep(0.25 * (attempt + 1))
                    continue
                if errno == getattr(socket, "EAI_AGAIN", -3):
                    return None, str(e)
                return None, None
            last_err = str(e)
        except OSError as e:
            last_err = str(e)

        # Fallback: gethostbyaddr
        try:
            host, aliases, _ = socket.gethostbyaddr(ip)
            for candidate in (host, *(aliases or ())):
                norm = _normalize_hostname(candidate)
                if norm and norm != ip:
                    return norm, None
            return None, None
        except socket.herror:
            return None, None
        except OSError as e:
            last_err = str(e)
            time.sleep(0.25 * (attempt + 1))

    return None, last_err or "PTR lookup failed"


def forward_resolve_a(hostname: str) -> tuple[str, ...]:
    """Resolve A records for ``hostname`` (IPv4 only)."""
    addrs: list[str] = []
    for attempt in range(_DNS_ATTEMPTS):
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            for info in infos:
                sockaddr = info[4]
                if sockaddr and isinstance(sockaddr[0], str):
                    addrs.append(sockaddr[0])
            break
        except socket.gaierror:
            return ()
        except OSError:
            time.sleep(0.2 * (attempt + 1))
    return tuple(dict.fromkeys(addrs))


def classify_ptr_hostname(ptr: str) -> tuple[str, str]:
    """Return ``(class, reason)`` for a lowercased PTR hostname."""
    host = ptr.lower().rstrip(".")

    if VPN_TOKEN_RE.search(host):
        m = VPN_TOKEN_RE.search(host)
        return "vpn", f"VPN/anonymizer token matched: {m.group(1) if m else 'vpn'}"

    hosting_hits: list[str] = []
    m = HOSTING_ZONE_RE.search(host)
    if m:
        hosting_hits.append(f"zone={m.group(1)}")
    m = HOSTING_TOKEN_RE.search(host)
    if m:
        hosting_hits.append(f"token={m.group(1)}")
    if hosting_hits:
        return "hosting", "hosting/cloud naming: " + ", ".join(hosting_hits)

    residential_hits: list[str] = []
    m = RESIDENTIAL_ZONE_RE.search(host)
    if m:
        residential_hits.append(f"zone={m.group(1)}")
    m = RESIDENTIAL_TOKEN_RE.search(host)
    if m:
        residential_hits.append(f"token={m.group(1)}")
    # Many ISP pools encode the IP in the label (e.g. 18.108.88.138.isp.net)
    if re.search(r"(?:^|[.\-])\d{1,3}(?:[.\-]\d{1,3}){3}(?:[.\-]|$)", host):
        residential_hits.append("ip-in-label")
    if residential_hits:
        return "residential", "residential/ISP naming: " + ", ".join(residential_hits)

    return "generic", "PTR present but no strong residential/hosting tokens"


def ip_api_meta(ip: str) -> dict[str, Any]:
    try:
        r = requests.get(
            IP_API_URL_WITH_FIELDS.format(ip=ip),
            headers=UA,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, dict) else {}
    except (requests.RequestException, ValueError):
        return {}


def collect_ptr_evidence(ip: str, ip_strong: bool, ip_note: str) -> PtrEvidence:
    ptr, ptr_err = lookup_ptr(ip)
    forward_ips: tuple[str, ...] = ()
    fcrdns = False
    if ptr:
        forward_ips = forward_resolve_a(ptr)
        fcrdns = ip in forward_ips
        name_class, reason = classify_ptr_hostname(ptr)
    elif ptr_err:
        name_class, reason = "error", ptr_err
    else:
        name_class, reason = "none", "no PTR record"

    meta = ip_api_meta(ip)
    hosting_flag: bool | None = None
    org: str | None = None
    if meta.get("status") == "success":
        hosting_flag = meta.get("hosting") is True
        org_raw = meta.get("org") or meta.get("isp") or meta.get("as")
        org = str(org_raw) if org_raw else None

    return PtrEvidence(
        ip=ip,
        ip_strong=ip_strong,
        ip_note=ip_note,
        ptr=ptr,
        ptr_error=ptr_err,
        forward_ips=forward_ips,
        fcrdns=fcrdns,
        name_class=name_class,
        class_reason=reason,
        hosting_flag=hosting_flag,
        org=org,
    )


def score_ptr_evidence(ev: PtrEvidence) -> tuple[int, str]:
    if ev.name_class == "error":
        return 3, f"PTR lookup failed for {ev.ip}: {ev.ptr_error or ev.class_reason}"

    ptr_s = ev.ptr or "(none)"
    fcr = "FCrDNS=yes" if ev.fcrdns else "FCrDNS=no"
    org_s = f"; org={ev.org}" if ev.org else ""

    if ev.name_class == "vpn":
        if ev.fcrdns:
            return (
                5,
                f"Confirmed VPN/anonymizer-style PTR {ptr_s} ({ev.class_reason}; {fcr}){org_s}",
            )
        return (
            4,
            f"VPN/anonymizer-style PTR {ptr_s} without FCrDNS ({ev.class_reason}){org_s}",
        )

    if ev.name_class == "hosting":
        if ev.fcrdns:
            return (
                5,
                f"Confirmed hosting/cloud PTR {ptr_s} ({ev.class_reason}; {fcr}){org_s}",
            )
        return (
            4,
            f"Hosting/cloud-style PTR {ptr_s} without FCrDNS ({ev.class_reason}){org_s}",
        )

    if ev.name_class == "residential":
        if ev.ip_strong and ev.fcrdns:
            return (
                1,
                f"Confirmed residential/ISP PTR {ptr_s} ({ev.class_reason}; {fcr}){org_s}",
            )
        if ev.fcrdns:
            return (
                2,
                f"Residential/ISP PTR {ptr_s} confirmed but egress IP consensus was weak "
                f"({ev.ip_note or 'weak consensus'}; {fcr}){org_s}",
            )
        if ev.ip_strong:
            return (
                2,
                f"Residential/ISP-style PTR {ptr_s} without FCrDNS ({ev.class_reason}){org_s}",
            )
        return (
            3,
            f"Residential-looking PTR {ptr_s} but weak IP consensus and no FCrDNS "
            f"({ev.ip_note or 'weak consensus'}){org_s}",
        )

    # generic or none
    if ev.hosting_flag is True:
        return (
            4,
            f"PTR {ptr_s} is {ev.name_class}; ip-api hosting=true{org_s}",
        )

    if ev.name_class == "none":
        if not ev.ip_strong:
            return (
                2,
                f"No PTR for {ev.ip}; weak egress consensus "
                f"({ev.ip_note or 'weak consensus'}){org_s}",
            )
        # No PTR is common on some residential networks — not strong clean, not hosting.
        return (
            2,
            f"No PTR for {ev.ip}; cannot confirm residential naming from reverse DNS{org_s}",
        )

    # generic PTR
    if not ev.ip_strong:
        return (
            2,
            f"Generic PTR {ptr_s}; weak egress consensus "
            f"({ev.ip_note or 'weak consensus'}; {fcr}){org_s}",
        )
    if ev.fcrdns:
        return (
            3,
            f"Generic FCrDNS-confirmed PTR {ptr_s}; inconclusive residential vs hosting "
            f"({ev.class_reason}){org_s}",
        )
    return (
        3,
        f"Generic PTR {ptr_s} without FCrDNS; inconclusive ({ev.class_reason}){org_s}",
    )


def print_evidence(ev: PtrEvidence) -> None:
    print(f"Public IPv4:     {ev.ip}")
    print(f"IP consensus:    {'strong' if ev.ip_strong else 'weak'}"
          + (f" ({ev.ip_note})" if ev.ip_note else ""))
    print(f"PTR:             {ev.ptr or '(none)'}")
    if ev.ptr_error:
        print(f"PTR error:       {ev.ptr_error}")
    print(f"Forward A:       {', '.join(ev.forward_ips) if ev.forward_ips else '(none)'}")
    print(f"FCrDNS:          {'yes' if ev.fcrdns else 'no'}")
    print(f"Name class:      {ev.name_class}")
    print(f"Class reason:    {ev.class_reason}")
    if ev.hosting_flag is not None:
        print(f"ip-api hosting:  {ev.hosting_flag}")
    if ev.org:
        print(f"ip-api org:      {ev.org}")


def check_egress_ptr() -> tuple[int, str]:
    ip, ip_strong, ip_note = resolve_egress_ipv4(
        user_agent=UA["User-Agent"],
        timeout=TIMEOUT,
        override_env="OVERDRIVE_IP",
    )
    if not ip:
        return 3, f"Could not determine public IPv4. {ip_note}"

    cached = _read_cache(ip)
    if cached:
        score, description, _ = cached
        return score, f"[cached ≤{_cache_ttl_s()}s] {description}"

    evidence = collect_ptr_evidence(ip, ip_strong, ip_note)
    score, description = score_ptr_evidence(evidence)
    _write_cache(ip, score, description, evidence)
    return score, description


def main() -> int:
    print("=" * 60)
    print("Egress PTR / Reverse-DNS Check")
    print("=" * 60)
    print()

    ip, ip_strong, ip_note = resolve_egress_ipv4(
        user_agent=UA["User-Agent"],
        timeout=TIMEOUT,
        override_env="OVERDRIVE_IP",
    )
    if not ip:
        score, description = 3, f"Could not determine public IPv4. {ip_note}"
        print(f"SCORE: {score}")
        print(f"STATUS: {description}")
        print()
        print("=" * 60)
        return 0

    cached = _read_cache(ip)
    if cached:
        score, description, row = cached
        ev = PtrEvidence(
            ip=str(row.get("ip") or ip),
            ip_strong=bool(row.get("ip_strong")),
            ip_note=str(row.get("ip_note") or ""),
            ptr=row.get("ptr") if isinstance(row.get("ptr"), str) else None,
            ptr_error=row.get("ptr_error") if isinstance(row.get("ptr_error"), str) else None,
            forward_ips=tuple(row.get("forward_ips") or ()),
            fcrdns=bool(row.get("fcrdns")),
            name_class=str(row.get("name_class") or "generic"),
            class_reason=str(row.get("class_reason") or ""),
            hosting_flag=row.get("hosting_flag") if isinstance(row.get("hosting_flag"), bool) else None,
            org=row.get("org") if isinstance(row.get("org"), str) else None,
        )
        print_evidence(ev)
        print()
        print(f"(result cache hit, TTL {_cache_ttl_s()}s)")
        description = f"[cached ≤{_cache_ttl_s()}s] {description}"
    else:
        evidence = collect_ptr_evidence(ip, ip_strong, ip_note)
        print_evidence(evidence)
        print()
        score, description = score_ptr_evidence(evidence)
        _write_cache(ip, score, description, evidence)

    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print()
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
