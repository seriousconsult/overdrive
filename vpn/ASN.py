#!/usr/bin/env python3
"""
ASN / org classification for egress IP using **ipapi.co** and **ip-api.com**.

Score (1–5), higher = more suspicious / non-residential:
  5 — Strong VPN/proxy/datacenter signal
  4 — Probably non-residential / anonymization-adjacent
  3 — Mixed / unknown / providers disagree
  2 — Likely residential / mobile carrier
  1 — Strong residential ISP signal
"""

from __future__ import annotations

import re
import sys
from typing import Any

import requests

IPIFY = "https://api.ipify.org?format=json"
IP_API_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,query,isp,org,as,hosting,mobile,proxy"
)
IPAPI_URL_AUTO = "https://ipapi.co/json/"
IPAPI_URL_IP = "https://ipapi.co/{ip}/json/"
TIMEOUT = 15
UA = {"User-Agent": "overdrive-asn-lookup/1.0"}

# Patterns that indicate non-residential (datacenter/hosting/transit)
HOSTING_ORG_PATTERNS = [
    r"\bM247\b",
    r"\bDatacamp\b",
    r"\bHosting\b",
    r"\bTierPoint\b",
    r"\bEquinix\b",
    r"\bOVH\b",
    r"\bHetzner\b",
    r"\bDigitalOcean\b",
    r"\bAWS\b",
    r"\bAmazon\b",
    r"\bGoogle\b",
    r"\bCloudflare\b",
    r"\bAkamai\b",
    r"\bLinode\b",
    r"\bVultr\b",
    r"\bLeaseweb\b",
    r"\bMicrosoft\b",
    r"\bAzure\b",
    r"\bOracle\b",
    r"\bIBM\b",
    r"\bAlibaba\b",
    r"\bTencent\b",
    r"\bColocenter\b",
    r"\bServer\b",
    r"\bDataCenter\b",
    r"\bColocation\b",
    r"\bTransit\b",
    r"\bBackbone\b",
    r"\bIP\b.*Transit\b",
    r"\bVerizon\b.*Business\b",
    r"\bUUNET\b",
    r"\bMCI\b",
    r"\bSprint\b",
    r"\bAT&T\b",
    r"\bComcast\b.*Business\b",
    r"\bBusiness\b.*Cable\b",
]

# Commercial / privacy VPN and anonymization providers (non-residential egress)
VPN_ORG_PATTERNS = [
    r"\bMullvad\b",
    r"\bNordVPN\b",
    r"\bExpressVPN\b",
    r"\bSurfshark\b",
    r"\bCyberGhost\b",
    r"\bPrivate\s+Internet\s+Access\b",
    r"\bProton[_\s-]?VPN\b",
    r"\bProton\s+AG\b",
    r"\bWindscribe\b",
    r"\bIVPN\b",
    r"\bAzireVPN\b",
    r"\bAirVPN\b",
    r"\bPerfect\s+Privacy\b",
    r"\bTorGuard\b",
    r"\bIPVanish\b",
    r"\bVyprVPN\b",
    r"\bPureVPN\b",
    r"\bStrongVPN\b",
    r"\bHide\.?Me\b",
    r"\bOVPN\b",
    r"\bVPN\.ac\b",
    r"\bVPN\s+Secure\b",
    r"\bZenMate\b",
    r"\bHotspot\s+Shield\b",
    r"\bTunnelBear\b",
    r"\bNorton\s+Secure\s+VPN\b",
    r"\bKaspersky\s+VPN\b",
    r"\bBitdefender\s+VPN\b",
    r"\bOpenVPN\b",
    r"\bWireGuard\b.*Access",
    r"\bCorporate\s+VPN\b",
    r"\bEnterprise\s+VPN\b",
    r"\bVirtual\s+Private\s+Network\b",
    r"\bVPN\s+Service\b",
    r"\bVPN\s+Provider\b",
]

# Patterns that indicate residential ISPs
RESIDENTIAL_ISP_PATTERNS = [
    r"\bComcast\b",
    r"\bCharter\b",
    r"\bSpectrum\b",
    r"\bVerizon\b.*FiOS\b",
    r"\bVerizon\b.*Online\b",
    r"\bAT&T\b.*DSL\b",
    r"\bAT&T\b.*Fiber\b",
    r"\bCox\b",
    r"\bSuddenlink\b",
    r"\bRCN\b",
    r"\bFrontier\b",
    r"\bWindstream\b",
    r"\bCenturyLink\b",
    r"\bLumen\b",
    r"\bT-Mobile\b",
    r"\bVerizon\b.*Wireless\b",
    r"\bAT&T\b.*Wireless\b",
    r"\bSprint\b.*Wireless\b",
    r"\bCricket\b",
    r"\bConsumer\b",
    r"\bResidential\b",
    r"\bHome\b.*Internet\b",
    r"\bFTTH\b",
    r"\bFiber\b.*Network\b",
]


def vpn_name_match(text: str) -> bool:
    if not text or not text.strip():
        return False
    t = text.strip()
    return any(re.search(pat, t, flags=re.IGNORECASE) for pat in VPN_ORG_PATTERNS)


def classify_org(org: str) -> tuple[int, str]:
    """
    Returns a score 1-5 and description:
    5 = strong VPN/proxy/datacenter signal
    4 = likely non-residential
    3 = mixed/unknown
    2 = likely residential
    1 = strong residential
    """
    if not org:
        return 3, "unknown"

    org = org.strip()

    if vpn_name_match(org):
        return 5, "VPN / anonymization provider (org name)"

    residential_score = 0
    for pat in RESIDENTIAL_ISP_PATTERNS:
        if re.search(pat, org, flags=re.IGNORECASE):
            residential_score += 2

    hosting_score = 0
    for pat in HOSTING_ORG_PATTERNS:
        if re.search(pat, org, flags=re.IGNORECASE):
            hosting_score += 2

    if hosting_score >= 2 and residential_score == 0:
        return 5, "datacenter/hosting org pattern"
    if hosting_score >= 2 and residential_score >= 2:
        return 3, "mixed residential + hosting signals"
    if residential_score >= 4:
        return 1, "strong residential ISP signal"
    if residential_score >= 2:
        return 2, "likely residential ISP"
    if residential_score >= 1:
        return 3, "maybe residential"
    return 4, "probably non-residential"


def classify_ip_api(meta: dict[str, Any]) -> tuple[int | None, str]:
    """
    ip-api ``hosting`` flag plus ISP/org string heuristics (incl. VPN patterns).
    Returns (score, detail) or (None, error note).
    """
    if meta.get("status") != "success":
        msg = meta.get("message") or meta.get("reason") or "not success"
        return None, f"ip-api: {msg}"

    isp = str(meta.get("isp") or "").strip()
    org = str(meta.get("org") or "").strip()
    combined = f"{isp} {org}".strip()

    if meta.get("proxy") is True:
        return 5, "ip-api: proxy=true"

    if vpn_name_match(combined):
        return 5, "ip-api: VPN-like ISP/org name"

    if meta.get("hosting") is True:
        if _residential_strength(isp):
            return 4, "ip-api: hosting=true but ISP hints residential (mixed)"
        return 5, "ip-api: hosting=true (datacenter/colocation)"

    if meta.get("mobile") is True:
        return 2, "ip-api: mobile carrier (likely residential/mobile NAT)"

    if isp:
        score, status = classify_org(isp)
        if score != 3 or status != "unknown":
            return score, f"ip-api isp heuristic: {status}"

    if org and org != isp:
        score, status = classify_org(org)
        if score != 3 or status != "unknown":
            return score, f"ip-api org heuristic: {status}"

    return 3, "ip-api: hosting=false, no strong ISP/org match"


def _residential_strength(isp: str) -> bool:
    if not isp:
        return False
    return any(
        re.search(pat, isp, flags=re.IGNORECASE) for pat in RESIDENTIAL_ISP_PATTERNS
    )


def merge_asn_scores(
    s_ipapi: int,
    s_ip_api: int | None,
    msg_ipapi: str,
    msg_ip_api: str | None,
) -> tuple[int, str]:
    """Blend ipapi.co and ip-api scores; preserve high-confidence proxy/VPN evidence."""
    if s_ip_api is None:
        return s_ipapi, f"{msg_ipapi} (ip-api: {msg_ip_api or 'skipped'})"

    suspicious_terms = ("proxy", "vpn", "anonym", "hosting", "datacenter", "colocation")
    explicit_suspicious = any(
        term in (msg_ipapi or "").lower() for term in suspicious_terms
    ) or any(term in (msg_ip_api or "").lower() for term in suspicious_terms)

    # Never down-rank explicit high-confidence proxy/VPN evidence.
    if explicit_suspicious and max(s_ipapi, s_ip_api) >= 5:
        return (
            5,
            f"high-confidence suspicious egress: ipapi={s_ipapi} ({msg_ipapi}); "
            f"ip-api={s_ip_api} ({msg_ip_api})",
        )

    if explicit_suspicious and max(s_ipapi, s_ip_api) >= 4:
        return (
            4,
            f"suspicious egress: ipapi={s_ipapi} ({msg_ipapi}); "
            f"ip-api={s_ip_api} ({msg_ip_api})",
        )

    if s_ipapi == s_ip_api:
        return s_ipapi, f"consensus {s_ipapi}: ipapi «{msg_ipapi}» | ip-api «{msg_ip_api}»"

    diff = abs(s_ipapi - s_ip_api)
    if diff >= 2:
        return (
            3,
            f"providers disagree (ipapi={s_ipapi}: {msg_ipapi}; ip-api={s_ip_api}: {msg_ip_api})",
        )

    blended = max(1, min(5, round((s_ipapi + s_ip_api) / 2)))
    return (
        blended,
        f"blended {blended}: ipapi={s_ipapi} ({msg_ipapi}); ip-api={s_ip_api} ({msg_ip_api})",
    )


def _public_ip_ipify() -> str | None:
    try:
        r = requests.get(IPIFY, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        ip = r.json().get("ip")
        if not ip or ":" in str(ip):
            return None
        return str(ip).strip()
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return None


def fetch_ipapi(ip: str | None) -> dict[str, Any] | None:
    url = IPAPI_URL_IP.format(ip=ip) if ip else IPAPI_URL_AUTO
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        if r.status_code == 429:
            return {"error": True, "reason": "Rate limited (429)"}
        r.raise_for_status()
        return r.json()
    except requests.RequestException:
        return None
    except ValueError:
        return None


def fetch_ip_api(ip: str) -> dict[str, Any]:
    try:
        r = requests.get(IP_API_URL.format(ip=ip), headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError):
        return {"status": "fail", "message": "request error"}


def resolve_target_ip(arg_ip: str) -> tuple[str | None, str | None]:
    """Returns (ipv4, error). Uses argv IP if set; else ipapi auto; else ipify."""
    if arg_ip.strip():
        ip = arg_ip.strip()
        if ":" in ip:
            return None, "IPv6 not supported for this lookup; pass an IPv4 address"
        return ip, None

    data = fetch_ipapi(None)
    if data and not data.get("error"):
        pip = data.get("ip")
        if pip and ":" not in str(pip):
            return str(pip).strip(), None

    pip = _public_ip_ipify()
    if pip:
        return pip, None
    return None, "Could not determine public IPv4 (ipapi/ipify failed)"


def lookup_asn(ip_address: str = "") -> None:
    ip, err = resolve_target_ip(ip_address)
    if err or not ip:
        print("--- ASN Lookup Results ---")
        print(f"Error: {err or 'no IP'}")
        print("SCORE: 3")
        print("STATUS: Could not resolve egress IPv4 for ASN lookup.")
        return

    ipapi_data = fetch_ipapi(ip)
    ipapi_err: str | None = None
    if not ipapi_data:
        ipapi_err = "request failed"
    elif ipapi_data.get("error"):
        ipapi_err = str(ipapi_data.get("reason") or "ipapi error")

    if ipapi_err:
        org_display = "N/A"
        asn_display = "N/A"
        country = city = timezone = "N/A"
    else:
        org_display = ipapi_data.get("org") or "N/A"
        asn_display = ipapi_data.get("asn") or "N/A"
        country = ipapi_data.get("country_name") or "N/A"
        city = ipapi_data.get("city") or "N/A"
        timezone = ipapi_data.get("timezone") or "N/A"

    ip_api_meta = fetch_ip_api(ip)

    print("--- ASN Lookup Results ---")
    print(f"IP Address: {ip}")
    print(f"ASN (ipapi): {asn_display}")
    print(f"Org (ipapi): {org_display}")
    print(f"Country:     {country}")
    print(f"City:        {city}")
    print(f"Timezone:    {timezone}")

    if ip_api_meta.get("status") == "success":
        print(
            f"ip-api:      isp={ip_api_meta.get('isp')!r} as={ip_api_meta.get('as')!r} "
            f"hosting={ip_api_meta.get('hosting')} mobile={ip_api_meta.get('mobile')} "
            f"proxy={ip_api_meta.get('proxy')}"
        )
    else:
        print(
            f"ip-api:      status={ip_api_meta.get('status')!r} "
            f"({ip_api_meta.get('message')!r})"
        )

    if ipapi_err:
        s_ipapi, msg_ipapi = 3, f"ipapi unavailable ({ipapi_err}), org unknown"
    else:
        org = str(ipapi_data.get("org") or "")
        s_ipapi, msg_ipapi = classify_org(org)

    s_api, msg_api = classify_ip_api(ip_api_meta)

    final_score, final_status = merge_asn_scores(s_ipapi, s_api, msg_ipapi, msg_api)

    print()
    print(f"SCORE: {final_score}")
    print(f"STATUS: {final_status}")


def main() -> None:
    arg_ip = sys.argv[1] if len(sys.argv) > 1 else ""
    lookup_asn(arg_ip)


if __name__ == "__main__":
    main()
