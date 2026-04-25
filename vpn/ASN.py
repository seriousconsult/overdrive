#!/usr/bin/env python3
import re
import sys
import requests

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


def classify_org(org: str) -> tuple[int, str]:
    """
    Returns a score 1-5 and description:
    5 = certain residential
    4 = likely residential
    3 = maybe residential
    2 = probably not residential
    1 = not residential (datacenter/hosting)
    """
    if not org:
        return 3, "unknown"

    org = org.strip()

    # Check for residential patterns first (higher priority)
    residential_score = 0
    for pat in RESIDENTIAL_ISP_PATTERNS:
        if re.search(pat, org, flags=re.IGNORECASE):
            residential_score += 2

    # Check for hosting/datacenter patterns
    hosting_score = 0
    for pat in HOSTING_ORG_PATTERNS:
        if re.search(pat, org, flags=re.IGNORECASE):
            hosting_score += 2

    # Calculate final score
    if hosting_score >= 2 and residential_score == 0:
        return 1, "not residential (datacenter/hosting)"
    elif hosting_score >= 2 and residential_score >= 2:
        return 3, "maybe residential (mixed signals)"
    elif residential_score >= 4:
        return 5, "certain residential"
    elif residential_score >= 2:
        return 4, "likely residential"
    elif residential_score >= 1:
        return 3, "maybe residential"
    else:
        return 2, "probably not residential"

def lookup_asn(ip_address: str = ""):
    if ip_address:
        url = f"https://ipapi.co/{ip_address}/json/"
    else:
        url = "https://ipapi.co/json/"

    headers = {
        "User-Agent": "asn-lookup/1.0",
    }

    r = requests.get(url, headers=headers, timeout=15)
    r.raise_for_status()
    data = r.json()

    ip = data.get("ip")
    asn = data.get("asn")
    org = data.get("org")
    country = data.get("country_name")
    city = data.get("city")
    timezone = data.get("timezone")

    print("--- ASN Lookup Results ---")
    print(f"IP Address: {ip}")
    print(f"ASN:        {asn}")
    print(f"Org:        {org}")
    print(f"Country:    {country}")
    print(f"City:       {city}")
    print(f"Timezone:   {timezone}")

    score, status = classify_org(org)
    print(f"Status:     {status} (Score: {score}/5)")

if __name__ == "__main__":
    # Usage:
    #   ./ASN.py
    #   ./ASN.py 40.143.35.118
    arg_ip = sys.argv[1] if len(sys.argv) > 1 else ""
    lookup_asn(arg_ip)