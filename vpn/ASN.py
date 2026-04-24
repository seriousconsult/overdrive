#!/usr/bin/env python3
import re
import sys
import requests

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
]

def classify_org(org: str) -> str:
    if not org:
        return "unknown"

    org = org.strip()
    for pat in HOSTING_ORG_PATTERNS:
        if re.search(pat, org, flags=re.IGNORECASE):
            return "likely hosting / datacenter / transit (heuristic)"
    return "unknown (heuristic) — not enough evidence of residential"

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

    status = classify_org(org)
    print(f"Status:     {status}")

if __name__ == "__main__":
    # Usage:
    #   ./ASN.py
    #   ./ASN.py 40.143.35.118
    arg_ip = sys.argv[1] if len(sys.argv) > 1 else ""
    lookup_asn(arg_ip)