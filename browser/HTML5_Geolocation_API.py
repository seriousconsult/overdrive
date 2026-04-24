#!/usr/bin/env python3

#!/usr/bin/env python3
import requests
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 8

PROVIDERS = [
    {
        "name": "ipapi.co",
        "url": "https://ipapi.co/json/",
    },
    {
        "name": "ip-api.com",
        "url": "http://ip-api.com/json/",
    },
    {
         "name": "ipapi.is",
         "url": "https://api.ipapi.is/json/",
    },
]


def fetch_json(url: str, params: Optional[dict] = None, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    r = requests.get(url, params=params, timeout=timeout, headers={
        "User-Agent": "geo-leak-check/1.0"
    })
    r.raise_for_status()
    return r.json()


def normalize_ip_fields(provider: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize common fields across providers.
    Missing fields are kept as None so we can compare easily.
    """
    # ipapi.is returns asn as an object, country as 2-letter code
    asn_raw = raw.get("asn")
    asn_val = None
    org_from_asn = None
    if isinstance(asn_raw, dict):
        asn_val = asn_raw.get("asn")
        org_from_asn = asn_raw.get("org")
    
    # ipapi.is specific field mapping - data is nested under location/company
    if provider == "ipapi.is":
        loc = raw.get("location", {})
        comp = raw.get("company", {})
        out = {
            "provider": provider,
            "ip": raw.get("ip"),
            "city": loc.get("city"),
            "region": loc.get("state"),
            "country": loc.get("country"),
            "timezone": loc.get("timezone"),
            "lat": loc.get("latitude"),
            "lon": loc.get("longitude"),
            "asn": asn_val,
            "org": comp.get("name") or org_from_asn,
        }
    else:
        out = {
            "provider": provider,
            "ip": raw.get("ip") or raw.get("query"),
            "city": raw.get("city") or raw.get("cityName"),
            "country": raw.get("country_name") or raw.get("country"),
            "region": raw.get("region") or raw.get("regionName"),
            "timezone": raw.get("timezone"),
            "lat": raw.get("latitude") or raw.get("lat"),
            "lon": raw.get("longitude") or raw.get("lon"),
            "asn": asn_val or raw.get("as"),
            "org": raw.get("org") or raw.get("isp") or org_from_asn,
        }
    return out


def consensus_summary(results: List[Dict[str, Any]]) -> None:
    def uniq(field: str) -> List[str]:
        vals = []
        for r in results:
            v = r.get(field)
            if v is not None:
                vals.append(str(v))
        return sorted(set(vals))

    countries = uniq("country")
    cities = uniq("city")
    timezones = uniq("timezone")
    asns = uniq("asn")

    print("\n--- Provider Discrepancy Summary ---")
    print(f"Countries seen ({len(countries)}): {', '.join(countries) if countries else 'N/A'}")
    print(f"Cities seen    ({len(cities)}): {', '.join(cities) if cities else 'N/A'}")
    print(f"Timezones      ({len(timezones)}): {', '.join(timezones) if timezones else 'N/A'}")
    print(f"ASNs seen       ({len(asns)}): {', '.join(asns) if asns else 'N/A'}")


def main():
    print("== Geolocation Checker (what servers think) ==")

    results = []
    for p in PROVIDERS:
        name = p["name"]
        url = p["url"]
        try:
            raw = fetch_json(url, params=p.get("params"), timeout=DEFAULT_TIMEOUT)
            # Handle ip-api.com error payloads
            if name == "ip-api.com" and raw.get("status") == "fail":
                raise RuntimeError(raw.get("message") or "ip-api.com status=fail")

            norm = normalize_ip_fields(name, raw)
            results.append(norm)

        except Exception as e:
            print(f"[{name}] ERROR: {e}")

    if not results:
        print("No provider results available.")
        return

    print("\n--- Per-Provider Results ---")
    for r in results:
        print(f"\n[{r['provider']}]")
        print(f"  IP:        {r['ip']}")
        print(f"  City:      {r['city']}")
        print(f"  Region:    {r['region']}")
        print(f"  Country:   {r['country']}")
        print(f"  Timezone:  {r['timezone']}")
        print(f"  Lat/Lon:   {r['lat']}, {r['lon']}")
        print(f"  Org/ISP:   {r['org']}")

    consensus_summary(results)


if __name__ == "__main__":
    main()