#!/usr/bin/env python3

'''
Does GeoIP-style APIs disagree enough that it *looks* like the same client is
associated with more than one place (VPN / multi-exit / bad data)?

This script queries several IP geolocation APIs and compares normalized fields.

Unified score (see compute_multi_location_score):
  1 — Providers agree on one country / one coherent place (not “multiple locations”).
  5 — Strong disagreement across providers (very “multiple locations” from GeoIP).
  2–4 — Gradations of uncertainty or partial conflict.
'''


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
        cc = loc.get("country")
        if isinstance(cc, str):
            cc = cc.strip().upper() if len(cc) == 2 else None
        out = {
            "provider": provider,
            "ip": raw.get("ip"),
            "city": loc.get("city"),
            "region": loc.get("state"),
            "country": loc.get("country"),
            "country_code": cc,
            "timezone": loc.get("timezone"),
            "lat": loc.get("latitude"),
            "lon": loc.get("longitude"),
            "asn": asn_val,
            "org": comp.get("name") or org_from_asn,
        }
    else:
        cc_raw = raw.get("country_code") or raw.get("countryCode")
        cc = None
        if isinstance(cc_raw, str) and len(cc_raw.strip()) == 2:
            cc = cc_raw.strip().upper()
        cname = raw.get("country_name") or raw.get("country")
        out = {
            "provider": provider,
            "ip": raw.get("ip") or raw.get("query"),
            "city": raw.get("city") or raw.get("cityName"),
            "country": cname,
            "country_code": cc,
            "region": raw.get("region") or raw.get("regionName"),
            "timezone": raw.get("timezone"),
            "lat": raw.get("latitude") or raw.get("lat"),
            "lon": raw.get("longitude") or raw.get("lon"),
            "asn": asn_val or raw.get("as"),
            "org": raw.get("org") or raw.get("isp") or org_from_asn,
        }
    return out


def compute_multi_location_score(results: List[Dict[str, Any]]) -> tuple[int, str]:
    """
    1 — APIs agree: one country (coherent “single place” from GeoIP).
    5 — Strong disagreement: multiple countries (looks like “multiple locations”).
    2–4 — Ambiguity, partial data, or moderate conflict.
    """
    n = len(results)
    if n < 2:
        return (
            3,
            "Fewer than two successful API responses; cannot compare providers reliably.",
        )

    codes = [str(r["country_code"]).upper() for r in results if r.get("country_code")]
    use_codes = len(codes) == n

    if use_codes:
        distinct = set(codes)
        kind = "country code"
    else:
        distinct = set()
        for r in results:
            name = r.get("country")
            if name is not None and str(name).strip():
                distinct.add(str(name).strip().lower())
        kind = "country name"

    if not distinct:
        return 3, "No usable country field across results; inconclusive."

    dc = len(distinct)

    cities = [
        str(r["city"]).strip().lower()
        for r in results
        if r.get("city") is not None and str(r.get("city")).strip()
    ]
    distinct_cities = len(set(cities)) if cities else 0

    tzs = [
        str(r["timezone"]).strip().lower()
        for r in results
        if r.get("timezone") is not None and str(r.get("timezone")).strip()
    ]
    distinct_tz = len(set(tzs)) if tzs else 0

    if dc >= 3:
        return (
            5,
            f"{dc} distinct {kind}s — strong GeoIP disagreement (“multiple locations”).",
        )

    if dc == 2:
        return (
            5,
            f"Two distinct {kind}s — providers place this IP in different countries.",
        )

    score = 1
    note = f"All providers agree on one {kind} — not multiple countries."

    if distinct_cities >= 4:
        score = 3
        note = (
            "Single country but several different city labels — naming or database noise; "
            "mostly one country, slight ambiguity."
        )
    elif distinct_cities == 3:
        score = 3
        note = "Single country but two city labels — inconsistency."

    if score == 1 and distinct_tz >= 3:
        score = 3
        note = (
            "One country but many timezones across APIs — unusual; treat as alerting "
            "(data quality / regional TZ differences)."
        )
    elif score == 1 and distinct_tz == 2:
        score = 3
        note = "One country but two timezone values —  inconsistency."

    return score, note


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
        return None

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

    score, geo_note = compute_multi_location_score(results)
    print("\n--- Multi-location score (1–5) ---")
    print(f"SCORE: {score}")
    print(f"STATUS: {geo_note}")
    print()
    print("Scale: 1 = single coherent GeoIP location  ·  5 = strong cross-provider disagreement")
    return score


if __name__ == "__main__":
    main()