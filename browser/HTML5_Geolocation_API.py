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


from typing import Any, Dict, List

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from common.common_browser import DEFAULT_TIMEOUT, fetch_json, normalize_ip_fields

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