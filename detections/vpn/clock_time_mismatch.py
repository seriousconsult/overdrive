#!/usr/bin/env python3
"""Local clock vs geo-IP timezone offset heuristic.

Purpose: Compare your machine's UTC offset to the offset implied by the egress IP's timezone
(ip-api style metadata). Large skew can suggest VPN/geo inconsistency (weak signal).

Score (1–5): 1 = offsets align. 5 = material mismatch. 3 = inconclusive when timezone lookup fails.

Environment: Needs outbound HTTP (requests) and local zoneinfo.

Exit code: 0 after scoring completes.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_vpn import get_ip_timezone

UA = {"User-Agent": "overdrive-clock-time-mismatch/1.0"}
TIMEOUT = 12



def get_local_timezone():
    """Get the local timezone name"""
    return datetime.now().astimezone().tzname()

def get_local_utc_offset():
    return datetime.now().astimezone().utcoffset()

def get_ip_utc_offset(ip_tz_name: str):
    if not ip_tz_name:
        return None
    try:
        ip_tz = ZoneInfo(ip_tz_name)  # will map IANA -> correct offset incl. DST
    except ZoneInfoNotFoundError:
        return None
    return datetime.now(ip_tz).utcoffset()

def calculate_match_score(local_offset, ip_offset):
    """
    Suspicion score (1–5), aligned with the rest of Overdrive:
      1 — Strong agreement: local clock UTC offset matches geo-IP timezone offset (low suspicion).
      3 — Moderate disagreement / noisy (provider, DST edge, partial data).
      5 — Strong disagreement: offsets differ materially (VPN/geo/wrong-TZ signal — heuristic).

    (Previously this function used an inverted “match quality” scale; higher was “more match”.)
    """
    if local_offset is None or ip_offset is None:
        return 3

    # Calculate difference in hours
    diff_seconds = abs(local_offset - ip_offset)
    diff_hours = diff_seconds.total_seconds() / 3600

    if diff_hours == 0:
        return 1
    if diff_hours <= 1:
        return 2  # within 1 hour — often DST / provider noise; low suspicion
    if diff_hours <= 3:
        return 3  # noticeable skew
    if diff_hours <= 6:
        return 4  # strong skew
    return 5  # material mismatch

def main() -> int:
    ip_zone, provenance = get_ip_timezone()

    if not ip_zone:
        print("Could not determine a valid IANA timezone for egress IP.")
        print(f"Provenance: {provenance}")
        print("\nSCORE: 3")
        print(
            "STATUS: Inconclusive — geo-IP timezone lookup failed (rate limit, blocking HTML, or API error)."
        )
        return 0
    
    local_offset = get_local_utc_offset()
    ip_offset = get_ip_utc_offset(ip_zone)
    local_tz = str(datetime.now().astimezone().tzinfo)

    print(f"IP Timezone (IANA): {ip_zone}")
    print(f"IP TZ source:       {provenance}")
    print(f"Local Timezone:     {local_tz}")
    print(f"Local UTC offset:   {local_offset}")
    print(f"IP UTC offset:      {ip_offset}")

    score = calculate_match_score(local_offset, ip_offset)
    
    print(f"\nSCORE: {score}")
    
    if score <= 2:
        print(
            "STATUS: Local UTC offset aligns with geo-IP timezone offset (low suspicion; heuristic)."
        )
    elif score == 3:
        print(
            "STATUS: Moderate offset skew — may be provider noise, DST edge, or soft VPN/geo mismatch."
        )
    elif score == 4:
        print(
            "STATUS: Strong offset skew — suspicious for VPN, wrong geo-IP TZ, or split routing (heuristic)."
        )
    else:
        print(
            "STATUS: Material offset mismatch — high suspicion for VPN/geo/TZ inconsistency (heuristic)."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())