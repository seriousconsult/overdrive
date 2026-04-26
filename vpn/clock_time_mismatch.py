#!/usr/bin/env python3
from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests

UA = {"User-Agent": "overdrive-clock-time-mismatch/1.0"}
TIMEOUT = 12

_IANA_TZ_RE = re.compile(r"^[A-Za-z0-9_\-/+]+$")


def _looks_like_error_blob(s: str) -> bool:
    t = (s or "").strip().lower()
    if not t:
        return True
    if t.startswith("{") or t.startswith("<!doctype") or t.startswith("<html"):
        return True
    if "rate" in t and "limit" in t:
        return True
    if "please contact us" in t or "sign up" in t or "pricing" in t:
        return True
    if "error" in t and ("http" in t or "trial" in t):
        return True
    return False


def _normalize_iana_tz(name: str | None) -> str | None:
    if not name:
        return None
    tz = str(name).strip().strip('"').strip("'")
    if not tz or _looks_like_error_blob(tz):
        return None
    # ip-api sometimes returns "Region/City" with spaces? rare; strip
    tz = tz.replace(" ", "_")
    if not _IANA_TZ_RE.match(tz) or "/" not in tz:
        return None
    try:
        ZoneInfo(tz)  # validate key is loadable
    except ZoneInfoNotFoundError:
        return None
    except Exception:
        return None
    return tz


def _public_ipv4() -> str | None:
    try:
        r = requests.get("https://api.ipify.org?format=json", headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        ip = r.json().get("ip")
        if not ip or ":" in str(ip):
            return None
        return str(ip).strip()
    except Exception:
        return None


def _ipapi_json(ip: str | None) -> dict[str, Any] | None:
    try:
        url = f"https://ipapi.co/{ip}/json/" if ip else "https://ipapi.co/json/"
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        if r.status_code == 429:
            return None
        data = r.json()
        if isinstance(data, dict) and data.get("error"):
            return None
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _ipapi_timezone(ip: str | None) -> str | None:
    data = _ipapi_json(ip)
    if not data:
        return None
    return _normalize_iana_tz(str(data.get("timezone") or ""))


def _ip_api_timezone(ip: str) -> str | None:
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,timezone",
            headers=UA,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("status") != "success":
            return None
        return _normalize_iana_tz(str(data.get("timezone") or ""))
    except Exception:
        return None


def get_ip_timezone() -> tuple[str | None, str]:
    """
    Resolve an IANA timezone for the egress IP using multiple providers.
    Returns (tz_or_none, provenance_string).
    """
    ip = _public_ipv4()

    if ip:
        tz = _ip_api_timezone(ip)
        if tz:
            return tz, f"ip-api.com (ip={ip})"

    tz = _ipapi_timezone(ip)
    if tz:
        return tz, f"ipapi.co json (ip={ip or 'auto'})"

    if ip:
        tz2 = _ipapi_timezone(None)
        if tz2:
            return tz2, "ipapi.co json (auto endpoint)"

    # Last resort: ip-api auto (may be less reliable than explicit IP)
    try:
        r = requests.get(
            "http://ip-api.com/json/?fields=status,message,timezone",
            headers=UA,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("status") == "success":
            tz3 = _normalize_iana_tz(str(data.get("timezone") or ""))
            if tz3:
                return tz3, "ip-api.com (auto endpoint)"
    except Exception:
        pass

    return None, f"all providers failed (ip={ip or 'unknown'})"


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

def main():
    ip_zone, provenance = get_ip_timezone()
    
    if not ip_zone:
        print("Could not determine a valid IANA timezone for egress IP.")
        print(f"Provenance: {provenance}")
        print("\nSCORE: 3")
        print(
            "STATUS: Inconclusive — geo-IP timezone lookup failed (rate limit, blocking HTML, or API error)."
        )
        return
    
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

if __name__ == "__main__":
    main()