#!/usr/bin/env python3
import requests
from datetime import datetime
from zoneinfo import ZoneInfo

def get_ip_timezone():
    """Get timezone from IP using ipapi.co, with fallback to ip-api.com"""
    try:
        # Try ipapi.co first
        r = requests.get("https://ipapi.co/timezone/", timeout=10)
        text = r.text.strip()
        # Check if we got a valid timezone (not an error)
        if text and not text.startswith("{") and "RateLimited" not in text:
            return text
    except Exception as e:
        print(f"ipapi.co error: {e}")
    
    # Fallback to ip-api.com
    try:
        r = requests.get("http://ip-api.com/json/", timeout=10)
        data = r.json()
        if data.get("status") == "success":
            return data.get("timezone")
    except Exception as e:
        print(f"ip-api.com fallback error: {e}")
    
    return None

def get_local_timezone():
    """Get the local timezone name"""
    return datetime.now().astimezone().tzname()

def get_local_utc_offset():
    return datetime.now().astimezone().utcoffset()

def get_ip_utc_offset(ip_tz_name: str):
    if not ip_tz_name:
        return None
    ip_tz = ZoneInfo(ip_tz_name)  # will map IANA -> correct offset incl. DST
    return datetime.now(ip_tz).utcoffset()

def calculate_match_score(local_offset, ip_offset):
    """
    Calculate a score 1-5 for timezone match:
    1 = no match
    2 = possible match
    3 = probably match
    4 = match
    5 = certain match
    """
    if local_offset is None or ip_offset is None:
        return 1
    
    if local_offset == ip_offset:
        return 5
    
    # Calculate difference in hours
    diff_seconds = abs(local_offset - ip_offset)
    diff_hours = diff_seconds.total_seconds() / 3600
    
    if diff_hours == 0:
        return 5
    elif diff_hours <= 1:
        return 4  # within 1 hour - likely DST difference
    elif diff_hours <= 3:
        return 3  # within 3 hours - possible match
    elif diff_hours <= 6:
        return 2  # within 6 hours - possible match but unlikely
    else:
        return 1  # more than 6 hours - no match

def main():
    ip_zone = get_ip_timezone()
    
    if not ip_zone:
        print("ERROR: Could not determine IP timezone (rate limited or API failed)")
        return
    
    local_offset = get_local_utc_offset()
    ip_offset = get_ip_utc_offset(ip_zone)
    local_tz = str(datetime.now().astimezone().tzinfo)

    print(f"IP Timezone (IANA): {ip_zone}")
    print(f"Local Timezone:     {local_tz}")
    print(f"Local UTC offset:   {local_offset}")
    print(f"IP UTC offset:      {ip_offset}")

    score = calculate_match_score(local_offset, ip_offset)
    
    print(f"\Score: {score}/5")
    
    if score >= 4:
        print("✅ Timezone match")
    elif score == 3:
        print("⚠️  Probably match (within 3 hours)")
    elif score == 2:
        print("⚠️  Possible match (within 6 hours)")
    else:
        print("🚨 No match (timezone mismatch)")

if __name__ == "__main__":
    main()