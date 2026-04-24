#!/usr/bin/env python3
import requests
from datetime import datetime
from zoneinfo import ZoneInfo

def get_ip_timezone():
    # Example returned value: "America/New_York"
    return requests.get("https://ipapi.co/timezone/").text.strip()

def get_local_utc_offset():
    return datetime.now().astimezone().utcoffset()

def get_ip_utc_offset(ip_tz_name: str):
    ip_tz = ZoneInfo(ip_tz_name)  # will map IANA -> correct offset incl. DST
    return datetime.now(ip_tz).utcoffset()

def main():
    ip_zone = get_ip_timezone()
    local_offset = get_local_utc_offset()
    ip_offset = get_ip_utc_offset(ip_zone)

    print(f"IP Timezone (IANA): {ip_zone}")
    print(f"Local UTC offset:   {local_offset}")
    print(f"IP UTC offset:      {ip_offset}")

    # If offsets differ by hours, that’s a real mismatch.
    if local_offset != ip_offset:
        print("🚨 ALERT: Timezone/offset mismatch detected (heuristic).")
    else:
        print("✅ Timezone/offset match (at current time).")

if __name__ == "__main__":
    main()