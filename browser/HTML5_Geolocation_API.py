#!/usr/bin/env python3


import requests

def check_location_leak():
    # 1. Check location based on IP
    try:
        data = requests.get('https://ipapi.co/json/').json()
        print(f"IP-based Location: {data.get('city')}, {data.get('country_name')}")
        print(f"Coordinates: {data.get('latitude')}, {data.get('longitude')}")
    except Exception as e:
        print(f"Error checking IP location: {e}")

check_location_leak()