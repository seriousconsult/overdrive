#!/usr/bin/env python3



import time
import requests

# Get Timezone from IP
ip_zone = requests.get("https://ipapi.co/timezone/").text
# Get Timezone from System
sys_zone = time.tzname[0]

print(f"IP Timezone: {ip_zone}")
print(f"System Timezone: {sys_zone}")

if ip_zone != sys_zone:
    print("🚨 ALERT: Timezone mismatch detected! Websites will know you are using a VPN.")