#!/usr/bin/env python3
 
'''
VPNs add a "hop" to your connection. 
If you are in New York and connected to a London VPN, your latency to a London server should be very low (~2-10ms), 
but your latency to a New York server should be high (~70-100ms).
If you are "in London" but your ping to a New York server is 5ms, the website knows your geographical
 location is faked.

Starting Geo-Latency Analysis against google.co.uk...
Trying to fetch your IP data from ipapi.co...
Your Reported Location: Buenos Aires, Argentina (IP: 84.252.114.2)
Could not locate google.co.uk via API. Using London defaults for testing.

--- Analysis ---
Map Distance (based on IP):   11128 km
Physics Distance (based on RTT): 2866 km

🚨 LEAK DETECTED!
Your ping is 28.667ms. It is physically impossible to be 11128km away.

'''

import requests
import subprocess
import re
import math
import sys

def get_my_coords():
    """Fetches location using multiple providers for redundancy."""
    # List of reliable geolocation APIs
    providers = [
        "https://ipapi.co/json/",
        "https://ip-api.com/json/",
        "https://freeipapi.com/api/json"
    ]
    
    for url in providers:
        try:
            print(f"📡 Trying to fetch your IP data from {url.split('/')[2]}...")
            response = requests.get(url, timeout=5)
            data = response.json()
            
            # Normalize the data (different APIs use different keys)
            lat = data.get('latitude') or data.get('lat')
            lon = data.get('longitude') or data.get('lon')
            
            if lat and lon:
                return {
                    "lat": float(lat),
                    "lon": float(lon),
                    "city": data.get('city') or data.get('cityName'),
                    "country": data.get('country_name') or data.get('country'),
                    "ip": data.get('ip') or data.get('query')
                }
        except Exception as e:
            continue
    return None

def get_host_coords(hostname):
    """Fetches the location of the target host."""
    try:
        # Resolve the hostname to an IP using the system's 'getent' or 'host'
        host_ip = socket.gethostbyname(hostname)
        response = requests.get(f"https://ipapi.co/{host_ip}/json/", timeout=5)
        data = response.json()
        return {"lat": data.get("latitude"), "lon": data.get("longitude"), "ip": host_ip}
    except Exception as e:
        print(f"❌ Target lookup failed: {e}")
        return None

def haversine(lat1, lon1, lat2, lon2):
    """Haversine formula to calculate distance in km."""
    R = 6371 
    dlat, dlon = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

def run_test(target_host="google.co.uk"):
    print(f"🚀 Starting Geo-Latency Analysis against {target_host}...")
    
    me = get_my_coords()
    if not me:
        print("❌ CRITICAL ERROR: Could not determine your location from any provider.")
        print("💡 Tip: Check if your VPN 'Kill Switch' is blocking unencrypted HTTP/HTTPS requests.")
        return

    print(f"📍 Your Reported Location: {me['city']}, {me['country']} (IP: {me['ip']})")

    target = get_host_coords(target_host)
    if not target or target['lat'] is None:
        # Fallback for manual coordinate entry if target API fails
        print(f"⚠️ Could not locate {target_host} via API. Using London defaults for testing.")
        target = {"lat": 51.5074, "lon": -0.1278, "ip": "Unknown"}

    geo_dist = haversine(me['lat'], me['lon'], target['lat'], target['lon'])

    try:
        # Ping the target
        ping_output = subprocess.check_output(["ping", "-c", "4", target_host]).decode()
        avg_rtt = float(re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", ping_output).group(1))
        
        # Fiber speed estimate (~100km per 1ms of one-way travel)
        network_dist_est = (avg_rtt * 200) / 2
        
        print(f"\n--- Analysis ---")
        print(f"Map Distance (based on IP):   {int(geo_dist)} km")
        print(f"Physics Distance (based on RTT): {int(network_dist_est)} km")
        
        # If the physics distance is less than half the map distance, it's a leak
        if network_dist_est < (geo_dist * 0.6) and geo_dist > 500:
            print("\n🚨 LEAK DETECTED!")
            print(f"Your ping is {avg_rtt}ms. It is physically impossible to be {int(geo_dist)}km away.")
        else:
            print("\n🟢 VERIFIED: Latency is consistent with reported location.")

    except Exception as e:
        print(f"Ping failed: {e}")

import socket
if __name__ == "__main__":
    run_test()