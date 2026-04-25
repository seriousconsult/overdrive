#!/usr/bin/env python3
 
'''
VPNs add a "hop" to your connection. 
If you are in New York and connected to a London VPN, your latency to a London server should be very low (~2-10ms), 
but your latency to a New York server should be high (~70-100ms).
If you are "in London" but your ping to a New York server is 5ms, the website knows your geographical
 location is faked.

------
Your Reported Location: Buenos Aires, Argentina (IP: 84.252.114.2)
Map Distance (based on IP):   11128 km
Physics Distance (based on RTT): 2866 km
🚨 LEAK DETECTED!
Your ping is 28.667ms. It is physically impossible to be 11128km away.
#!/usr/bin/env python3

Geo-Latency Consistency Check (heuristic)

Goal:
- Compare geolocation “distance” (from IP) vs observed network timing.
- If ICMP ping is blocked (0% received), print a clear statement and fall back
  to TCP connect timing to :443 (weaker heuristic).

Note:
- This is NOT definitive VPN leak detection. Routing, congestion, and geolocation
  inaccuracy can all distort results.
'''

#!/usr/bin/env python3

import subprocess
import re
import time
import socket
import requests
import math

def calculate_latency_score(distance_km, rtt_ms):
    if rtt_ms <= 0 or distance_km <= 0:
        return 0
    
    # 1. The Physics Limit (Speed of light in fiber is ~200,000 km/s)
    # Round trip distance is distance * 2. 
    # Minimum RTT = (Distance * 2) / 200
    min_possible_rtt = (distance_km * 2) / 200
    
    # 2. Compare Actual vs Physics
    ratio = rtt_ms / min_possible_rtt
    
    if rtt_ms < (min_possible_rtt * 0.9): # 10% buffer for slight measurement errors
        return 1  # Impossible speed: Location is definitely spoofed
    elif ratio < 1.8:
        return 5  # Very consistent: Physical location matches IP
    elif ratio < 3.0:
        return 4  # Likely match: Standard routing delays
    elif ratio < 5.0:
        return 3  # Inconsistent: High lag or indirect routing
    elif ratio < 8.0:
        return 2  # Probable mismatch: Data is taking a very long 'scenic route'
    else:
        return 1  # Certain mismatch: IP location is faked


def get_my_coords():
    providers = ["https://ipapi.co/json/", "https://ip-api.com/json/"]
    for url in providers:
        try:
            resp = requests.get(url, timeout=5)
            data = resp.json()
            lat = data.get("latitude") or data.get("lat")
            lon = data.get("longitude") or data.get("lon")
            if lat and lon:
                return {
                    "lat": float(lat), "lon": float(lon),
                    "city": data.get("city") or "",
                    "country": data.get("country_name") or data.get("country") or "",
                    "ip": data.get("ip") or data.get("query") or ""
                }
        except: continue
    return None


def get_host_coords(hostname):
    try:
        host_ip = socket.gethostbyname(hostname)
        resp = requests.get(f"https://ipapi.co/{host_ip}/json/", timeout=5)
        data = resp.json()
        return {"lat": float(data["latitude"]), "lon": float(data["longitude"]), "ip": host_ip}
    except: return None


def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    dlat, dlon = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

def ping_result(host):
    try:
        proc = subprocess.run(["ping", "-c", "4", "-W", "2", host], stdout=subprocess.PIPE, text=True, timeout=10)
        m_avg = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", proc.stdout)
        received = int(re.search(r"(\d+) received", proc.stdout).group(1))
        return {"avg_rtt_ms": float(m_avg.group(1)) if m_avg else None, "received": received}
    except: return {"avg_rtt_ms": None, "received": 0}


def tcp_connect_ms(host, port=443):
    timings = []
    for _ in range(3):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        t0 = time.time()
        try:
            s.connect((host, port))
            timings.append((time.time() - t0) * 1000.0)
            s.close()
        except: pass
    return sum(timings) / len(timings) if timings else None


def run_test(target_host="www.canberra.edu.au"):
    # note most major commercial sites will use a CDN that makes this test less accurate, 
    # so we pick a well-known university server that is geographically consistent with its IP.
    print(f"--- Starting Geo-Latency Analysis against {target_host} ---")
    
    me = get_my_coords()
    target = get_host_coords(target_host)
    if not me or not target:
        print("❌ Error: Could not resolve coordinates.")
        return

    dist = haversine(me["lat"], me["lon"], target["lat"], target["lon"])
    print(f"Location: {me['city']}, {me['country']} -> Target: {target_host}")
    print(f"Map Distance: {int(dist)} km")

    # Try Ping, Fallback to TCP
    ping = ping_result(target_host)
    rtt = ping["avg_rtt_ms"]
    method = "ICMP Ping"

    if not rtt:
        print("Ping blocked. Falling back to TCP port 443...")
        rtt = tcp_connect_ms(target_host)
        method = "TCP Connect"

    if not rtt:
        print("❌ All timing attempts failed.")
        return

    score = calculate_latency_score(dist, rtt)
    
    print("\n" + "="*45)
    print(f"SCORE: {score}")
    print(f" Measured via: {method}")
    print(f" Latency: {rtt:.2f} ms")
    
    messages = {
        5: "MATCH: Latency is consistent with your reported IP location.",
        4: "LIKELY MATCH: Minor routing overhead detected.",
        3: "INCONSISTENT: High lag detected for this distance.",
        2: "SUSPICIOUS: Data taking a very long route (Possible VPN).",
        1: "IMPOSSIBLE: Speed of light proves your IP location is faked."
    }
    print(f" RESULT: {messages.get(score)}")
    print("="*45)

if __name__ == "__main__":
    run_test()