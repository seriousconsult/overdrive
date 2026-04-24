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

import requests
import subprocess
import re
import math
import socket
import time


def get_my_coords():
    """Fetch location using multiple providers for redundancy."""
    providers = [
        "https://ipapi.co/json/",
        "https://ip-api.com/json/",
        # freeipapi often works, but may be less reliable/available
        "https://freeipapi.com/api/json",
    ]

    for url in providers:
        try:
            host = url.split("/")[2]
            print(f"Trying to fetch your IP data from {host}...")
            resp = requests.get(url, timeout=5)
            data = resp.json()

            lat = data.get("latitude") or data.get("lat")
            lon = data.get("longitude") or data.get("lon")
            if lat is None or lon is None:
                continue

            return {
                "lat": float(lat),
                "lon": float(lon),
                "city": data.get("city") or data.get("cityName") or "",
                "country": data.get("country_name") or data.get("country") or "",
                "ip": data.get("ip") or data.get("query") or "",
            }
        except Exception:
            continue

    return None


def get_host_coords(hostname):
    """Resolve hostname to IP and geolocate that IP."""
    try:
        host_ip = socket.gethostbyname(hostname)
        resp = requests.get(f"https://ipapi.co/{host_ip}/json/", timeout=5)
        data = resp.json()

        lat = data.get("latitude")
        lon = data.get("longitude")
        if lat is None or lon is None:
            return None

        return {"lat": float(lat), "lon": float(lon), "ip": host_ip}
    except Exception as e:
        print(f"❌ Target lookup failed: {e}")
        return None


def haversine(lat1, lon1, lat2, lon2):
    """Distance in km on a sphere."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    )
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def ping_result(host, count=4, timeout_sec=2):
    """
    Return ping summary:
      {
        "avg_rtt_ms": float|None,
        "received": int,
        "packet_loss_pct": float
      }
    """
    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout_sec), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=25,
        )
        out = proc.stdout

        m = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received", out)
        if not m:
            # Fallback
            received = 0
            transmitted = count
        else:
            transmitted = int(m.group(1))
            received = int(m.group(2))

        loss_pct = 100.0
        if transmitted > 0:
            loss_pct = ((transmitted - received) / transmitted) * 100.0

        # Parse avg RTT
        m_avg = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", out)
        avg = float(m_avg.group(1)) if m_avg else None

        return {"avg_rtt_ms": avg, "received": received, "packet_loss_pct": loss_pct}
    except Exception:
        # Treat as blocked/unavailable
        return {"avg_rtt_ms": None, "received": 0, "packet_loss_pct": 100.0}


def tcp_connect_ms(host, port=443, attempts=4, timeout=5):
    """
    Return average TCP connect time in milliseconds, or None if all attempts fail.
    """
    timings = []
    for _ in range(attempts):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        try:
            s.connect((host, port))
            timings.append((time.time() - t0) * 1000.0)
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass

    return sum(timings) / len(timings) if timings else None


def run_test(target_host="ox.ac.uk"):
    print(f"Starting Geo-Latency Analysis against {target_host}...\n")

    me = get_my_coords()
    if not me:
        print("❌ CRITICAL ERROR: Could not determine your location from any provider.")
        print("Tip: Check if your VPN kill-switch blocks requests, or try a different provider.")
        return

    print(f"Your Reported Location: {me['city']}, {me['country']} (IP: {me['ip']})")

    target = get_host_coords(target_host)
    if not target or target.get("lat") is None or target.get("lon") is None:
        print(f"\n⚠️ Could not locate {target_host} via API. Cannot do geo-distance consistency check.")
        return

    geo_dist_km = haversine(me["lat"], me["lon"], target["lat"], target["lon"])
    print(f"Resolved target: {target_host} -> {target['ip']}")
    print(f"Map Distance (IP straight-line): {int(geo_dist_km)} km\n")

    # ---- Ping first (if available) ----
    ping = ping_result(target_host, count=4, timeout_sec=2)

    if ping["received"] == 0:
        print("Ping: 0 replies received (ICMP likely blocked/unreachable).")
        if ping["packet_loss_pct"] is not None:
            print(f"Ping loss: {ping['packet_loss_pct']:.0f}%")
        print("\nTiming consistency check (RTT vs geo-distance): UNAVAILABLE.")
        print("Reason: no measurable RTT from ping. This is NOT proof of VPN location spoofing.\n")

        print("Falling back to TCP connect timing to port 443 (weaker heuristic)...")
        tcp_ms = tcp_connect_ms(target_host, port=443)
        if tcp_ms is None:
            print("❌ TCP connect timing also failed. No useful timing data.")
            return

        network_dist_est_km = (tcp_ms * 200.0) / 2.0  # very rough, RTT->distance proxy
        print(f"TCP connect avg: {tcp_ms:.3f} ms")
        print(f"Physics distance estimate (TCP-approx): {int(network_dist_est_km)} km\n")

        # Heuristic statement (still not definitive)
        if geo_dist_km > 500 and network_dist_est_km < (geo_dist_km * 0.6):
            print("🚨 Inconsistency (heuristic): TCP-based estimate is much smaller than IP geo-distance.")
        else:
            print("🟢 Rough consistency (heuristic): TCP-based estimate is not drastically inconsistent.")
        print("\n(Again: not definitive—routing and congestion can distort timing.)")
        return

    # If ping had replies:
    avg_rtt_ms = ping["avg_rtt_ms"]
    if avg_rtt_ms is None:
        print("Ping replies received, but could not parse avg RTT. Skipping RTT-based check.")
        return

    print(f"Ping avg RTT: {avg_rtt_ms:.3f} ms")

    # Fiber-ish approximation: ~100 km per 1ms one-way => RTT/2 => ~200 km per 1ms RTT
    network_dist_est_km = (avg_rtt_ms * 200.0) / 2.0
    print(f"Physics distance estimate (RTT-based): {int(network_dist_est_km)} km\n")

    print("--- Analysis ---")
    if geo_dist_km > 500 and network_dist_est_km < (geo_dist_km * 0.6):
        print("🚨 LEAK/INCONSISTENCY DETECTED (heuristic): RTT is too small vs IP-distance.")
        print(f"Your ping is {avg_rtt_ms:.3f}ms; IP geo-distance is {int(geo_dist_km)}km.")
    else:
        print("🟢 VERIFIED-ISH (heuristic): latency is generally consistent with the reported IP geo-distance.")


if __name__ == "__main__":
    run_test()