#!/usr/bin/env python3
"""
Geo-Latency Consistency Check (heuristic)

Compare geolocation distance (from IP) vs observed network timing (ping or TCP connect).
If ICMP is blocked, falls back to TCP connect to :443.

SCORE scale: **1** = latency matches geographic distance (consistent). **5** = mismatch
(impossible RTT vs claimed distance, or very long “scenic” route vs distance).
This is NOT definitive VPN detection.

Exit codes: 0 on success (SCORE printed), 1 on failure so batch runners do not treat errors as OK.
"""

import math
import re
import socket
import subprocess
import sys
import time

import requests


def calculate_latency_score(distance_km, rtt_ms):
    """
    1 = good match (RTT plausible for distance). 5 = strong mismatch.
    """
    if rtt_ms <= 0 or distance_km <= 0:
        return 0

    min_possible_rtt = (distance_km * 2) / 200
    ratio = rtt_ms / min_possible_rtt

    # Too fast for claimed distance → timing contradicts geo (often CDN / wrong geo / “fake” far IP)
    if rtt_ms < (min_possible_rtt * 0.9):
        return 5
    if ratio < 1.8:
        return 1
    if ratio < 3.0:
        return 2
    if ratio < 5.0:
        return 3
    if ratio < 8.0:
        return 4
    return 5


def get_my_coords():
    endpoints = [
        "https://ipapi.co/json/",
        "http://ip-api.com/json/",
    ]
    for url in endpoints:
        try:
            resp = requests.get(url, timeout=8)
            data = resp.json()
            if data.get("status") == "fail" or data.get("error"):
                continue
            lat = data.get("latitude") or data.get("lat")
            lon = data.get("longitude") or data.get("lon")
            if lat is not None and lon is not None:
                return {
                    "lat": float(lat),
                    "lon": float(lon),
                    "city": data.get("city") or "",
                    "country": data.get("country_name") or data.get("country") or "",
                    "ip": data.get("ip") or data.get("query") or "",
                }
        except (requests.RequestException, ValueError, TypeError, KeyError):
            continue
    return None


def get_host_coords(hostname):
    try:
        host_ip = socket.gethostbyname(hostname)
    except OSError:
        return None

    urls = (
        f"https://ipapi.co/{host_ip}/json/",
        f"http://ip-api.com/json/{host_ip}",
    )
    for url in urls:
        try:
            resp = requests.get(url, timeout=8)
            data = resp.json()
            if data.get("status") == "fail" or data.get("error"):
                continue
            lat = data.get("latitude") or data.get("lat")
            lon = data.get("longitude") or data.get("lon")
            if lat is not None and lon is not None:
                return {
                    "lat": float(lat),
                    "lon": float(lon),
                    "ip": host_ip,
                }
        except (requests.RequestException, ValueError, TypeError, KeyError):
            continue
    return None


def haversine(lat1, lon1, lat2, lon2):
    r = 6371.0
    dlat, dlon = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(
        math.radians(lat2)
    ) * math.sin(dlon / 2) ** 2
    return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def ping_result(host):
    if sys.platform == "win32":
        cmd = ["ping", "-n", "4", "-w", "2000", host]
    else:
        cmd = ["ping", "-c", "4", "-W", "2", host]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return {"avg_rtt_ms": None, "received": 0}

    received = 0
    avg_rtt = None

    if sys.platform == "win32":
        m_recv = re.search(r"Received\s*=\s*(\d+)", out, re.I)
        if m_recv:
            received = int(m_recv.group(1))
        m_avg = re.search(r"Average\s*=\s*(\d+)\s*ms", out, re.I)
        if m_avg:
            avg_rtt = float(m_avg.group(1))
    else:
        m_recv = re.search(r"(\d+)\s+received", out)
        if m_recv:
            received = int(m_recv.group(1))
        m_avg = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", out)
        if m_avg:
            avg_rtt = float(m_avg.group(1))

    return {"avg_rtt_ms": avg_rtt if received > 0 else None, "received": received}


def tcp_connect_ms(host, port=443):
    timings = []
    for _ in range(3):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        t0 = time.time()
        try:
            s.connect((host, port))
            timings.append((time.time() - t0) * 1000.0)
        except OSError:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
    return sum(timings) / len(timings) if timings else None


def run_test(target_host="www.canberra.edu.au") -> bool:
    print(f"--- Geo-Latency Analysis vs {target_host} ---")

    me = get_my_coords()
    target = get_host_coords(target_host)
    if not me or not target:
        print(
            "❌ Error: Could not resolve coordinates for your IP or target host "
            "(network, rate limit, or DNS).",
            file=sys.stderr,
        )
        return False

    dist = haversine(me["lat"], me["lon"], target["lat"], target["lon"])
    print(f"Location: {me['city']}, {me['country']} -> Target: {target_host}")
    print(f"Map Distance: {int(dist)} km")

    ping = ping_result(target_host)
    rtt = ping["avg_rtt_ms"]
    method = "ICMP Ping"

    if not rtt:
        print("Ping unusable or blocked. Falling back to TCP port 443...")
        rtt = tcp_connect_ms(target_host)
        method = "TCP Connect"

    if not rtt:
        print("❌ Error: All timing attempts failed (ping + TCP).", file=sys.stderr)
        return False

    score = calculate_latency_score(dist, rtt)

    print("\n" + "=" * 45)
    print(f"SCORE: {score}")

    messages = {
        1: "MATCH: Latency is consistent with geographic distance.",
        2: "LIKELY MATCH: Minor routing overhead vs distance.",
        3: "INCONSISTENT: Lag high for this distance (routing noise or indirect path).",
        4: "SUSPICIOUS: Very long route vs distance (possible VPN or bad geo).",
        5: "MISMATCH: RTT too low for claimed distance, or far too high (timing vs geo disagree).",
    }
    verdict = messages.get(score, "N/A (invalid inputs)")
    # Keep STATUS under ~180 chars so batch HTML extraction always picks it up.
    print(f"STATUS: Measured via: {method}")
    print(f" Latency: {rtt:.2f} ms")
    print(f" RESULT: {verdict}")
    print("=" * 45)
    return True


if __name__ == "__main__":
    try:
        ok = run_test()
    except Exception as exc:
        print(f"❌ Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0 if ok else 1)
