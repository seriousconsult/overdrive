#!/usr/bin/env python3
"""Geo-latency consistency (heuristic).

Purpose: Compare geolocation distance (from IP) vs observed RTT (ICMP ping or TCP connect to :443).

Score (1–5): 1 = latency plausibly matches distance. 5 = strong timing/geo disagreement.
Not definitive VPN detection.

Environment: Linux/WSL with ping or TCP fallback; uses outbound HTTP for geo hints.

Exit code: 0 when SCORE was computed; 1 on failure (coords or timing unavailable).
"""

from __future__ import annotations

import math
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_vpn import (
    fetch_ip_api,
    fetch_ipapi,
    geo_coords_from_payload,
    public_ipv4,
)


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
    coords = geo_coords_from_payload(fetch_ipapi(None))
    if coords:
        return coords
    ip = public_ipv4()
    if ip:
        return geo_coords_from_payload(fetch_ip_api(ip))
    return None


def get_host_coords(hostname):
    try:
        host_ip = socket.gethostbyname(hostname)
    except OSError:
        return None

    for data in (fetch_ipapi(host_ip), fetch_ip_api(host_ip)):
        coords = geo_coords_from_payload(data if isinstance(data, dict) else None)
        if coords:
            coords["ip"] = host_ip
            return coords
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


def run_test(target_host: str = "www.canberra.edu.au") -> bool:
    print(f"--- Geo-Latency Analysis vs {target_host} ---")

    me = get_my_coords()
    target = get_host_coords(target_host)
    if not me or not target:
        print(
            "Error: Could not resolve coordinates for your IP or target host "
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
        print("Error: All timing attempts failed (ping + TCP).", file=sys.stderr)
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
    print(f"STATUS: Measured via {method}; RTT {rtt:.2f} ms — {verdict}")
    print("=" * 45)
    return True


def main() -> int:
    try:
        return 0 if run_test() else 1
    except Exception as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
