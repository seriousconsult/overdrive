#!/usr/bin/env python3
"""Port checks for common VPN / proxy ports.

Purpose: Scan egress, loopback, and (on WSL2) default gateway for VPN-related TCP/UDP listeners.

Environment: Linux — bare metal, VM, or WSL2. Targets include public IPv4 (NAT egress on WSL2),
127.0.0.1, and WSL2 default gateway (often Windows host vNIC).

Score (1–5): **5** = OPEN VPN/proxy-related port on at least one target. **1** = no OPEN ports.
Middle scores = UDP silent/filtered uncertainty.

Exit code: **0** after completed audit; **130** on Ctrl+C.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys

import requests
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_vpn import get_public_ipv4, is_wsl, wsl_windows_host_ip


VPN_PORTS: tuple[tuple[int, str, str], ...] = (
    (1194, "udp", "OpenVPN"),
    (51820, "udp", "WireGuard"),
    (443, "tcp", "HTTPS/VPN"),
    (1080, "tcp", "SOCKS5"),
    (3128, "tcp", "HTTP proxy"),
    (500, "udp", "IPsec"),
    (4500, "udp", "IPsec NAT-T"),
)


def check_port(ip: str, port: int, protocol: str) -> bool | str:
    if protocol == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.2)
        try:
            rc = sock.connect_ex((ip, port))
            return rc == 0
        finally:
            sock.close()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.2)
    try:
        sock.sendto(b"\x00", (ip, port))
        try:
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return "UNKNOWN (Silent)"
    except OSError:
        return False
    finally:
        sock.close()


def calculate_score(statuses: list[str]) -> int:
    if not statuses:
        return 3
    if any("OPEN" in s for s in statuses):
        return 5
    silent_count = sum(1 for s in statuses if "SILENT" in s)
    n = len(statuses)
    if silent_count == 0:
        return 1
    if silent_count >= max(5, (n + 1) // 2):
        return 3
    return 2


def run_audit() -> int:
    public_ip = get_public_ipv4()

    targets: list[tuple[str, str]] = []

    if public_ip:
        targets.append(("Public IPv4 (egress)", public_ip))
    if is_wsl():
        print(
            "\n[WSL2] Public IPv4 reflects NAT egress. 127.0.0.1 is this distro only.\n"
            "       A separate row scans the default gateway (usually the Windows host).\n"
        )
        gw = wsl_windows_host_ip()
        if gw:
            targets.append(("WSL2 gateway (Windows host)", gw))
        else:
            print("[WSL2] Could not read default gateway (ip route / resolv.conf).\n")
    else:
        print("\n[Linux] Scanning public egress and loopback on this host.\n")

    targets.append(("Loopback (this Linux)", "127.0.0.1"))

    all_statuses: list[str] = []

    for label, ip in targets:
        print(f"\n{'=' * 50}\nTarget: {label}\nAddress: {ip}\n{'=' * 50}")
        print(f"{'PORT':<8} {'PROTO':<6} {'SERVICE':<16} {'STATUS'}")
        print("-" * 52)

        for port, proto, name in VPN_PORTS:
            res = check_port(ip, port, proto)
            if res is True:
                status = "OPEN"
            elif res == "UNKNOWN (Silent)":
                status = "SILENT/FILTERED"
            else:
                status = "CLOSED"

            print(f"{port:<8} {proto:<6} {name:<16} {status}")
            all_statuses.append(status)

    score = calculate_score(all_statuses)
    print("\n" + "=" * 50)
    print(f"SCORE: {score}")
    if score == 5:
        status_msg = "VPN/proxy-related port(s) responded OPEN on at least one scan target."
    elif score == 1:
        status_msg = (
            "No OPEN VPN/proxy-related ports; TCP closed and UDP mostly silent/filtered."
        )
    else:
        status_msg = "Inconclusive — mostly UDP silent/filtered; no clear OPEN port."
    # Next line after SCORE should be STATUS for run_all_detections HTML extraction.
    print(f"STATUS: {status_msg}")
    print(
        "  Scale: 1 = no OPEN VPN/proxy ports seen · 5 = at least one OPEN (in use / accepting)"
    )
    print("=" * 50)
    return 0


def main() -> int:
    try:
        return run_audit()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
