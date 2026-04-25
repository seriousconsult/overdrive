#!/usr/bin/env python3
"""
Port checks for common VPN / proxy ports

Scans from this Linux environment (works on bare metal, VMs, and WSL2):

- **Public IPv4** — what you get from ipify-style APIs (egress; on WSL2 this is
  the NAT path, not necessarily the Windows host’s own public IP).
- **127.0.0.1** — listeners on *this* Linux instance (WSL distro or native Linux).
- **WSL2 only** — default-route gateway IPv4, which is usually the Windows host
  vNIC (useful cross-check; not identical to “in-browser localhost on Windows”).

UDP ports often look SILENT/FILTERED when no reply is received; that is expected.

Score (this module): **5** = at least one probe saw an **OPEN** VPN/proxy-related
port (or strong response). **1** = **no** OPEN ports; probes look **closed** /
not in use. Middle scores = mostly inconclusive **UDP silent/filtered** results.

Exit: 0 after a completed audit (even if public IP lookup failed for one target).
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys

import requests


VPN_PORTS: tuple[tuple[int, str, str], ...] = (
    (1194, "udp", "OpenVPN"),
    (51820, "udp", "WireGuard"),
    (443, "tcp", "HTTPS/VPN"),
    (1080, "tcp", "SOCKS5"),
    (3128, "tcp", "HTTP proxy"),
    (500, "udp", "IPsec"),
    (4500, "udp", "IPsec NAT-T"),
)


def is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        with open("/proc/version", encoding="utf-8", errors="ignore") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def wsl_windows_host_ip() -> str | None:
    """
    On WSL2, the default IPv4 gateway is typically the Windows host virtual interface.
    """
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0 and out.stdout:
            m = re.search(r"default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})", out.stdout)
            if m:
                return m.group(1)
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    ip = parts[1]
                    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip) and not ip.startswith(
                        "127."
                    ):
                        return ip
    except OSError:
        pass
    return None


def get_public_ipv4() -> str | None:
    candidates = (
        ("https://api4.ipify.org", False),
        ("https://api.ipify.org?format=json", True),
        ("http://ip-api.com/json/?fields=query", True),
    )
    for url, is_json in candidates:
        try:
            r = requests.get(url, timeout=8, headers={"User-Agent": "vpn-ports-audit/1.0"})
            r.raise_for_status()
            if is_json:
                data = r.json()
                ip = data.get("ip") or data.get("query")
            else:
                ip = r.text.strip()
            if ip and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
                return ip
        except (requests.RequestException, ValueError, TypeError, KeyError):
            continue
    return None


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


def run_audit() -> None:
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
    print(
        "  Scale: 1 = no OPEN VPN/proxy ports seen · 5 = at least one OPEN (in use / accepting)")
    print("=" * 50)

    if score == 5:
        print("\nSTATUS: VPN/proxy port(s) responded OPEN on at least one target.")
    elif score == 1:
        print("\nSTATUS: No OPEN ports; all probes closed (no sign those services are listening here).")
    else:
        print("\nSTATUS: Inconclusive — mostly UDP silent/filtered; no clear OPEN.")


if __name__ == "__main__":
    try:
        run_audit()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
