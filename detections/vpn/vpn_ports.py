#!/usr/bin/env python3
"""Port checks for common VPN / proxy ports.

Purpose: Scan egress, loopback, and (on WSL2) default gateway for VPN/proxy-specific TCP/UDP listeners.

Environment: Linux — bare metal, VM, or WSL2. Targets include public IPv4 (NAT egress on WSL2),
127.0.0.1, and WSL2 default gateway (often Windows host vNIC).

Score (1–5): **5** = OPEN VPN/proxy-specific port on at least one target. **1** = no OPEN
VPN/proxy-specific ports. TCP/443 is reported as generic HTTPS and does not score as VPN evidence.
**3** is reserved for cases where no VPN/proxy-specific port observations were available.

Exit code: **0** after completed audit; **130** on Ctrl+C.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_local import is_wsl_local, wsl_windows_host_ip
from detections.common.common_vpn import public_ipv4


VPN_PROXY_SIGNAL = "vpn_proxy"
GENERIC_WEB_SIGNAL = "generic_web"
UNAVAILABLE_STATUS = "UNAVAILABLE"


VPN_PORTS: tuple[tuple[int, str, str, str], ...] = (
    (1194, "udp", "OpenVPN", VPN_PROXY_SIGNAL),
    (51820, "udp", "WireGuard", VPN_PROXY_SIGNAL),
    (443, "tcp", "HTTPS (generic web)", GENERIC_WEB_SIGNAL),
    (1080, "tcp", "SOCKS5", VPN_PROXY_SIGNAL),
    (3128, "tcp", "HTTP proxy", VPN_PROXY_SIGNAL),
    (500, "udp", "IPsec", VPN_PROXY_SIGNAL),
    (4500, "udp", "IPsec NAT-T", VPN_PROXY_SIGNAL),
)


def check_port(ip: str, port: int, protocol: str) -> bool | str:
    if protocol == "tcp":
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            return UNAVAILABLE_STATUS
        sock.settimeout(1.2)
        try:
            rc = sock.connect_ex((ip, port))
            return rc == 0
        finally:
            sock.close()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return UNAVAILABLE_STATUS
    sock.settimeout(1.2)
    try:
        sock.sendto(b"\x00", (ip, port))
        try:
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return "UNKNOWN (Silent)"
    except PermissionError:
        return UNAVAILABLE_STATUS
    except OSError:
        return False
    finally:
        sock.close()


def calculate_score(observations: list[tuple[str, str]]) -> int:
    vpn_statuses = [status for status, signal in observations if signal == VPN_PROXY_SIGNAL]
    usable_statuses = [status for status in vpn_statuses if status != UNAVAILABLE_STATUS]
    if not usable_statuses:
        return 3
    if any(status == "OPEN" for status in usable_statuses):
        return 5
    return 1


def summarize_generic_https(observations: list[tuple[str, str]]) -> str | None:
    https_statuses = [
        status for status, signal in observations if signal == GENERIC_WEB_SIGNAL
    ]
    if any(status == "OPEN" for status in https_statuses):
        return (
            "TCP/443 responded OPEN, but this is generic HTTPS web traffic and is "
            "not counted as VPN/proxy evidence."
        )
    return None


def run_audit() -> int:
    public_ip = public_ipv4()

    targets: list[tuple[str, str]] = []

    if public_ip:
        targets.append(("Public IPv4 (egress)", public_ip))
    if is_wsl_local():
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

    all_observations: list[tuple[str, str]] = []

    for label, ip in targets:
        print(f"\n{'=' * 50}\nTarget: {label}\nAddress: {ip}\n{'=' * 50}")
        print(f"{'PORT':<8} {'PROTO':<6} {'SERVICE':<22} {'STATUS'}")
        print("-" * 58)

        for port, proto, name, signal in VPN_PORTS:
            res = check_port(ip, port, proto)
            if res is True:
                status = "OPEN"
            elif res == "UNKNOWN (Silent)":
                status = "SILENT/FILTERED"
            elif res == UNAVAILABLE_STATUS:
                status = UNAVAILABLE_STATUS
            else:
                status = "CLOSED"

            print(f"{port:<8} {proto:<6} {name:<22} {status}")
            all_observations.append((status, signal))

    score = calculate_score(all_observations)
    print("\n" + "=" * 50)
    print(f"SCORE: {score}")
    if score == 5:
        status_msg = "VPN/proxy-specific port(s) responded OPEN on at least one scan target."
    elif score == 1:
        status_msg = (
            "No OPEN VPN/proxy-specific ports were observed. Generic HTTPS/443 is informational only."
        )
    else:
        status_msg = "Inconclusive — no VPN/proxy-specific port observations were available."
    # Next line after SCORE should be STATUS for detections/run_detections.py HTML extraction.
    print(f"STATUS: {status_msg}")
    https_note = summarize_generic_https(all_observations)
    if https_note:
        print(f"NOTE: {https_note}")
    print(
        "  Scale: 1 = no OPEN VPN/proxy-specific ports seen · 5 = VPN/proxy-specific port OPEN"
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
