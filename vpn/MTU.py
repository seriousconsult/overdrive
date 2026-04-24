#!/usr/bin/env python3

'''
MTU (Maximum Transmission Unit) Analysis
VPNs wrap your data in an "envelope" (encapsulation). This makes the data packets slightly
 smaller than normal internet packets.
Standard Packet: 1500 bytes.
VPN Packet: Usually 1300 to 1450 bytes.
If a website sees you sending full 1500-byte packets, it knows you are not using a VPN, 
or your VPN is misconfigured.
'''

import subprocess
import re

TUNNEL_PATTERNS = [
    r"^tun", r"^tap", r"^wg", r"^ppp", r"^ipsec", r"^vti", r"^gre"
]

def run(cmd):
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)

def parse_link_mtu():
    # Parse: "2: eth0: <...> mtu 1378 ..."
    out = run(["ip", "-o", "link", "show"])
    records = []
    for line in out.splitlines():
        m_iface = re.match(r"^\d+:\s+([^:]+):", line)
        m_mtu = re.search(r"\bmtu\s+(\d+)\b", line)
        if m_iface and m_mtu:
            iface = m_iface.group(1)
            mtu = int(m_mtu.group(1))
            records.append((iface, mtu))
    return records

def is_tunnel_iface(name: str) -> bool:
    return any(re.match(p, name) for p in TUNNEL_PATTERNS)

def main():
    print("--- MTU + Tunnel Evidence (heuristic) ---")

    records = parse_link_mtu()
    if not records:
        print("Could not parse MTU from `ip link` output.")
        return

    # Heuristic “reduced MTU”
    REDUCED_MIN = 1300
    REDUCED_MAX = 1450

    # Summaries
    tunnel_ifaces = [(i, m) for (i, m) in records if i != "lo" and is_tunnel_iface(i)]
    eth_like = [(i, m) for (i, m) in records if i != "lo" and (i == "eth0" or i.startswith("en"))]

    # Print MTUs
    for iface, mtu in sorted(records, key=lambda x: x[0]):
        if iface == "lo":
            continue

        if is_tunnel_iface(iface):
            status = "🚨 Tunnel interface MTU (strong VPN/tunnel evidence)"
        elif 0 < mtu <= 1500:
            status = f"⚠️ Reduced MTU (not proof; verify with tunnel evidence)"
        else:
            status = "✅ MTU"

        print(f"{iface:10} MTU={mtu:5}  {status}")

    print("\n--- Confidence Summary ---")
    if tunnel_ifaces:
        print(f"High confidence of VPN/tunnel presence: tunnel-like interface(s) detected: {', '.join([i for i,_ in tunnel_ifaces])}")
        if eth_like:
            for i, m in eth_like:
                print(f"Main interface {i} has MTU={m}.")
    else:
        print("Low confidence: No tunnel-like interface names detected.")
        print("Your reduced MTU (e.g., eth0=1378) may be due to WSL/Windows networking virtualization, not necessarily the VPN.")

    # Extra debug: show routes (quick)
    print("\n--- Route Snippet (top lines) ---")
    try:
        routes = run(["ip", "route", "show"]).splitlines()
        for r in routes[:15]:
            print(r)
    except Exception as e:
        print(f"Could not fetch routes: {e}")

if __name__ == "__main__":
    main()
