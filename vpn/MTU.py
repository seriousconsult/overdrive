#!/usr/bin/env python3

'''
MTU (Maximum Transmission Unit) Analysis
VPNs wrap your data in an "envelope" (encapsulation). This makes the data packets slightly
 smaller than normal internet packets.
Standard Packet: 1500 bytes.
VPN Packet: Usually 1300 to 1450 bytes.
If a website sees you sending full 1500-byte packets, it suspects you are not using a VPN, 
or your VPN is misconfigured.
'''

#!/usr/bin/env python3

import subprocess
import re
import os

def run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except:
        return ""

def _is_tunnelish_iface(name: str) -> bool:
    n = (name or "").lower()
    if not n:
        return False
    if n == "lo":
        return False
    # Common virtual tunnel interfaces (not exhaustive, but high signal for VPN-ish stacks on Linux)
    if n.startswith(("tun", "tap", "wg", "ipsec", "ppp", "l2tp", "gtp", "gretap", "erspan", "veth", "docker", "br-", "virbr")):
        return True
    return "vpn" in n


def get_link_mtu_info():
    """
    Parse `ip -o link show` and return:
    - min_mtu: minimum MTU across non-loopback interfaces
    - tunnel_ifaces: (iface, mtu) for interfaces that look VPN/tunnel related

    Notes:
    - This is **local** link MTU, not "path MTU" to a remote website.
    - Many commercial VPNs still show 1500 on the default route interface; the tunnel may
      have a private name or may not be visible depending on how the VPN is integrated.
    """
    out = run(["ip", "-o", "link", "show"])
    mtus: list[int] = []
    tunnel: list[tuple[str, int]] = []

    for line in out.splitlines():
        m_if = re.match(r"^\d+:\s*(\S+)@", line) or re.match(r"^\d+:\s*(\S+):", line)
        iface = m_if.group(1) if m_if else ""
        if iface == "lo":
            continue

        m_mtu = re.search(r"\bmtu\s+(\d+)\b", line)
        if not m_mtu:
            continue
        mtu = int(m_mtu.group(1))
        mtus.append(mtu)
        if _is_tunnelish_iface(iface):
            tunnel.append((iface, mtu))

    min_mtu = min(mtus) if mtus else 1500
    return min_mtu, tunnel


def get_min_mtu():
    min_mtu, _tunnel = get_link_mtu_info()
    return min_mtu

def calculate_mtu_score(mtu):
    """
    Score Map:
    1: 1500 (Standard Ethernet/No VPN)
    2: 1451 - 1499 (Possible slight overhead/Virtualization)
    3: 1421 - 1450 (Probable overhead/Some Tunnels)
    4: 1351 - 1420 (Strong VPN signature - Wireguard/OpenVPN)
    5: <= 1350 (Heavy encapsulation - Double VPN or high overhead)
    """
    if mtu >= 1500:
        return 1
    elif mtu > 1450:
        return 2
    elif mtu > 1420:
        return 3
    elif mtu > 1350:
        return 4
    else:
        return 5

def main():
    mtu, tunnel_ifaces = get_link_mtu_info()
    score = calculate_mtu_score(mtu)
    on_wsl = False
    try:
        on_wsl = "microsoft" in (open("/proc/version", "r", encoding="utf-8", errors="ignore").read().lower())
    except Exception:
        on_wsl = bool(os.environ.get("WSL_DISTRO_NAME"))
    
    print(f"Detected Minimum MTU: {mtu}")
    if tunnel_ifaces:
        tshow = ", ".join(f"{n}={m}" for n, m in sorted(tunnel_ifaces, key=lambda x: x[0].lower())[:20])
        more = "" if len(tunnel_ifaces) <= 20 else f" … (+{len(tunnel_ifaces) - 20} more)"
        print(f"Tunnel/VPN-ish interfaces (heuristic): {tshow}{more}")
    if on_wsl:
        print("Note: WSL2 networking can hide host VPN/tunnel interfaces from the Linux namespace; treat MTU as a weak signal.")
    print("-" * 30)
    print(f"SCORE: {score}")
    # Same pattern as timing_latency.py: first short line after SCORE is what run_all_detections uses as the table comment.
    print(" Measured via: ip -o link show (local link MTU; not path MTU to a remote host)")
    print(f" Minimum link MTU observed: {mtu}")
    
    # Interpretation
    if score == 1:
        status = (
            "Standard local link MTU (often 1500 on Ethernet). This does **not** prove you are not using a VPN; "
            "many VPNs do not show up as a reduced MTU on the interface this script can see, and WSL can obscure host tunnels."
        )
    elif score == 2:
        status = "Slightly reduced packet size. Likely local virtualization (WSL/VM) or light overhead; still not definitive for VPNs."
    elif score == 3:
        status = "Moderate packet reduction. Suggestive of a tunnel, VPN, or custom network stack, but not definitive alone."
    elif score >= 4:
        status = "Small packet size detected. Strong signal of encapsulation/tunneling on at least one visible interface, but not a full attribution."
        
    print(f"STATUS: {status}")

if __name__ == "__main__":
    main()