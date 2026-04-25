#!/usr/bin/env python3
 
 
'''
a tunnel interface is a "fake" or virtual network card created by software
 rather than a physical piece of hardware. 


When you connect to a VPN (like OpenVPN or WireGuard), the software tells your operating system: 
"Don't send internet traffic through the Wi-Fi card; send it to this new virtual networkinterface I just created called tun0."


'''


import subprocess
import re

# Common patterns for VPN/Tunnel interfaces
# Added more common providers like Tailscale and ZeroTier
TUNNEL_PATTERNS = [
    r"^tun", r"^tap", r"^wg", r"^ppp", r"^ipsec", r"^vti", r"^gre", 
    r"^tailscale", r"^utun", r"^zt", r"^as0t"
]

def run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except:
        return ""

def get_interfaces():
    # Using -o (oneline) for easier parsing
    out = run(["ip", "-o", "link", "show"])
    ifaces = []
    for line in out.splitlines():
        # Extract the interface name (e.g., 'eth0' from '2: eth0: ...')
        match = re.match(r"^\d+:\s+([^:]+):", line)
        if match:
            ifaces.append(match.group(1).strip())
    return ifaces

def is_tunnel_iface(name: str) -> bool:
    return any(re.match(p, name) for p in TUNNEL_PATTERNS)

def calculate_tunnel_score():
    ifaces = get_interfaces()
    if not ifaces:
        return 3, "No network interfaces enumerated (need `ip link` — e.g. Linux/WSL)."

    # Filter out loopback
    active_ifaces = [i for i in ifaces if i != "lo"]
    
    # Identify tunnels
    detected_tunnels = [i for i in active_ifaces if is_tunnel_iface(i)]
    
    # --- SCORING (1 to 5): higher = stronger tunnel / VPN virtual-iface signal ---
    # 5 = Multiple tunnel-pattern interfaces (strong tunnel environment).
    # 4 = One tunnel-pattern interface (typical single VPN / WireGuard / OpenVPN).
    # 3 = Ambiguous (e.g. many NICs, no name match — containers / complex routing).
    # 2 = Mild uncertainty (reserved / few signals).
    # 1 = No tunnel-pattern interfaces; looks like a normal host (certainly no named tunnel).

    if len(detected_tunnels) > 1:
        score = 5
        status = f"Multiple tunnel interfaces: {', '.join(detected_tunnels)}"
    elif len(detected_tunnels) == 1:
        score = 4
        status = f"Tunnel interface detected: '{detected_tunnels[0]}'"
    elif len(active_ifaces) > 4:
        score = 3
        status = (
            f"No tunnel name patterns matched, but many interfaces ({len(active_ifaces)}) — "
            "possible VM/container or complex routing."
        )
    else:
        score = 1
        status = "No tunnel-pattern interfaces found (tun/tap/wg/…); no VPN-style virtual iface names."

    return score, status

if __name__ == "__main__":
    print("="*50)
    print("TUNNEL INTERFACE ANALYSIS (MTU IGNORED)")
    print("Scale: 1 = no tunnel-pattern NICs · 5 = tunnel(s) detected")
    print("="*50)
    
    score, message = calculate_tunnel_score()
    
    print(f"\nSCORE: {score}")
    print(f"STATUS: {message}")
    print("\n" + "="*50)