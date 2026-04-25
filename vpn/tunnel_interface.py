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
        return 3, "No network interfaces detected."

    # Filter out loopback
    active_ifaces = [i for i in ifaces if i != "lo"]
    
    # Identify tunnels
    detected_tunnels = [i for i in active_ifaces if is_tunnel_iface(i)]
    
    # --- SCORING LOGIC (1 to 5) ---
    # 5: Only physical/standard interfaces found.
    # 3: No clear tunnel names, but more than 3 virtual interfaces (suspicious environment).
    # 2: At least one interface matches a known VPN/Tunnel pattern.
    # 1: Multiple tunnel interfaces detected (e.g., tun0 and wg0).

    if len(detected_tunnels) > 1:
        score = 1
        status = f"HIGH RISK: Multiple tunnel interfaces detected: {', '.join(detected_tunnels)}"
    elif len(detected_tunnels) == 1:
        score = 2
        status = f"VPN DETECTED: Found tunnel interface '{detected_tunnels[0]}'"
    elif len(active_ifaces) > 4:
        # Many virtual interfaces (common in complex proxy/container setups)
        score = 3
        status = f"CAUTION: High number of active interfaces ({len(active_ifaces)}). Possible complex routing."
    else:
        score = 5
        status = "CLEAN: No tunnel interfaces detected."

    return score, status

if __name__ == "__main__":
    print("="*50)
    print("TUNNEL INTERFACE ANALYSIS (MTU IGNORED)")
    print("="*50)
    
    score, message = calculate_tunnel_score()
    
    print(f"\nSCORE: {score}")
    print(f"STATUS: {message}")
    print("\n" + "="*50)