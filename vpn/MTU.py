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

#!/usr/bin/env python3

import subprocess
import re

def run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except:
        return ""

def get_min_mtu():
    # Get all link info
    out = run(["ip", "-o", "link", "show"])
    mtus = []
    
    for line in out.splitlines():
        # Skip loopback (lo) because it usually has a massive MTU (65536)
        if " lo " in line:
            continue
            
        m_mtu = re.search(r"\bmtu\s+(\d+)\b", line)
        if m_mtu:
            mtus.append(int(m_mtu.group(1)))
    
    return min(mtus) if mtus else 1500

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
    mtu = get_min_mtu()
    score = calculate_mtu_score(mtu)
    
    print(f"Detected Minimum MTU: {mtu}")
    print("-" * 30)
    print(f"SCORE: {score}")
    
    # Interpretation
    if score == 1:
        status = "Standard packet size. No VPN detected."
    elif score == 2:
        status = "Slightly reduced packet size. Likely local virtualization (WSL/VM)."
    elif score == 3:
        status = "Moderate packet reduction. Likely a tunnel or VPN."
    elif score >= 4:
        status = "Small packet size detected. High certainty of VPN encapsulation."
        
    print(f"ANALYSIS: {status}")

if __name__ == "__main__":
    main()