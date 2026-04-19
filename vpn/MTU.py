#!/usr/bin/env python3

'''
MTU (Maximum Transmission Unit) Analysis
VPNs wrap your data in an "envelope" (encapsulation). This makes the data packets slightly smaller 
than normal internet packets.
Standard Packet: 1500 bytes.
VPN Packet: Usually 1300 to 1450 bytes.
If a website sees you sending full 1500-byte packets, it knows you are not using a VPN, 
or your VPN is misconfigured.
'''

import subprocess
import re

def get_mtu():
    try:
        # 'ip link' is the modern way to check interface stats
        result = subprocess.check_output(["ip", "link"], stderr=subprocess.STDOUT).decode()
        
        # Find all occurrences of 'mtu' followed by a number
        mtus = re.findall(r'mtu (\d+)', result)
        
        print("--- Interface MTU Analysis ---")
        for i, mtu in enumerate(mtus):
            mtu_val = int(mtu)
            status = "Standard (Likely no VPN)" if mtu_val == 1500 else "🚨 ANOMALY:Reduced (Possible VPN/Tunnel)"
            print(f"Interface {i}: MTU {mtu_val} -> {status}")

    except FileNotFoundError:
        print("Error: The 'ip' command was not found. Are you on Windows without WSL?")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")

if __name__ == "__main__":
    get_mtu()