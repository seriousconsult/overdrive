#!/usr/bin/env python3

import os
import subprocess
import sys
import argparse
import socket

'''
WSL2 operates as a lightweight Virtual Machine (VM) that, by default, uses a NAT-based network topology. This creates an isolation layer
that prevents the Linux environment from participating in broadcast/multicast traffic and obscures its identity on the local LAN. 
To enable WSL to act as a transparent network peer to the Windows host, this script configures Mirrored Networking Mode. 
This allows WSL to share the host's network interfaces directly, enabling critical capabilities like mDNS discovery, IPv6 support, 
and direct LAN accessibility.

To switch to Mirrored Mode (for Recon/mDNS):
python3 this_script.py --enable

To switch back to standard NAT:
python3 python3 this_script.py --disable
'''

def get_windows_user():
    try:
        # Ask Windows directly for the username it's using
        win_user = subprocess.check_output(["cmd.exe", "/c", "echo %USERNAME%"], 
                                          stderr=subprocess.DEVNULL).decode().strip()
        return win_user
    except:
        # If that fails, we can't reliably guess.
        return None

def get_current_mode():
    """Detects mode by inspecting global IPv4 addresses on interfaces."""
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show", "scope", "global"],
            text=True
        )

        ips = set()
        for line in out.splitlines():
            parts = line.split()
            # format: <idx>: <ifname> <fam> <ip>/<prefix> ...
            ip_cidr = parts[3]
            ip = ip_cidr.split("/")[0]
            ips.add(ip)

        if not ips:
            return "UNKNOWN (no global IPv4 IPs found)"

        # Heuristic (tunable):
        # - If we see explicit LAN-ish 192.168.* addresses, likely mirrored.
        # - If we only see private ranges typical of NAT setups, likely NAT.
        if any(ip.startswith("192.168.") for ip in ips):
            return "MIRRORED"
        if any(ip.startswith("172.") for ip in ips):
            return "NAT"

        # Fallback: show what we actually detected
        return f"UNKNOWN ({', '.join(sorted(ips))})"
    except Exception as e:
        return f"ERROR ({str(e)})"


    """Detects mode using Python's native socket library."""
    try:
        # Get the hostname of the machine
        host_name = socket.gethostname()
        # Get all IP addresses associated with this host
        ips = socket.gethostbyname_ex(host_name)[2]
        
        if not ips:
            return "UNKNOWN (No IP found)"

        # Check for the 'tell-tale' NAT range
        for ip in ips:
            if ip.startswith("172."):
                return "NAT"
            if ip.startswith("192.168.1."):
                return "MIRRORED"
        
        return f"UNKNOWN ({ips[0]})"
    except Exception as e:
        return f"ERROR ({str(e)})"
    

def manage_wsl_mode(enable_mirrored=True):
    win_user = get_windows_user()
    if not win_user:
        print("[-] Error: Could not identify Windows user.")
        return

    config_path = f"/mnt/c/Users/{win_user}/.wslconfig"
    
    # Configuration blocks
    if enable_mirrored:
        content = ["[wsl2]\n", "networkingMode=mirrored\n", "dnsTunneling=true\n", "firewall=true\n"]
        mode_label = "MIRRORED"
    else:
        content = ["[wsl2]\n", "networkingMode=nat\n", "dnsTunneling=false\n"]
        mode_label = "NAT"

    try:
        with open(config_path, 'w') as f:
            f.writelines(content)
        print(f"[+] Successfully updated .wslconfig to {mode_label}.")
        print("\n" + "="*50)
        print("ACTION REQUIRED: You must restart WSL for changes to take effect.")
        print("Run 'wsl --shutdown' in PowerShell, then restart your terminal.")
        print("="*50)
    except Exception as e:
        print(f"[-] Failed to write config: {e}")

if __name__ == "__main__":
    # Check if user provided NO arguments
    if len(sys.argv) == 1:
        current = get_current_mode()
        print(f"[*] Current WSL Networking Mode: {current}")
        print("\n[!] No action specified. Please use one of the following:")
        print("    --enable   : Switch to Mirrored Mode")
        print("    --disable  : Revert to NAT Mode (Default)")
        sys.exit(0)

    parser = argparse.ArgumentParser(description="Toggle WSL2 Networking Mode.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--enable', action='store_true')
    group.add_argument('--disable', action='store_true')
    
    args = parser.parse_args()
    manage_wsl_mode(enable_mirrored=args.enable)