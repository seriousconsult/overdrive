#!/usr/bin/env python3


'''
Port Scanning (Common VPN Ports)

Some aggressive anti-VPN systems will perform a "scan" on your public IP to see if common VPN ports
 are open:
    UDP 1194 (OpenVPN)
    UDP 51820 (WireGuard)
    TCP 443 (Used by obfuscated VPNs)

TODO: since WSL is a VM, a VPN running on the host and which ports it is using won't show easily. 
However there are ways around this.   
'''

import socket
import requests

def check_port(ip, port, protocol='tcp'):
    if protocol == 'tcp':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    else:
        # UDP is tricky. Realistically, we can only detect if it's CLOSED
        # via an ICMP 'Unreachable' message. If it's silent, it's 'Open|Filtered'.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        try:
            sock.sendto(b'\x00', (ip, port))
            data, addr = sock.recvfrom(1024)
            return True # Got a response! Definitely open.
        except socket.timeout:
            # This is the 'ambiguous' state for UDP
            return "UNKNOWN (Silent)" 
        except Exception:
            return False

def run_audit():
    # Get Public IP to see what the 'World' sees
    try:
        public_ip = requests.get('https://api4.ipify.org', timeout=5).text
    except:
        public_ip = "127.0.0.1"

    vpn_ports = [
        (1194, 'udp', 'OpenVPN'),
        (51820, 'udp', 'WireGuard'),
        (443, 'tcp', 'HTTPS/VPN'),
        (500, 'udp', 'IPsec'),
        (4500, 'udp', 'IPsec NAT-T')
    ]

    print(f"Target: {public_ip}")
    print(f"{'PORT':<8} {'PROTO':<8} {'SERVICE':<15} {'STATUS'}")
    print("-" * 50)

    for port, proto, name in vpn_ports:
        res = check_port(public_ip, port, proto)
        if res is True:
            status = "🔴 OPEN"
        elif res == "UNKNOWN (Silent)":
            status = "🟡 SILENT/FILTERED"
        else:
            status = "🟢 CLOSED"
        print(f"{port:<8} {proto:<8} {name:<15} {status}")

if __name__ == "__main__":
    run_audit()