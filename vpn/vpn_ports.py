#!/usr/bin/env python3


'''
Port Scanning (Common VPN Ports)

Some aggressive anti-VPN systems (eX. Netflix) will perform a "scan" on your public IP to see if common VPN ports
 are open:
    UDP 1194 (OpenVPN)
    UDP 51820 (WireGuard)
    TCP 443 (Used by obfuscated VPNs)
    TCP 1080 (SOCKS5) 
    TCP 3128 (HTTP Proxy)
    UDP 500 (IPsec)
    UDP 4500 (IPsec NAT-T)


This technique is known as Client-Side Port Scanning (or "In-Browser Port Scanning") and can be done from a website using JavaScript.

"Residential Proxies" where they control a home computer remotely. These proxies usually run on specific ports (e.g., 1080 for SOCKS5 or 3128).

UDP scanning is tricky because of the "silent" nature of open/filtered ports. 

TODO: WSL2 is behind a NAT (Network Address Translation) layer, so it won't see the host's public IP or its open ports directly.
A scan from inside WSL against your Public IP is actually scanning your Router or your VPN Provider, not the Windows host itself. 
To see what a website sees via JavaScript, you would actually need to scan 127.0.0.1 (localhost) from a Windows-based browser.
Since you are in WSL2, if you want to test the "In-Browser JavaScript" scenario accurately, change the public_ip in your script manually to 127.0.0.1.

Because WSL2 uses a virtual network, a scan against your Public IP tests your Router/ISP, but a scan against 127.0.0.1 tests what a malicious
 website can see inside your Browser session.
'''

#!/usr/bin/env python3

import socket
import requests

def calculate_score(results):
    if "🔴 OPEN" in results:
        return 1
    
    # We adjust the threshold slightly because we are scanning two targets
    silent_count = results.count("🟡 SILENT/FILTERED")
    
    if silent_count >= 5: # Adjusted for 10 total checks
        return 2
    if silent_count > 0:
        return 3
    return 5

def check_port(ip, port, protocol='tcp'):
    if protocol == 'tcp':
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        try:
            sock.sendto(b'\x00', (ip, port))
            data, addr = sock.recvfrom(1024)
            return True 
        except socket.timeout:
            return "UNKNOWN (Silent)" 
        except Exception:
            return False

def run_audit():
    try:
        public_ip = requests.get('https://api4.ipify.org', timeout=5).text
    except:
        public_ip = "Error: Could not fetch IP"
    
    targets = [
        ("Public IP", public_ip),
        ("Localhost", "127.0.0.1")
    ]
    
    vpn_ports = [
        (1194, 'udp', 'OpenVPN'),
        (51820, 'udp', 'WireGuard'),
        (443, 'tcp', 'HTTPS/VPN'),
        (500, 'udp', 'IPsec'),
        (4500, 'udp', 'IPsec NAT-T')
    ]

    all_statuses = []

    for label, ip in targets:
        print(f"\nTargeting {label}: {ip}")
        print(f"{'PORT':<8} {'PROTO':<8} {'SERVICE':<15} {'STATUS'}")
        print("-" * 50)

        for port, proto, name in vpn_ports:
            res = check_port(ip, port, proto)
            
            if res is True:
                status = "🔴 OPEN"
            elif res == "UNKNOWN (Silent)":
                status = "🟡 SILENT/FILTERED"
            else:
                status = "🟢 CLOSED"
            
            print(f"{port:<8} {proto:<8} {name:<15} {status}")
            all_statuses.append(status)

    final_score = calculate_score(all_statuses)
    print("\n" + "="*50)
    print(f"SCORE: {final_score}")
    print("="*50)
    
    if final_score <= 2:
        print("🚨 STATUS: HIGH RISK. Services are visible or being intentionally filtered.")
    elif final_score == 5:
        print("✅ STATUS: CLEAN. No VPN signatures detected on public or local interfaces.")

if __name__ == "__main__":
    run_audit()