#!/usr/bin/env python3


'''
Port Scanning (Common VPN Ports)

Some aggressive anti-VPN systems will perform a "scan" on your public IP to see if common VPN ports
 are open:
    UDP 1194 (OpenVPN)
    UDP 51820 (WireGuard)
    TCP 443 (Used by obfuscated VPNs)
'''


#!/usr/bin/env python3
import socket

def check_port(ip, port, protocol='tcp'):
    """Attempts to connect to a specific port to see if it's open."""
    if protocol == 'tcp':
        # TCP check is straightforward: try to connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    else:
        # UDP is "connectionless," making it harder to check. 
        # We send an empty packet and see if it's rejected.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(b'', (ip, port))
            # If we don't get an 'ICMP Port Unreachable' error, 
            # the port *might* be open or filtered.
            data, addr = sock.recvfrom(1024)
            return True
        except socket.timeout:
            # UDP ports often just 'timeout' when open/filtered
            return True 
        except Exception:
            return False

def run_vpn_port_audit():
    # '127.0.0.1' checks your internal listener
    # You can also use your Public IP here to see what the world sees
    target = "127.0.0.1" 
    
    vpn_ports = [
        (1194, 'udp', 'OpenVPN'),
        (51820, 'udp', 'WireGuard'),
        (443, 'tcp', 'SSL/Obfuscated VPN'),
        (500, 'udp', 'IPsec/IKEv2'),
        (4500, 'udp', 'IPsec NAT-T')
    ]

    print(f"🔍 Auditing {target} for VPN signatures...\n")
    print(f"{'PORT':<10} {'PROT':<10} {'SERVICE':<20} {'STATUS'}")
    print("-" * 55)

    for port, proto, name in vpn_ports:
        is_open = check_port(target, port, proto)
        status = "🔴 OPEN (Detected)" if is_open else "🟢 CLOSED"
        print(f"{port:<10} {proto:<10} {name:<20} {status}")

if __name__ == "__main__":
    run_vpn_port_audit()