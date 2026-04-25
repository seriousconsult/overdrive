#!/usr/bin/env python3

'''
Many VPNs only tunnel IPv4 traffic. If your ISP provides IPv6, 
your computer might send DNS requests over IPv6 completely outside the VPN tunnel.


Windows Features: Features like "Teredo" or "Smart Multi-Homed Name Resolution" can bypass VPN
 settings to find a "faster" connection.

VPN:  we website see a request coming from a server owned by your VPN provider (e.g., a NordVPN 
or Mullvad server).
Leak: The website sees a request coming from a server owned by your ISP (e.g., Comcast, AT&T, etc.) or a third-party DNS provider (e.g., Google Public DNS, Cloudflare DNS) instead of your VPN.
'''

import requests
import uuid

def run_dns_leak_test():
    session_id = str(uuid.uuid4().hex)[:10]
    api_domain = "bash.ws"
    
    print(f"--- Running DNS Leak Test: Session {session_id} ---")

    # 1. THE TRIGGER & 2. THE REQUEST
    # We hit 10 unique subdomains to force DNS resolution
    for i in range(1, 11):
        try:
            requests.get(f"http://{i}.{session_id}.{api_domain}", timeout=2)
        except:
            pass

    # 3. THE ANSWER & 4. THE REVEAL
    try:
        response = requests.get(f"https://{api_domain}/dnsleak/test/{session_id}?json")
        results = response.json()
        
        has_ipv4_leak = False
        has_ipv6_leak = False
        non_vpn_servers = 0
        total_servers = len(results)

        for server in results:
            is_vpn = server.get('type') == 'vpn'
            ip = server.get('ip', '')
            
            if not is_vpn:
                non_vpn_servers += 1
                if ":" in ip: # Basic check for IPv6
                    has_ipv6_leak = True
                else:
                    has_ipv4_leak = True

        # LOGIC FOR 1-5 SCORE
        score = 0
        message = ""

        if has_ipv4_leak and has_ipv6_leak:
            score = 5
            message = "Certain leak of IPv4 AND IPv6."
        elif has_ipv4_leak and not has_ipv6_leak:
            score = 4
            message = "Certain leak of IPv4."
        elif non_vpn_servers > 0 and non_vpn_servers == total_servers:
            score = 1
            message = "Certain leak (All DNS traffic is public)."
        elif non_vpn_servers > (total_servers / 2):
            score = 3
            message = "Probable leak (Majority of servers are non-VPN)."
        elif non_vpn_servers > 0:
            score = 2
            message = "Possible leak (Mixed results detected)."
        else:
            score = 0 # No leak detected
            message = "Connection secure. No leaks found."

        print("-" * 40)
        print(f"SCORE: {score}")
        print(f"STATUS: {message}")
        print("-" * 40)
        
        return score

    except Exception as e:
        print(f"Error analyzing results: {e}")
        return None

if __name__ == "__main__":
    run_dns_leak_test()