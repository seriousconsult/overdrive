#!/usr/bin/env python3
"""DNS leak probe via bash.ws (IPv4/IPv6 resolver visibility).

Purpose: Detect whether DNS appears to exit through non-VPN / non-provider paths when VPN claims
to tunnel traffic.

Score (1–5), aligned with Overdrive: 1 = no leak pattern observed (best case). 5 = strong
leak signal (IPv4 and/or IPv6 resolvers look non-VPN). Middle scores = mixed or partial exposure.

Environment: Any OS with Python requests and outbound HTTPS; uses third-party bash.ws — rate
limits or blocking yield inconclusive errors.

Exit code: 0 after a completed run (including handled API errors where SCORE 3 is printed). 1 on unexpected failure.
"""

from __future__ import annotations

import sys
import uuid

import requests


def run_dns_leak_test() -> int:
    session_id = str(uuid.uuid4().hex)[:10]
    api_domain = "bash.ws"
    
    print(f"--- Running DNS Leak Test: Session {session_id} ---")

    # 1. THE TRIGGER & 2. THE REQUEST
    # We hit 10 unique subdomains to force DNS resolution
    for i in range(1, 11):
        try:
            requests.get(f"http://{i}.{session_id}.{api_domain}", timeout=2)
        except requests.RequestException:
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
            score = 5
            message = "Certain leak of IPv4."
        elif non_vpn_servers > 0 and non_vpn_servers == total_servers:
            score = 5
            message = "Certain leak (All DNS traffic is public)."
        elif non_vpn_servers > (total_servers / 2):
            score = 4
            message = "Probable leak (Majority of servers are non-VPN)."
        elif non_vpn_servers > 0:
            score = 3
            message = "Possible leak (Mixed results detected)."
        else:
            score = 1
            message = "Connection secure. No leaks found."

        print("-" * 40)
        print(f"SCORE: {score}")
        print(f"STATUS: {message}")
        print("-" * 40)

        return 0

    except Exception as e:
        print(f"Error analyzing results: {e}")
        print("-" * 40)
        print("SCORE: 3")
        print(f"STATUS: Inconclusive — could not complete bash.ws analysis ({e}).")
        print("-" * 40)
        return 1


def main() -> int:
    return run_dns_leak_test()


if __name__ == "__main__":
    sys.exit(main())