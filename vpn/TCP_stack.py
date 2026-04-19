#!/usr/bin/env python3


'''TCP Stack Fingerprinting (Layer 4)

Every OS (Windows, Linux, iOS) handles TCP packets slightly differently
 (initial window size, TTL, etc.). Some VPNs change these values to look like a different OS.
If your IP says "Linux Server" (VPN) but your TCP fingerprint says "iPhone," 
a site may flag you for "Proxy Usage."

Because this is below packet level Python is not the ideal tool.


NOTE:scapy needs sudo however sudo does not use the Python virtual env. So you need to run like this: 
sudo /mnt/c/code/overdrive/virtual_env/bin/python /mnt/c/code/overdrive/vpn/TCP_stack.py
or from the /mnt/c/code/overdrive/vpn/ path:
sudo ../virtual_env/bin/python TCP_stack.py 

'''

from scapy.all import IP, TCP, sr1
import requests


def get_tcp_fingerprint(target_ip):
    packet = IP(dst=target_ip)/TCP(dport=443, flags="S")
    response = sr1(packet, timeout=2, verbose=False)

    if not response:
        print("No response.")
        return

    ttl = response.ttl
    win = response[TCP].window
    opts = response[TCP].options # This is a list of tuples like [('MSS', 1460), ...]

    print(f"RAW: TTL={ttl}, WIN={win}, OPTIONS={opts}")

# Convert options to a string for easier matching
    opt_str = str(opts)

    # 1. The "WSL / Windows-via-Linux" Special Case 
    if (ttl == 63 or ttl == 64) and win == 64240:
        return "Windows 10/11 (Detected via WSL or Linux Bridge)"

    # 2.  Windows Signatures
    if 64 < ttl <= 128:
        if win == 64240:
            if 'WScale' in opt_str:
                return "Windows 10 / Windows 11 / Server 2019"
            return "Windows 10 (Custom/Legacy Stack)"
        if win == 8192:
            return "Windows 7 or Windows Server 2008"
        if win == 65535:
            return "Windows XP / 2000 (Legacy)"

    # 3.  Linux & Mobile Signatures
    if ttl <= 64:
        # Standard Linux
        if win == 29200:
            return "Linux Kernel 3.x+ (Ubuntu/CentOS/Debian)"
        # Google / Android
        if win == 14600:
            return "Android Device / Google Frontend"
        # iOS / macOS
        if win == 65535:
            if 'SAckOK' in opt_str and 'WScale' in opt_str:
                return "iOS (iPhone/iPad) or macOS (Modern)"
            return "FreeBSD / macOS (Older)"
        # Small MSS/Win (often IoT or specialized proxies)
        if win <= 5840:
            return "Embedded Device / IoT or Older Linux 2.4"

    # 4. Infrastructure
    if ttl > 128:
        return "Network Infrastructure (Cisco Router / Juniper Switch)"

    return f"Unknown Fingerprint: TTL={ttl}, WIN={win}"





def get_my_ips():
    print("--- Network Identity Check ---")
    results = {}

    # 1. Get IPv4
    try:
        ipv4 = requests.get('https://api4.ipify.org', timeout=5).text
        results['ipv4'] = ipv4  # <--- CRITICAL: Save the result here!
    except Exception:
        print("IPv4: Not supported or no connection")
        results['ipv4'] = None

    # 2. Get IPv6
    try:
        ipv6 = requests.get('https://api6.ipify.org', timeout=3).text
        results['ipv6'] = ipv6  # <--- CRITICAL: Save the result here!
    except Exception:
        print("IPv6: Not supported")
        results['ipv6'] = None

    return results

if __name__ == "__main__":
    my_data = get_my_ips()
    
    # Check if they exist before printing
    if my_data.get('ipv4'):
        print(f"IP4 found: {my_data['ipv4']}")
        print(get_tcp_fingerprint(my_data['ipv4']))
    
    if my_data.get('ipv6'):
        print(f"IP6 found: {my_data['ipv6']}")
        print(get_tcp_fingerprint(my_data['ipv6']))
