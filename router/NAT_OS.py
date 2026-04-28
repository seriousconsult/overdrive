#!/usr/bin/env python3

'''
The "NAT" Pattern (Behavioral Analysis) based on operating system
This is the most clever method. Because a router's job is to sit in front of other devices, 
its traffic looks "crowded" compared to a single computer.

The OS Jumble: If one IP address is sending traffic that looks like an iPhone (TTL 64) 
and a Windows PC (TTL 128) simultaneously, the "device" at that IP is almost certainly 
a router performing NAT (Network Address Translation) for a household.
'''

from scapy.all import sniff, IP, TCP
from collections import defaultdict

# Dictionary to track 'fingerprints' seen for each IP
# Structure: { ip: { 'ttls': {64, 128}, 'window_sizes': {set of sizes} } }
network_stats = defaultdict(lambda: {'ttls': set(), 'mss': set()})

def detect_nat_behavior(pkt):
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        ttl = pkt[IP].ttl
        
        # Track TTL values
        network_stats[src_ip]['ttls'].add(ttl)
        
        # Track TCP Maximum Segment Size (MSS) - different OSs use different defaults
        if pkt.haslayer(TCP):
            opts = dict(pkt[TCP].options)
            if 'MSS' in opts:
                network_stats[src_ip]['mss'].add(opts['MSS'])

        # ANALYZE THE GATHERED DATA
        ttls_seen = network_stats[src_ip]['ttls']
        
        # If we see multiple 'starting' TTL signatures from one IP, it's NAT
        # We look for values near 64 (Linux/IoT) AND near 128 (Windows)
        has_linux = any(50 <= t <= 64 for t in ttls_seen)
        has_windows = any(100 <= t <= 128 for t in ttls_seen)
        
        if has_linux and has_windows:
            print(f"\n[!!!] NAT DETECTED: {src_ip}")
            print(f"    Reason: 'OS Jumble' detected.")
            print(f"    Distinct TTLs found: {ttls_seen}")
            print(f"    Distinct TCP MSS values: {network_stats[src_ip]['mss']}")

# Run the sniffer
print("Monitoring for NAT behavioral patterns... (Ctrl+C to stop)")
sniff(prn=detect_nat_behavior, store=0)

