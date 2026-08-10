#!/usr/bin/env python3

'''
NOTE: To make this script work on WSL, you must set WSL to Mirrored Networking Mode.

mDNS (Multicast DNS) is used by mesh network systems to discover and advertise services (such as web management portals and setup APIs) within the local network, 
allowing devices to resolve names like .local without a centralized DNS server. If a device is designed to be controlled via a smartphone app or 
discovered by a browser without you manually entering an IP address, it is likely using mDNS/DNS-SD.

'''

from __future__ import annotations

import socket
import sys
import time

try:
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf, ZeroconfServiceTypes
except ModuleNotFoundError:
    print(
        "Missing dependency: zeroconf\n"
        "  Alpine:  apk add py3-zeroconf   OR   pip3 install --break-system-packages zeroconf\n"
        "  Host venv: pip install zeroconf   (also installed by install.py)",
        file=sys.stderr,
    )
    raise SystemExit(1) from None

class DeepDiscoveryListener(ServiceListener):
    def __init__(self):
        self.found_names = set()

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name not in self.found_names:
            self.found_names.add(name)
            info = zc.get_service_info(type_, name)
            if info:
                print(f"\n[+] DISCOVERED: {name}")
                print(f"    Type: {type_}")
                addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
                print(f"    IPs:  {addresses} | Port: {info.port}")
                if info.properties:
                    print("    Properties:")
                    for k, v in info.properties.items():
                        # Cleanly decode bytes to strings for the report
                        key_str = k.decode('utf-8', errors='ignore') if isinstance(k, bytes) else k
                        val_str = v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else v
                        print(f"      {key_str}: {val_str}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

def main():
    duration = 60
    print(f"[*] Initializing Robust Global Discovery (Timeout: {duration}seconds)...")
    zc = Zeroconf()
    listener = DeepDiscoveryListener()

    try:
        all_types = list(ZeroconfServiceTypes.find(zc=zc))
    except Exception as e:
        print(f"[-] Error finding service types: {e}")
        all_types = ["_http._tcp.local.", "_services._dns-sd._udp.local."]

    print(f"[*] Found {len(all_types)} potential categories. Filtering and listening...")

    browsers = []
    for service_type in all_types:
        # Filter out the subtype strings that cause the BadTypeInNameException
        if "_sub." in service_type:
            continue
            
        try:
            browsers.append(ServiceBrowser(zc, service_type, listener))
        except Exception:
            # Skip any other weird types that don't conform to standard DNS-SD naming
            continue

    start_time = time.time()
    try:
        while time.time() - start_time < duration:
            remaining = int(duration - (time.time() - start_time))
            print(f"Scanning... {remaining}s left. (Unique Devices: {len(listener.found_names)})", end='\r')
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    finally:
        print("\n\n[*] Scan complete. Cleaning up...")
        zc.close()    
        found = len(listener.found_names)
        if found >= 3:
            score = 1
            status = f"Multiple mDNS/DNS-SD services found ({found}); strong residential LAN evidence."
        elif found > 0:
            score = 2
            status = f"Some mDNS/DNS-SD services found ({found}); weak residential LAN evidence."
        else:
            # Align with mDNS_consumer: empty multicast view is lab-like, not neutral.
            score = 5
            status = (
                "No mDNS/DNS-SD services found; lab-like multicast silence "
                "(lived-in home LANs usually advertise something)."
            )
        print(f"SCORE: {score}")
        print(f"STATUS: {status}")

if __name__ == "__main__":
    main()
