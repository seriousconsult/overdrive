#!/usr/bin/env python3
'''
(Layer 2)
MAC Address OUI: If you are on the same local network, the first half of the device's 
MAC address (the OUI) is registered to a manufacturer. A MAC starting with C0:56:27 
immediately tells you, "I am a NETGEAR device."
'''

import argparse
import json
import re
import subprocess
import time
from typing import Dict, Any, Optional

from getmac import get_mac_address

# Router/consumer networking vendor OUI prefixes (heuristic list; tune as desired)
DEFAULT_OUI_MAP: Dict[str, str] = {
    "C0:56:27": "NETGEAR",
    "14:CC:20": "TP-LINK",
    "00:24:D1": "ASUS",
    "BC:62:0E": "Sagemcom (ISP equipment - heuristic)",
    "00:14:BF": "Linksys",
    # Common consumer/ISP gear (examples; extend with your own needs)
    "F4:5C:89": "Apple (often - not a router, but could appear in neighbor cache)",
    "3C:3B:1B": "Cisco/SPA (example - not guaranteed)",
}

def normalize_oui(mac: str) -> str:
    # Accept forms like "C0:56:27:12:34:56" or "c0-56-27-12-34-56"
    mac = mac.strip().upper()
    mac = mac.replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 3:
        raise ValueError(f"Bad MAC format: {mac!r}")
    return f"{parts[0]}:{parts[1]}:{parts[2]}"

def try_ip_neigh(ip: str) -> Optional[str]:
    """
    Best-effort neighbor lookup using iproute2 (Linux/WSL).
    Requires: `ip neigh`.
    """
    try:
        # Example output line:
        # 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        proc = subprocess.run(
            ["ip", "neigh", "show", "to", ip],
            capture_output=True,
            text=True,
            check=False,
        )
        out = (proc.stdout or "").strip()
        if not out:
            return None

        # Extract lladdr MAC
        m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
        if m:
            return m.group(1)
        # Sometimes appears as "PERMANENT" etc; try more generally:
        m2 = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", out)
        if m2:
            return out[m2.start():m2.end()]
        return None
    except Exception:
        return None

def ping_first(ip: str, iface: Optional[str], count: int, timeout_s: int) -> None:
    cmd = ["ping", "-c", str(count), "-W", str(timeout_s), ip]
    if iface:
        cmd = ["ping", "-I", iface, "-c", str(count), "-W", str(timeout_s), ip]
    subprocess.run(cmd, capture_output=True, text=True, check=False)

def main():
    ap = argparse.ArgumentParser(description="OUI-only vendor guess from a target IP's MAC (ARP/neighbor).")
    ap.add_argument("--ip", required=True, help="Target IP on the LAN (e.g., 192.168.1.1).")
    ap.add_argument("--iface", default=None, help="Optional interface (e.g., eth0).")
    ap.add_argument("--oui-map-json", default=None,
                    help="Optional JSON file mapping 'XX:XX:XX' -> 'Vendor'.")
    ap.add_argument("--ping-first", action="store_true",
                    help="Ping once (or count) to populate ARP/neighbor cache before lookup.")
    ap.add_argument("--ping-count", type=int, default=1)
    ap.add_argument("--ping-timeout", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=2,
                    help="Timeout used by MAC lookup / retries (heuristic).")
    ap.add_argument("--retries", type=int, default=3, help="Retry MAC lookup this many times.")
    ap.add_argument("--out-json", default=None, help="Optional path to write evidence JSON.")
    args = ap.parse_args()

    oui_map = DEFAULT_OUI_MAP
    if args.oui_map_json:
        with open(args.oui_map_json, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        # normalize keys
        oui_map = {normalize_oui(k): v for k, v in loaded.items()}

    evidence: Dict[str, Any] = {
        "target_ip": args.ip,
        "timestamp": time.time(),
        "iface": args.iface,
        "mac": None,
        "oui": None,
        "vendor_guess": None,
        "confidence": 0,
        "notes": [],
        "errors": [],
    }

    if args.ping_first:
        evidence["notes"].append("ping-first enabled; attempting to populate ARP/neighbor cache")
        ping_first(args.ip, args.iface, args.ping_count, args.ping_timeout)

    mac = None
    # Retry: MAC lookup often fails until neighbor cache is populated.
    for _ in range(max(1, args.retries)):
        try:
            mac = get_mac_address(ip=args.ip, interface=args.iface)
        except Exception as e:
            evidence["errors"].append(f"getmac error: {e}")
            mac = None

        if mac:
            break

        # Fallback to `ip neigh`
        mac_neigh = try_ip_neigh(args.ip)
        if mac_neigh:
            mac = mac_neigh
            break

        time.sleep(0.3)

    if not mac:
        evidence["notes"].append("MAC not found. Device may be offline or ARP/neighbor cache not populated.")
        evidence["confidence"] = 0
    else:
        evidence["mac"] = mac
        try:
            oui = normalize_oui(mac)
            evidence["oui"] = oui
            vendor = oui_map.get(oui, "Unknown Manufacturer")
            evidence["vendor_guess"] = vendor

            # Confidence is intentionally heuristic.
            # Exact OUI prefix match => higher confidence.
            evidence["confidence"] = 7 if vendor != "Unknown Manufacturer" else 1

            if vendor != "Unknown Manufacturer":
                evidence["notes"].append("OUI prefix matched known vendor heuristics (probabilistic).")
            else:
                evidence["notes"].append("OUI prefix not in built-in/loaded map; cannot vendor-guess reliably.")
        except Exception as e:
            evidence["errors"].append(str(e))

    # Print result
    print("=== OUI-only Vendor Probe (heuristic) ===")
    print(f"Target IP: {evidence['target_ip']}")
    if evidence["mac"]:
        print(f"MAC: {evidence['mac']}")
        print(f"OUI: {evidence['oui']}")
        print(f"Vendor guess: {evidence['vendor_guess']}")
    else:
        print("MAC: not found")
    print(f"Confidence (heuristic): {evidence['confidence']}")
    if evidence["notes"]:
        print("Notes:")
        for n in evidence["notes"]:
            print(f" - {n}")
    if evidence["errors"]:
        print("Errors:")
        for e in evidence["errors"]:
            print(f" - {e}")

    # Optional JSON output
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)
        print(f"[+] Wrote evidence JSON to: {args.out_json}")

if __name__ == "__main__":
    main()