#!/usr/bin/env python3
"""
(Layer 2)
MAC Address OUI: On the same local network, the first half of the device's MAC
 (the OUI) is registered to a manufacturer.

Host-authenticity score: 1 = residential/home-router evidence, 3 = ambiguous,
5 = definitely artificial host.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from typing import Any

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_router_gateway import (
    default_ipv4_gateway,
    normalize_oui,
    try_ip_neigh,
    mac_from_proc_net_arp,
    ping_first,
    resolve_mac,
)

DEFAULT_OUI_MAP: dict[str, str] = {
    "C0:56:27": "NETGEAR",
    "14:CC:20": "TP-LINK",
    "00:24:D1": "ASUS",
    "BC:62:0E": "Sagemcom (ISP equipment - heuristic)",
    "00:14:BF": "Linksys",
    "F4:5C:89": "Apple (often - not a router, but could appear in neighbor cache)",
    "3C:3B:1B": "Cisco/SPA (example - not guaranteed)",
}

# Names that usually indicate home/SOHO router or ISP CPE (heuristic).
ROUTER_LIKELY_VENDOR_SUBSTR = (
    "NETGEAR",
    "TP-LINK",
    "ASUS",
    "Linksys",
    "Sagemcom",
    "Cisco",
)


def vendor_to_score(vendor: str | None, mac_found: bool) -> tuple[int, str]:
    """
    1 - Strong router/CPE vendor match from OUI map.
    2 - MAC seen but weak/ambiguous residential evidence.
    3 - No MAC or unknown target identity.
    4/5 are reserved for artificial-host evidence, which this probe does not produce.
    """
    if not mac_found:
        return 3, "MAC not resolved; cannot confirm residential OUI."
    if not vendor or vendor == "Unknown Manufacturer":
        return 2, "MAC present; OUI not in heuristic map."
    if "Apple" in vendor:
        return 2, "Apple OUI - often a phone/PC; weak router-specific signal."
    if any(s in vendor for s in ROUTER_LIKELY_VENDOR_SUBSTR):
        if any(x in vendor for x in ("NETGEAR", "TP-LINK", "ASUS", "Linksys", "Sagemcom")):
            return 1, f"OUI mapped to router/CPE vendor: {vendor}"
        return 2, f"OUI mapped to network vendor: {vendor}"
    return 2, f"OUI mapped to residential-capable vendor: {vendor}"


def main() -> None:
    ap = argparse.ArgumentParser(description="OUI-only vendor guess from a target IP's MAC (ARP/neighbor).")
    ap.add_argument(
        "--ip",
        default=None,
        help="Target IP on the LAN (e.g., 192.168.1.1). Default: IPv4 default gateway when available.",
    )
    ap.add_argument("--iface", default=None, help="Optional interface (e.g., eth0).")
    ap.add_argument(
        "--oui-map-json",
        default=None,
        help="Optional JSON file mapping 'XX:XX:XX' -> 'Vendor'.",
    )
    ap.add_argument(
        "--ping-first",
        action="store_true",
        help="Ping once (or count) to populate ARP/neighbor cache before lookup.",
    )
    ap.add_argument("--ping-count", type=int, default=1)
    ap.add_argument("--ping-timeout", type=int, default=1)
    ap.add_argument("--retries", type=int, default=3, help="Retry MAC lookup this many times.")
    ap.add_argument("--out-json", default=None, help="Optional path to write evidence JSON.")
    args = ap.parse_args()

    target_ip = args.ip or default_ipv4_gateway()
    if not target_ip:
        print("=== OUI-only Vendor Probe (heuristic) ===")
        print("No target IP (pass --ip or ensure default route is visible to `ip route`).")
        print("-" * 30)
        print("SCORE: 3")
        print("STATUS: No default gateway; residential OUI evidence unavailable.")
        return

    oui_map = DEFAULT_OUI_MAP
    if args.oui_map_json:
        with open(args.oui_map_json, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        oui_map = {normalize_oui(k): v for k, v in loaded.items()}

    evidence: dict[str, Any] = {
        "target_ip": target_ip,
        "timestamp": time.time(),
        "iface": args.iface,
        "mac": None,
        "oui": None,
        "vendor_guess": None,
        "notes": [],
        "errors": [],
    }

    if args.ping_first:
        evidence["notes"].append("ping-first enabled; attempting to populate ARP/neighbor cache")
        ping_first(target_ip, args.iface, args.ping_count, args.ping_timeout)

    mac, resolve_errs = resolve_mac(
        target_ip,
        args.iface,
        max(1, args.retries),
        ping_first_user=False,
    )
    if not mac:
        evidence["errors"].extend(resolve_errs)
        evidence["notes"].append("MAC not found. Device may be offline or ARP/neighbor cache not populated.")
        evidence["vendor_guess"] = None
    else:
        evidence["mac"] = mac
        try:
            oui = normalize_oui(mac)
            evidence["oui"] = oui
            vendor = oui_map.get(oui, "Unknown Manufacturer")
            evidence["vendor_guess"] = vendor
            if vendor != "Unknown Manufacturer":
                evidence["notes"].append("OUI prefix matched known vendor heuristics (probabilistic).")
            else:
                evidence["notes"].append("OUI prefix not in built-in/loaded map; cannot vendor-guess reliably.")
        except Exception as e:
            evidence["errors"].append(str(e))

    score, score_note = vendor_to_score(evidence.get("vendor_guess"), bool(evidence.get("mac")))

    print("=== OUI-only Vendor Probe (heuristic) ===")
    print(f"Target IP: {evidence['target_ip']}")
    if evidence["mac"]:
        print(f"MAC: {evidence['mac']}")
        print(f"OUI: {evidence['oui']}")
        print(f"Vendor guess: {evidence['vendor_guess']}")
    else:
        print("MAC: not found")
    print(f"Heuristic note: {score_note}")
    if evidence["notes"]:
        print("Notes:")
        for n in evidence["notes"]:
            print(f" - {n}")
    if evidence["errors"]:
        print("Errors:")
        for e in evidence["errors"]:
            print(f" - {e}")

    if args.out_json:
        evidence["score"] = score
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)
        print(f"[+] Wrote evidence JSON to: {args.out_json}")

    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {score_note}")


if __name__ == "__main__":
    main()
