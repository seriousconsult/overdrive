#!/usr/bin/env python3
"""
(Layer 2)
MAC Address OUI: On the same local network, the first half of the device's MAC
 (the OUI) is registered to a manufacturer.
Unified likelihood score **1–5** (aligned with Overdrive): 
**higher** = stronger signal that the target looks like consumer 
router / CPE gear from OUI heuristics.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from typing import Any

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


def default_ipv4_gateway() -> str | None:
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0 and out.stdout:
            m = re.search(r"default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})", out.stdout)
            if m:
                return m.group(1)
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def normalize_oui(mac: str) -> str:
    mac = mac.strip().upper()
    mac = mac.replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 3:
        raise ValueError(f"Bad MAC format: {mac!r}")
    return f"{parts[0]}:{parts[1]}:{parts[2]}"


def try_ip_neigh(ip: str, iface: str | None = None) -> str | None:
    try:
        cmd = ["ip", "neigh", "show", "to", ip]
        if iface:
            cmd.extend(["dev", iface])
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        out = (proc.stdout or "").strip()
        if not out:
            return None

        m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
        if m:
            return m.group(1).lower()
        m2 = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", out)
        if m2:
            return out[m2.start() : m2.end()].lower()
        return None
    except Exception:
        return None


def mac_from_proc_net_arp(ip: str) -> str | None:
    """Linux neighbor table as seen by the kernel (no extra packages)."""
    try:
        with open("/proc/net/arp", encoding="utf-8", errors="ignore") as f:
            f.readline()  # header
            for line in f:
                cols = line.split()
                if len(cols) < 4:
                    continue
                row_ip, _hwtype, flags, hw_addr = cols[0], cols[1], cols[2], cols[3]
                if row_ip != ip:
                    continue
                if flags == "0x0":
                    continue
                if hw_addr == "00:00:00:00:00:00":
                    continue
                if re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", hw_addr, re.I):
                    return hw_addr.lower()
    except OSError:
        pass
    return None


def ping_first(ip: str, iface: str | None, count: int, timeout_s: int) -> None:
    cmd = ["ping", "-c", str(count), "-W", str(timeout_s), ip]
    if iface:
        cmd = ["ping", "-I", iface, "-c", str(count), "-W", str(timeout_s), ip]
    subprocess.run(cmd, capture_output=True, text=True, check=False)


def resolve_mac(ip: str, iface: str | None, retries: int, ping_first_user: bool) -> tuple[str | None, list[str]]:
    """
    Try ip neigh + /proc/net/arp; optionally ping to populate the neighbor cache between attempts.
    Returns (mac or None, error strings for diagnostics).
    """
    errs: list[str] = []
    n = max(1, retries)
    for attempt in range(n):
        if ping_first_user and attempt == 0:
            ping_first(ip, iface, 1, 1)

        mac = try_ip_neigh(ip, iface) or mac_from_proc_net_arp(ip)
        if mac:
            return mac, errs

        if attempt < n - 1:
            ping_first(ip, iface, 1, 1)
            time.sleep(0.3)
        else:
            errs.append("No MAC from ip neigh or /proc/net/arp after probes.")

    return None, errs


def vendor_to_score(vendor: str | None, mac_found: bool) -> tuple[int, str]:
    """
    5 — Strong router/CPE vendor match from OUI map.
    4 — Router-like vendor string.
    3 — Ambiguous (e.g., Apple).
    2 — MAC seen but unknown OUI.
    1 — No MAC / cannot assess.
    """
    if not mac_found:
        return 1, "MAC not resolved; cannot score OUI."
    if not vendor or vendor == "Unknown Manufacturer":
        return 2, "MAC present; OUI not in heuristic map."
    if "Apple" in vendor:
        return 3, "Apple OUI — often a phone/PC; weak router-specific signal."
    if any(s in vendor for s in ROUTER_LIKELY_VENDOR_SUBSTR):
        if any(x in vendor for x in ("NETGEAR", "TP-LINK", "ASUS", "Linksys", "Sagemcom")):
            return 5, f"OUI mapped to router/CPE vendor: {vendor}"
        return 4, f"OUI mapped to network vendor: {vendor}"
    return 3, f"OUI mapped to: {vendor}"


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
        print("SCORE: 1")
        print(" No default gateway; probe skipped.")
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
