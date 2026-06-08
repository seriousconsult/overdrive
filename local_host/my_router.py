#!/usr/bin/env python3
"""Report the likely LAN router, model hints, MAC/OUI, and nmap digest."""

from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_local import is_wsl_local
from detections.common.common_router_gateway import (
    is_wsl2_style_nat_gateway,
    mac_from_linux_neigh,
    mac_from_windows,
    resolve_router_ipv4_and_iface,
    vendor_from_mac,
)
from detections.common.common_router_nmap import run_router_nmap_summary
from detections.common.common_router_upnp import fetch_upnp_device_info


def _print_upnp_summary(fields: dict[str, str]) -> None:
    if not fields:
        return
    print("--- Router model (from UPnP device description) ---")
    for key, label in (
        ("manufacturer", "Manufacturer"),
        ("modelname", "Model name"),
        ("modelnumber", "Model number"),
        ("friendlyname", "Friendly name"),
        ("modeldescription", "Description"),
        ("serialnumber", "Serial"),
        ("presentationurl", "Admin URL"),
    ):
        if key in fields:
            print(f"  {label}: {fields[key]}")


def main() -> None:
    try:
        target_ip, iface, via_windows = resolve_router_ipv4_and_iface()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)

    print(f"Using router / gateway IP: {target_ip}" + (f" (iface={iface})" if iface else ""))
    if is_wsl_local() and via_windows:
        print("MAC is read from Windows (Get-NetNeighbor / arp); WSL cannot ARP your LAN router directly.")
    if is_wsl_local() and is_wsl2_style_nat_gateway(target_ip):
        print(
            "Warning: gateway looks like a 172.16-172.31 address (often virtual). "
            "Set MY_MORE_ROUTER_IP if this is not your home router.",
            file=sys.stderr,
        )

    mac = mac_from_windows(target_ip) if is_wsl_local() else mac_from_linux_neigh(target_ip, iface)
    if mac:
        print(f"Router MAC Address: {mac}")
        print(f"OUI vendor / organization: {vendor_from_mac(mac)}")
    else:
        print(
            "Router MAC: not found. Try pinging the gateway first, using the correct interface, "
            "or running from Windows/native Linux.",
            file=sys.stderr,
        )

    raw_xml, upnp_fields = fetch_upnp_device_info(target_ip)
    if upnp_fields:
        _print_upnp_summary(upnp_fields)
    elif raw_xml:
        print("UPnP returned XML but no standard device fields were parsed.", file=sys.stderr)
        if os.environ.get("MY_MORE_UPNP_RAW"):
            print("--- Raw UPnP XML (MY_MORE_UPNP_RAW set) ---")
            print(raw_xml[:8000])
    else:
        print("Router model (UPnP): not available from detections.common description URLs.", file=sys.stderr)

    run_router_nmap_summary(target_ip)


if __name__ == "__main__":
    main()
