#!/usr/bin/env python3
"""
VM/Container Likelihood Detector (traffic for scoring + informational local evidence)
 - Generates outbound HTTPS requests while sniffing

Unified output: an integer score 1–5.
  1 — Very unlikely VM or container
  5 — Very likely VM or container
  2–4 — increasing uncertainty / strength of evidence that it is a VM

Network traffic (Layer 2 and Layer 3):
  - Sniffs Ethernet frames (if visible) to observe source MAC OUIs. 
  Every Network Interface Card (NIC) has a unique MAC address. 
  The first three bytes are the Organizationally Unique Identifier (OUI), which identifies the manufacturer.
  - Time to Live (TTL) value. When a packet passes through a router or a virtual gateway, its TTL is reduced by 1.
  -Virtual environments, especially containers using overlay networks (like Docker's overlay or Kubernetes' Calico), 
  often have a smaller MTU (e.g., 1450 or 1480) to account for the "tunneling" headers added to the packet.
 
Local system evidence (not strictly from traffic, but for internal self-awareness):
  - Container markers: /.dockerenv, /proc/1/cgroup, /run/*container* hints
  - VM markers: /proc/cpuinfo hypervisor flag + DMI product/board names
  - WSL network mode, WSL is a VM. 

"""

import argparse
import sys
import time
import os
import re
import socket
import subprocess
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import requests

from detections.common.common_local import (
    is_wsl_local,
    mac_to_oui,
    path_exists,
    read_text_file,
)


# Common virtualization OUIs (heuristic; expand as needed).
OUI_VENDOR_MAP = {
    # Hyper-V / Microsoft (commonly 00:15:5D => 00155d)
    "00155d": "Hyper-V",
    "0003ff": "Hyper-V",

    # VMware (common OUIs)
    "000569": "VMware",
    "000c29": "VMware",
    "005056": "VMware",

    # VirtualBox
    "080027": "VirtualBox",

    # Xen
    "00163e": "Xen",

    # KVM/QEMU
    "525400": "KVM/QEMU",
    "525549": "KVM/QEMU",

    # Parallels
    "000f4b": "Parallels",

    # Additional heuristic coverage
    "00a0bb": "VMware (alt/heuristic)",
    "00c0ff": "VMware (alt/heuristic)",
    "00163f": "Xen (alt/heuristic)",
    "001f29": "Virtualization (heuristic)",
    "0023d6": "Virtualization (heuristic)",
}

# Ensure keys are 6 hex chars.
OUI_VENDOR_MAP = {k: v for k, v in OUI_VENDOR_MAP.items()
                  if isinstance(k, str) and re.fullmatch(r"[0-9a-fA-F]{6}", k)}

KNOWN_VIRTUALIZATION_PRODUCTS = (
    "virtualbox",
    "vmware",
    "kvm",
    "qemu",
    "hyper-v",
    "xen",
    "parallels",
    "bhyve",
)


def oui_to_vendor(oui: str):
    if not oui or len(oui) != 6:
        return None
    return OUI_VENDOR_MAP.get(oui)


def get_local_iface_mac(iface: str) -> str:
    """
    Reads local interface MAC from `ip -o link show <iface>`.
    """
    try:
        out = subprocess.check_output(
            ["ip", "-o", "link", "show", iface],
            text=True,
            stderr=subprocess.STDOUT,
        )
        m = re.search(r"link/ether\s+([0-9a-f:]{17})", out.lower())
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def container_evidence():
    evid = []

    if path_exists("/.dockerenv"):
        evid.append("/.dockerenv exists")

    cgroup = read_text_file("/proc/1/cgroup").lower()
    if any(x in cgroup for x in ["docker", "kubepods", "containerd", "cri-o", "podman", "lxc"]):
        evid.append("/proc/1/cgroup contains container runtime hints")

    for p in ["/run/.containerenv", "/run/containerd", "/var/run/docker.sock"]:
        if path_exists(p):
            evid.append(f"{p} exists")

    ns = read_text_file("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
    if ns.strip():
        evid.append("Kubernetes serviceaccount namespace present")

    return evid


def vm_evidence():
    evid = []

    cpuinfo = read_text_file("/proc/cpuinfo").lower()
    if "hypervisor" in cpuinfo:
        evid.append("CPU flags include 'hypervisor'")

    product = read_text_file("/sys/class/dmi/id/product_name").lower()
    board = read_text_file("/sys/class/dmi/id/board_name").lower()
    sys_vendor = read_text_file("/sys/class/dmi/id/sys_vendor").lower()
    dmi_blob = " ".join([product, board, sys_vendor]).strip()

    if any(x in dmi_blob for x in ["vmware", "virtualbox", "kvm", "qemu", "hyper-v", "xen", "parallels", "bhyve"]):
        evid.append(f"DMI product/board/vendor mentions virtualization: {dmi_blob[:120]}")

    if path_exists("/sys/hypervisor/type"):
        evid.append("/sys/hypervisor/type exists")

    return evid


def generate_traffic(target="https://example.com", count=10, delay=0.12):
    """
    Generate outbound traffic while sniffing.
    """
    sess = requests.Session()
    headers = {"User-Agent": "vm-detector/1.0", "Accept": "*/*"}
    for _ in range(count):
        try:
            sess.get(target, headers=headers, timeout=8)
        except Exception:
            pass
        time.sleep(delay)

def check_wsl_networking_mode():
    results = {
        "mode": "Unknown",
        "details": "",
        "is_wsl": False
    }

    # 1. Verify we are actually in WSL
    if not is_wsl_local():
        results["details"] = "Not running inside a WSL environment."
        return results

    results["is_wsl"] = True

    # 2. Try the modern 'wslinfo' tool (Official method)
    try:
        mode_cmd = subprocess.check_output(
            ["wslinfo", "--networking-mode"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        results["mode"] = mode_cmd.upper()
        results["details"] = f"Detected via wslinfo: {mode_cmd}"
        return results
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # 3. Fallback: Heuristic Analysis of IP and Routes
    try:
        # Get default gateway
        route_out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        # NAT usually has a default via 172.x.x.1
        # Mirrored/Bridged usually show the host's actual gateway or no NAT-style route
        
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        if local_ip.startswith("172."):
            results["mode"] = "NAT"
            results["details"] = f"Heuristic: Private NAT IP detected ({local_ip})"
        elif "mirrored" in route_out.lower() or local_ip.startswith("192.168.") or local_ip.startswith("10."):
            # If IP is on a standard LAN range but we are in WSL, it's likely Bridged or Mirrored
            results["mode"] = "MIRRORED or BRIDGED"
            results["details"] = f"Heuristic: LAN-style IP detected ({local_ip}). Run 'wsl.exe --version' to confirm features."
        else:
            results["mode"] = "NAT (Likely)"
            results["details"] = "Standard WSL2 isolation detected."
            
    except Exception as e:
        results["details"] = f"Heuristic check failed: {str(e)}"

    return results


def compute_vm_container_score(
    cont_evid: list,
    vm_evid: list,
    local_vendor: str | None,
    mapped_obs: list,
    ttl_values: Counter,
) -> tuple[int, str, str]:

    has_oui = bool(mapped_obs)
    found_ttl_sig = any(t in {63, 127, 254} for t in ttl_values)
    vm_text = " ".join(str(x).lower() for x in vm_evid)
    cont_text = " ".join(str(x).lower() for x in cont_evid)
    observed_vendor_text = " ".join(str(v).lower() for v, _o, _c in mapped_obs)

    has_dmi_virtual_vendor = any(vendor in vm_text for vendor in KNOWN_VIRTUALIZATION_PRODUCTS)
    has_container_marker = bool(cont_evid) and any(
        marker in cont_text
        for marker in ("dockerenv", "container", "docker", "kubepods", "podman", "lxc", "kubernetes")
    )
    has_local_virtual_nic = bool(local_vendor)
    has_observed_virtualbox = "virtualbox" in observed_vendor_text
    has_observed_vm_oui = bool(mapped_obs)
    observed_total = sum(int(count) for _vendor, _oui, count in mapped_obs)

    # 1. Determine score. Explicit local VM/container markers should win over
    # weaker traffic-only heuristics. VirtualBox/VMware/KVM/etc. in DMI or the
    # local NIC OUI is direct self evidence, not merely an uncertain network hint.
    score = 1
    score_reasons: list[str] = []

    if has_container_marker:
        score = 5
        score_reasons.append("Local container runtime markers are present.")

    if has_dmi_virtual_vendor:
        score = 5
        score_reasons.append("Local DMI identifies a virtualization platform.")

    if has_local_virtual_nic:
        score = 5
        score_reasons.append(f"Local NIC OUI maps to {local_vendor}.")

    if "hypervisor" in vm_text:
        if score < 5:
            score = 4
        score_reasons.append("CPU advertises the hypervisor flag.")

    if "/sys/hypervisor/type exists" in vm_text:
        if score < 5:
            score = 4
        score_reasons.append("/sys/hypervisor/type exists.")

    if has_observed_vm_oui:
        # A dominant VirtualBox OUI on the captured interface is very strong for
        # this local probe, especially when generated traffic is enabled.
        if has_observed_virtualbox or observed_total >= 3:
            if score < 5:
                score = 5
            score_reasons.append("Captured Ethernet source OUIs map to virtual NIC vendors.")
        elif score < 4:
            score = 4
            score_reasons.append("A virtual NIC OUI was observed in local Ethernet traffic.")

    if found_ttl_sig:
        if score >= 4:
            score = 5
        elif score < 3:
            score = 3
        score_reasons.append("TTL hop signatures match common VM/router paths.")

    # 2. Network note (NO local info here)
    network_notes = []

    if score_reasons:
        network_notes.append("Evidence: " + " ".join(score_reasons))

    if has_oui:
        network_notes.append(
            f"Network: Virt-OUIs found ({', '.join([v for v, o, c in mapped_obs[:2]])})."
        )

    if found_ttl_sig:
        trigger_ttls = [t for t in ttl_values if t in {63, 127, 254}]
        network_notes.append(f"Network: Detected 'hop' TTL signatures ({trigger_ttls}).")

    if not has_oui and not found_ttl_sig:
        network_notes.append("Network: No virt-OUIs or TTL anomalies detected.")

    # 3. Local info (returned separately)
    local_info = check_wsl_networking_mode()
    if local_info.get("is_wsl"):
        score = 5
        network_notes.append(
            "Local: Running inside WSL, which is a virtualized environment."
        )
        local_note = f"Local Info: WSL {local_info['mode']} Mode ({local_info['details']})."
    else:
        local_note = f"Local Info: {local_info['details']}"

    alignment = "Clean"
    if score == 5:
        alignment = "VM/Container detected"
    elif score >= 4:
        alignment = "Likely virtualized"
    elif score == 3:
        alignment = "Uncertain"

    return score, f"{alignment}: {' '.join(network_notes)}", local_note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None, help="Interface to sniff on (e.g., eth0).")
    ap.add_argument("--seconds", type=int, default=10, help="Sniff duration seconds.")
    ap.add_argument("--max_packets", type=int, default=5000, help="Max packets to capture.")
    ap.add_argument("--target", default="https://example.com", help="HTTPS target for traffic generation.")
    ap.add_argument("--gen-count", type=int, default=10, help="How many requests during sniff.")
    ap.add_argument("--no-generate", action="store_true", help="Disable traffic generation.")
    args = ap.parse_args()

    iface = args.iface or "eth0"
    scapy_error = ""
    try:
        from scapy.all import AsyncSniffer, Ether, IP, TCP  # type: ignore
    except Exception as exc:
        AsyncSniffer = Ether = IP = TCP = None  # type: ignore[assignment]
        scapy_error = f"{type(exc).__name__}: {exc}"

    local_mac = get_local_iface_mac(iface)
    local_oui = mac_to_oui(local_mac)
    local_vendor = oui_to_vendor(local_oui)

    print("== VM / Container Likelihood Detector ==")
    print(f"Interface:          {iface}")
    print()

    seen_ouis = Counter()
    ether_seen = 0

    ip_seen = 0
    tcp_seen = 0
    syn_seen = 0
    ttl_values = Counter()

    def pkt_handler(pkt):
        nonlocal ether_seen, ip_seen, tcp_seen, syn_seen

        # L2: MAC/OUI evidence
        if Ether in pkt:
            ether_seen += 1
            oui = mac_to_oui(pkt[Ether].src)
            if oui:
                seen_ouis[oui] += 1

        if IP in pkt:
            ip_seen += 1
            # Capture TTLs from outbound packets (those matching your local MAC)
            if Ether in pkt and pkt[Ether].src == local_mac:
                ttl_values[int(pkt[IP].ttl)] += 1
        if TCP in pkt:
            tcp_seen += 1
            flags = int(pkt[TCP].flags)
            # SYN bit = 0x02, ACK bit = 0x10
            if (flags & 0x02) and not (flags & 0x10):
                syn_seen += 1

    sniffer = None
    if AsyncSniffer is not None:
        sniffer = AsyncSniffer(
            iface=iface,
            prn=pkt_handler,
            store=False,
        )
        sniffer.start()
    try:
        if not args.no_generate:
            generate_traffic(target=args.target, count=args.gen_count)
        time.sleep(args.seconds)
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass

    top_ouis = seen_ouis.most_common(8)

    reasons_vm = []
    reasons_container = []

    cont_evid = container_evidence()
    if cont_evid:
        reasons_container.extend(cont_evid)

    vm_evid = vm_evidence()
    if vm_evid:
        reasons_vm.extend(vm_evid)

    if local_vendor:
        reasons_vm.append(f"Local NIC OUI maps to {local_vendor} (heuristic)")

    mapped_obs = []
    for oui, cnt in top_ouis:
        v = oui_to_vendor(oui)
        if v:
            mapped_obs.append((v, oui, cnt))
    if mapped_obs:
        reasons_vm.append(
            "Observed traffic OUIs include mapped vendors: " +
            ", ".join([f"{v}({oui})x{cnt}" for v, oui, cnt in mapped_obs[:3]])
        )

    score, unified_note, local_note = compute_vm_container_score(
    cont_evid,
    vm_evid,
    local_vendor,
    mapped_obs,
    ttl_values
    )

    # --------- Output (trimmed/noise removed per your request) ----------
    print("== Results ==")
    print(f"SCORE: {score}")
    print(f"  ({unified_note})")
    print()
    print(f"L2/MAC OUI evidence: Ether frames observed: {ether_seen}")
    if scapy_error:
        print(f"Packet capture unavailable: {scapy_error}")

    if top_ouis:
        print("Top observed OUIs (from captured Ethernet src MACs):")
        for oui, cnt in top_ouis:
            vendor = oui_to_vendor(oui)
            if vendor:
                print(f"  - {oui} => {vendor} (seen {cnt})")
            else:
                print(f"  - {oui} (vendor not mapped; seen {cnt})")
    else:
        print("Top observed OUIs: none")

    if reasons_vm:
        print("\nSupporting detail (VM / network hints):")
        for r in reasons_vm[:10]:
            print(f"  - {r}")

    print("\nSupporting detail (Local / WSL networking mode):")
    print(f"  - {local_note}")

    if reasons_container:
        print("\nSupporting detail (container hints):")
        for r in reasons_container[:10]:
            print(f"  - {r}")

    return score


if __name__ == "__main__":
    main()
