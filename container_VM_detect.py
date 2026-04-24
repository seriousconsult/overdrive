#!/usr/bin/env python3
"""
Best-effort VM/Container Likelihood Detector (traffic + local evidence)

Network traffic:
  - Sniffs Ethernet frames (if visible) to observe source MAC OUIs
  - Generates outbound HTTPS requests while sniffing

Local system evidence (not strictly from traffic, but increases accuracy):
  - Container markers: /.dockerenv, /proc/1/cgroup, /run/*container* hints
  - VM markers: /proc/cpuinfo hypervisor flag + DMI product/board names
"""

import argparse
import time
import os
import re
import subprocess
from collections import Counter

import requests
from scapy.all import AsyncSniffer, sniff, Ether, IP, TCP  # type: ignore


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


def mac_to_oui(mac: str) -> str:
    if not mac:
        return ""
    mac = mac.lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 3:
        return ""
    return (parts[0] + parts[1] + parts[2]).lower()


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


def file_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except Exception:
        return False


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def container_evidence():
    evid = []

    if file_exists("/.dockerenv"):
        evid.append("/.dockerenv exists")

    cgroup = read_text("/proc/1/cgroup").lower()
    if any(x in cgroup for x in ["docker", "kubepods", "containerd", "cri-o", "podman", "lxc"]):
        evid.append("/proc/1/cgroup contains container runtime hints")

    for p in ["/run/.containerenv", "/run/containerd", "/var/run/docker.sock"]:
        if file_exists(p):
            evid.append(f"{p} exists")

    ns = read_text("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
    if ns.strip():
        evid.append("Kubernetes serviceaccount namespace present")

    return evid


def vm_evidence():
    evid = []

    cpuinfo = read_text("/proc/cpuinfo").lower()
    if "hypervisor" in cpuinfo:
        evid.append("CPU flags include 'hypervisor'")

    product = read_text("/sys/class/dmi/id/product_name").lower()
    board = read_text("/sys/class/dmi/id/board_name").lower()
    sys_vendor = read_text("/sys/class/dmi/id/sys_vendor").lower()
    dmi_blob = " ".join([product, board, sys_vendor]).strip()

    if any(x in dmi_blob for x in ["vmware", "virtualbox", "kvm", "qemu", "hyper-v", "xen", "parallels", "bhyve"]):
        evid.append(f"DMI product/board/vendor mentions virtualization: {dmi_blob[:120]}")

    if file_exists("/sys/hypervisor/type"):
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

        # L3/L4 (kept, but we won't print TTL/traffic blocks per your request)
        if IP in pkt:
            ip_seen += 1
            ttl_values[int(pkt[IP].ttl)] += 1
        if TCP in pkt:
            tcp_seen += 1
            flags = int(pkt[TCP].flags)
            # SYN bit = 0x02, ACK bit = 0x10
            if (flags & 0x02) and not (flags & 0x10):
                syn_seen += 1

    sniffer = AsyncSniffer(
        iface=iface,
        prn=pkt_handler,
        store=False
    )

    sniffer.start()
    try:
        if not args.no_generate:
            generate_traffic(target=args.target, count=args.gen_count)
        time.sleep(args.seconds)
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    top_ouis = seen_ouis.most_common(8)

    # Evidence scoring
    vm_score = 0
    container_score = 0
    reasons_vm = []
    reasons_container = []

    cont_evid = container_evidence()
    if cont_evid:
        container_score += 5
        reasons_container.extend(cont_evid)

    vm_evid = vm_evidence()
    if vm_evid:
        vm_score += 4
        reasons_vm.extend(vm_evid)

    if local_vendor:
        vm_score += 2
        reasons_vm.append(f"Local NIC OUI maps to {local_vendor} (heuristic)")

    mapped_obs = []
    for oui, cnt in top_ouis:
        v = oui_to_vendor(oui)
        if v:
            mapped_obs.append((v, oui, cnt))
    if mapped_obs:
        vm_score += 1
        reasons_vm.append(
            "Observed traffic OUIs include mapped vendors: " +
            ", ".join([f"{v}({oui})x{cnt}" for v, oui, cnt in mapped_obs[:3]])
        )

    def label_from_score(score, high_threshold, med_threshold):
        if score >= high_threshold:
            return "HIGH"
        if score >= med_threshold:
            return "MEDIUM"
        return "LOW"

    vm_level = label_from_score(vm_score, high_threshold=6, med_threshold=3)
    cont_level = label_from_score(container_score, high_threshold=4, med_threshold=2)

    # --------- Output (trimmed/noise removed per your request) ----------
    print("== Results ==")
    print(f"L2/MAC OUI evidence: Ether frames observed: {ether_seen}")

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

    print(f"\nVM Likelihood (best-effort): {vm_level}")
    if reasons_vm:
        print("Reasons (VM):")
        for r in reasons_vm[:10]:
            print(f"  - {r}")

    print(f"\nContainer Likelihood (best-effort): {cont_level}")
    if reasons_container:
        print("Reasons (Container):")
        for r in reasons_container[:10]:
            print(f"  - {r}")

    print("\nDone.")


if __name__ == "__main__":
    main()