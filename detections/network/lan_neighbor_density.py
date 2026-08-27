#!/usr/bin/env python3
"""
LAN neighbor density (ARP / NDP).

Estimates how “lived-in” the local L2 segment looks from neighbor tables.
A typical home LAN has many peers; a hardened lab often sees only the
gateway (and maybe the hypervisor host).

Host-authenticity score:
  1 = rich peer set (many non-gateway neighbors; residential LAN density)
  2 = several peers beyond the gateway
  3 = a few peers (thin home LAN; still some multi-device evidence)
  4 = only 1–2 non-gateway peers, or gateway-only (lab-like sparsity)
  5 = empty neighbor table after stimulation, or only explicit lab/virtual peers
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_local import normalize_mac_colon
from detections.common.common_router_gateway import (
    KNOWN_VIRTUAL_OUI,
    default_ipv4_gateway_linux,
    linux_ping_once,
)
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
MAC_RE = re.compile(r"(?i)(?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2}")


@dataclass
class Neighbor:
    ip: str
    mac: str | None = None
    iface: str | None = None
    state: str = ""
    sources: set[str] = field(default_factory=set)

    @property
    def oui(self) -> str | None:
        if not self.mac:
            return None
        return ":".join(self.mac.split(":")[:3])

    @property
    def virtual_vendor(self) -> str | None:
        oui = self.oui
        if not oui:
            return None
        return KNOWN_VIRTUAL_OUI.get(oui)


def _run(cmd: list[str], *, timeout: float = 8.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (proc.stdout or "") + (proc.stderr or "")


def _iface_subnet(iface: str) -> ipaddress.IPv4Network | None:
    out = _run(["ip", "-o", "-4", "addr", "show", "dev", iface], timeout=4)
    match = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", out)
    if not match:
        return None
    try:
        return ipaddress.ip_interface(match.group(1)).network
    except ValueError:
        return None


def collect_ip_neigh() -> list[Neighbor]:
    rows: dict[str, Neighbor] = {}
    out = _run(["ip", "-4", "neigh", "show"], timeout=5)
    for line in out.splitlines():
        ip_m = IPV4_RE.search(line)
        if not ip_m:
            continue
        ip = ip_m.group(1)
        mac = normalize_mac_colon(line, search=True, reject_broadcast=True)
        iface = None
        dev = re.search(r"\bdev\s+(\S+)", line)
        if dev:
            iface = dev.group(1)
        state = ""
        st = re.search(r"\b(REACHABLE|STALE|DELAY|PROBE|FAILED|INCOMPLETE|PERMANENT|NOARP)\b", line)
        if st:
            state = st.group(1)
        if state == "FAILED" and not mac:
            continue
        rec = rows.setdefault(ip, Neighbor(ip=ip))
        rec.sources.add("ip-neigh")
        if mac:
            rec.mac = mac
        if iface:
            rec.iface = iface
        if state:
            rec.state = state

    # /proc/net/arp fallback
    try:
        text = Path("/proc/net/arp").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        text = ""
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, hw = parts[0], parts[3]
        mac = normalize_mac_colon(hw, reject_broadcast=True)
        if not mac:
            continue
        iface = parts[5] if len(parts) > 5 else None
        rec = rows.setdefault(ip, Neighbor(ip=ip))
        rec.sources.add("proc-arp")
        rec.mac = mac
        if iface:
            rec.iface = iface

    return sorted(rows.values(), key=lambda n: n.ip)


def stimulate_neighbors(gateway: str | None, iface: str | None) -> list[str]:
    notes: list[str] = []
    if gateway:
        linux_ping_once(gateway, iface)
        notes.append(f"ping gateway {gateway}")
    net = _iface_subnet(iface) if iface else None
    if net and net.num_addresses <= 256:
        # Probe a handful of common CPE / client addresses without a full sweep.
        candidates: list[str] = []
        base = int(net.network_address)
        for offset in (1, 2, 10, 20, 50, 100, 150, 200, 254):
            addr = ipaddress.IPv4Address(base + offset)
            if addr in net and str(addr) != gateway:
                candidates.append(str(addr))
        for ip in candidates[:8]:
            _run(["ping", "-c", "1", "-W", "1", ip], timeout=3)
        if candidates:
            notes.append(f"pinged {min(8, len(candidates))} subnet candidates")
    return notes


def score_neighbors(
    neighbors: list[Neighbor],
    gateway: str | None,
) -> tuple[int, str]:
    if not neighbors:
        return (
            5,
            "No ARP/NDP neighbors after stimulation; empty L2 view looks lab-like.",
        )

    gw_peers = [n for n in neighbors if gateway and n.ip == gateway]
    others = [n for n in neighbors if not gateway or n.ip != gateway]
    virtual_others = [n for n in others if n.virtual_vendor]
    physical_others = [n for n in others if not n.virtual_vendor]

    if len(physical_others) >= 5:
        return (
            1,
            f"Rich LAN density: {len(physical_others)} non-gateway peers "
            f"(+{len(gw_peers)} gateway); residential-like neighborhood.",
        )
    if len(physical_others) >= 4:
        return (
            2,
            f"Several LAN peers: {len(physical_others)} non-gateway peers beyond gateway.",
        )
    if len(physical_others) == 3:
        return (
            3,
            f"Only {len(physical_others)} non-gateway peers; thin LAN — "
            "weak residential density.",
        )
    if len(physical_others) == 2:
        return (
            4,
            f"Only {len(physical_others)} non-gateway peers; atypical for a home LAN "
            "(common on minimal lab segments).",
        )
    if physical_others:
        return (
            4,
            f"Sparse LAN: only {len(physical_others)} non-gateway peer; lab-like sparsity.",
        )
    if virtual_others and not physical_others:
        vendors = sorted({n.virtual_vendor or "?" for n in virtual_others})
        return (
            5,
            f"Only virtual-OUI peers ({', '.join(vendors[:3])}); lab/VM neighborhood.",
        )
    if gw_peers and not others:
        return (
            4,
            "Neighbor table has gateway only; typical minimal lab/client segment.",
        )
    return 3, f"Neighbor evidence inconclusive ({len(neighbors)} entr(y/ies))."


def main() -> int:
    ap = argparse.ArgumentParser(description="LAN ARP/NDP neighbor density probe.")
    ap.add_argument("--no-stimulate", action="store_true", help="Do not ping to populate neigh.")
    ap.add_argument("--wait", type=float, default=0.8, help="Seconds to wait after stimulation.")
    args = ap.parse_args()

    print("=== LAN Neighbor Density ===")
    gateway, iface = default_ipv4_gateway_linux()
    print(f"Gateway: {gateway or '(unknown)'}  iface: {iface or '(unknown)'}")

    if not args.no_stimulate:
        notes = stimulate_neighbors(gateway, iface)
        for note in notes:
            print(f"Stimulate: {note}")
        time.sleep(max(0.0, args.wait))
    else:
        print("Stimulate: disabled")

    neighbors = collect_ip_neigh()
    print(f"\nNeighbors: {len(neighbors)}")
    for n in neighbors[:20]:
        mac = n.mac or "-"
        virt = f" [{n.virtual_vendor}]" if n.virtual_vendor else ""
        role = "gateway" if gateway and n.ip == gateway else "peer"
        print(f"  {n.ip:<15} {mac:<17} {role:<7} {n.state or '-'}{virt}")
    if len(neighbors) > 20:
        print(f"  ... {len(neighbors) - 20} more")

    score, status = score_neighbors(neighbors, gateway)
    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
