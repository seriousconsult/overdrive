#!/usr/bin/env python3
"""
Client VM MAC exposure probe.

Purpose: estimate whether a co-resident observer on the same L2 network, bridge,
or host namespace could learn the client VM's MAC address from Ethernet frames,
ARP/neighbor data, DHCP metadata, bridge forwarding tables, or local interface
metadata.

Host-authenticity score:
  1 = only ordinary physical/residential-looking MACs observed
  2 = MAC addresses are observable, but no virtual-client OUI or lab hostname
  3 = inconclusive; no usable MAC evidence or capture unavailable
  4 = likely virtual MAC observed without strong client attribution
  5 = explicit VM/client MAC exposure, e.g. VirtualBox/QEMU/VMware OUI plus local
      interface, DHCP hostname, or client/lab naming evidence
"""

from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_local import get_repo_root, normalize_mac_colon
from detections.common.common_router_capture import print_sniff_permission_help
from detections.common.common_router_gateway import KNOWN_VIRTUAL_OUI
from detections.common.common_utils import reexec_with_repo_venv


reexec_with_repo_venv(
    get_repo_root(),
    reason="Scapy capture scripts prefer the repo virtualenv Python",
)

IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
LAB_HOST_RE = re.compile(
    r"(?i)(my-alpine-client|overdrive|vbox|virtualbox|qemu|vmware|docker|podman|"
    r"container|lab-client|test-client|openwrt_lan_client|alpine-client|client-vm)"
)

VIRTUAL_OUI = {k.lower(): v for k, v in KNOWN_VIRTUAL_OUI.items()}


@dataclass
class MacEvidence:
    mac: str
    sources: set[str] = field(default_factory=set)
    ifaces: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    hostnames: set[str] = field(default_factory=set)
    dhcp_vendor_classes: set[str] = field(default_factory=set)
    frame_roles: set[str] = field(default_factory=set)
    frame_count: int = 0
    note: str = ""

    @property
    def oui(self) -> str:
        return ":".join(self.mac.split(":")[:3])

    @property
    def virtual_vendor(self) -> str | None:
        return VIRTUAL_OUI.get(self.oui)


def normalize_mac(value: str | bytes | None) -> str | None:
    """MAC normalize for ARP/neigh/pcap lines (search + drop broadcast/zero)."""
    return normalize_mac_colon(value, search=True, reject_broadcast=True)


def add_evidence(
    records: dict[str, MacEvidence],
    mac_value: str | bytes | None,
    source: str,
    *,
    iface: str | None = None,
    ip: str | None = None,
    hostname: str | None = None,
    dhcp_vendor: str | None = None,
    role: str | None = None,
    frame_count: int = 0,
    note: str | None = None,
) -> None:
    mac = normalize_mac(mac_value)
    if not mac:
        return
    rec = records.setdefault(mac, MacEvidence(mac=mac))
    rec.sources.add(source)
    if iface:
        rec.ifaces.add(iface)
    if ip:
        rec.ips.add(ip)
    if hostname:
        rec.hostnames.add(hostname)
    if dhcp_vendor:
        rec.dhcp_vendor_classes.add(dhcp_vendor)
    if role:
        rec.frame_roles.add(role)
    rec.frame_count += frame_count
    if note:
        rec.note = note


def run_command(cmd: list[str], *, timeout: float = 8) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def collect_local_interfaces(records: dict[str, MacEvidence]) -> None:
    sys_class = Path("/sys/class/net")
    if not sys_class.is_dir():
        return
    local_hostname = socket.gethostname().strip() or None
    for path in sorted(sys_class.iterdir(), key=lambda p: p.name):
        iface = path.name
        if iface == "lo":
            continue
        try:
            mac = (path / "address").read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            continue
        if not normalize_mac(mac):
            continue

        ret, out = run_command(["ip", "-o", "-4", "addr", "show", "dev", iface], timeout=4)
        ips = IPV4_RE.findall(out) if ret == 0 else []
        if not ips:
            add_evidence(records, mac, "local-interface", iface=iface, hostname=local_hostname)
        for ip in ips:
            add_evidence(records, mac, "local-interface", iface=iface, ip=ip, hostname=local_hostname)


def collect_ip_neigh(records: dict[str, MacEvidence]) -> None:
    ret, out = run_command(["ip", "neigh", "show"], timeout=6)
    if ret == 0 and out:
        for line in out.splitlines():
            mac = normalize_mac(line)
            if not mac:
                continue
            ip_match = IPV4_RE.search(line)
            iface_match = re.search(r"\bdev\s+(\S+)", line)
            add_evidence(
                records,
                mac,
                "neighbor-table",
                iface=iface_match.group(1) if iface_match else None,
                ip=ip_match.group(0) if ip_match else None,
                note=line.strip(),
            )

    arp = Path("/proc/net/arp")
    if arp.is_file():
        try:
            rows = arp.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
        except OSError:
            rows = []
        for row in rows:
            cols = row.split()
            if len(cols) < 6:
                continue
            ip, _hwtype, flags, mac, _mask, iface = cols[:6]
            if flags == "0x0":
                continue
            add_evidence(records, mac, "arp-cache", iface=iface, ip=ip)


def collect_bridge_fdb(records: dict[str, MacEvidence]) -> None:
    ret, out = run_command(["bridge", "fdb", "show"], timeout=6)
    if ret != 0 or not out:
        return
    for line in out.splitlines():
        mac = normalize_mac(line)
        if not mac:
            continue
        iface_match = re.search(r"\bdev\s+(\S+)", line)
        add_evidence(
            records,
            mac,
            "bridge-fdb",
            iface=iface_match.group(1) if iface_match else None,
            note=line.strip(),
        )


def _decode_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        text = value.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
    else:
        text = str(value).strip()
    if not text:
        return None
    return "".join(ch for ch in text if ch.isprintable())


def _dhcp_options(pkt: Any) -> dict[str, Any]:
    opts: dict[str, Any] = {}
    try:
        raw_opts = pkt["DHCP"].options
    except Exception:
        return opts
    for item in raw_opts:
        if isinstance(item, tuple) and item:
            opts[str(item[0])] = item[1] if len(item) > 1 else None
    return opts


def _observe_packet(records: dict[str, MacEvidence], pkt: Any) -> None:
    try:
        src = normalize_mac(pkt.src)
        dst = normalize_mac(pkt.dst)
    except Exception:
        return

    if src:
        add_evidence(records, src, "ethernet-frame", role="src", frame_count=1)
    if dst:
        add_evidence(records, dst, "ethernet-frame", role="dst", frame_count=1)

    try:
        if pkt.haslayer("ARP"):
            arp = pkt["ARP"]
            add_evidence(records, getattr(arp, "hwsrc", None), "arp-frame", ip=str(getattr(arp, "psrc", "") or ""), role="src")
            add_evidence(records, getattr(arp, "hwdst", None), "arp-frame", ip=str(getattr(arp, "pdst", "") or ""), role="dst")
    except Exception:
        pass

    try:
        if pkt.haslayer("DHCP") and pkt.haslayer("BOOTP"):
            bootp = pkt["BOOTP"]
            mac = normalize_mac(bytes(getattr(bootp, "chaddr", b"") or b"")[:6]) or src
            opts = _dhcp_options(pkt)
            hostname = _decode_text(opts.get("hostname"))
            vendor = _decode_text(opts.get("vendor_class_id"))
            add_evidence(records, mac, "dhcp-client-frame", hostname=hostname, dhcp_vendor=vendor, role="dhcp-client")
    except Exception:
        pass

    try:
        if pkt.haslayer("IP"):
            ip = pkt["IP"]
            if src:
                add_evidence(records, src, "ip-frame", ip=str(ip.src), role="ip-src")
            if dst:
                add_evidence(records, dst, "ip-frame", ip=str(ip.dst), role="ip-dst")
    except Exception:
        pass


def capture_or_read_packets(args: argparse.Namespace, records: dict[str, MacEvidence]) -> tuple[int, bool, str | None]:
    try:
        from scapy.all import conf, rdpcap, sniff
    except ImportError as exc:
        return 0, False, f"Scapy unavailable: {exc}"
    except PermissionError:
        return 0, True, None
    except Exception as exc:
        return 0, False, f"Scapy import failed: {exc}"

    conf.verb = 0
    packets: list[Any] = []
    denied = False
    err: str | None = None

    if args.pcap:
        try:
            packets = list(rdpcap(args.pcap))
        except Exception as exc:
            return 0, False, f"Could not read pcap: {exc}"
    else:
        sniff_kw: dict[str, Any] = {
            "iface": args.iface,
            "filter": args.bpf,
            "store": True,
        }
        if args.count > 0:
            sniff_kw["count"] = args.count
        if args.timeout > 0:
            sniff_kw["timeout"] = args.timeout
        try:
            packets = list(sniff(**sniff_kw))
        except KeyboardInterrupt:
            pass
        except PermissionError:
            denied = True
        except OSError as exc:
            if getattr(exc, "errno", None) in (1, 13):
                denied = True
            else:
                err = str(exc)
        except Exception as exc:
            err = str(exc)

    for pkt in packets:
        _observe_packet(records, pkt)
    return len(packets), denied, err


def classify_record(rec: MacEvidence) -> tuple[int, str, list[str]]:
    reasons: list[str] = []
    virtual_vendor = rec.virtual_vendor
    if virtual_vendor:
        reasons.append(f"virtual OUI {rec.oui.upper()} -> {virtual_vendor}")
    if rec.hostnames:
        reasons.append("hostname(s): " + ", ".join(sorted(rec.hostnames)[:3]))
    if rec.dhcp_vendor_classes:
        reasons.append("DHCP vendor class: " + ", ".join(sorted(rec.dhcp_vendor_classes)[:3]))
    if "local-interface" in rec.sources:
        reasons.append("present on local interface")
    if "dhcp-client-frame" in rec.sources:
        reasons.append("observed as DHCP client")
    if "bridge-fdb" in rec.sources:
        reasons.append("present in bridge forwarding table")
    if rec.frame_count:
        reasons.append(f"{rec.frame_count} Ethernet frame observation(s)")

    lab_name = any(LAB_HOST_RE.search(h or "") for h in rec.hostnames)
    if virtual_vendor and (lab_name or "dhcp-client-frame" in rec.sources):
        return 5, "explicit VM/client MAC exposure", reasons
    if virtual_vendor:
        return 4, "virtual MAC observed on shared network/host data", reasons
    if lab_name:
        return 4, "lab/client hostname observed with non-virtual OUI", reasons
    if rec.sources:
        return 2, "ordinary MAC observable", reasons
    return 3, "no usable evidence", reasons


def score_suite(records: list[MacEvidence]) -> tuple[int, str]:
    if not records:
        return 3, "No MAC evidence collected; capture may be unavailable or the segment was quiet."

    classified = [(classify_record(rec)[0], rec) for rec in records]
    top_score, top = max(classified, key=lambda item: item[0])
    if top_score >= 5:
        return 5, f"Client VM MAC likely exposed: {top.mac} ({top.virtual_vendor or top.oui})."
    if top_score == 4:
        return 4, f"Virtual/lab MAC evidence observed: {top.mac} ({top.virtual_vendor or top.oui})."
    if top_score == 2:
        return 2, f"MAC addresses are observable ({len(records)} unique), but no VM OUI/lab client attribution."
    return 3, "MAC data observed, but not enough to assess client VM exposure."


def _fmt_set(values: set[str], width: int) -> str:
    text = ",".join(sorted(v for v in values if v)[:3]) or "-"
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def main() -> int:
    ap = argparse.ArgumentParser(description="Find VM/client MAC exposure from frames, neighbor data, and host metadata.")
    ap.add_argument("--iface", default=None, help="Interface for live sniffing. Default: Scapy auto.")
    ap.add_argument("--timeout", type=float, default=35.0, help="Live capture seconds. Default 35; 0 means no timeout.")
    ap.add_argument("--count", type=int, default=120, help="Stop after N packets. Default 120; 0 means no limit.")
    ap.add_argument(
        "--bpf",
        default="arp or ip or ip6",
        help="BPF filter for live capture.",
    )
    ap.add_argument("--pcap", default=None, help="Read frames from pcap/pcapng instead of live capture.")
    ap.add_argument("--no-local", action="store_true", help="Do not inspect local interfaces.")
    ap.add_argument("--no-neigh", action="store_true", help="Do not inspect ARP/neighbor tables.")
    ap.add_argument("--no-bridge", action="store_true", help="Do not inspect bridge FDB.")
    args = ap.parse_args()

    records: dict[str, MacEvidence] = {}

    print("=== Client VM MAC Exposure Probe ===")
    print(
        "Observer model: data visible to a host sharing the L2 segment, bridge, "
        "or local namespace with the client."
    )
    if not args.no_local:
        collect_local_interfaces(records)
    if not args.no_neigh:
        collect_ip_neigh(records)
    if not args.no_bridge:
        collect_bridge_fdb(records)

    if args.pcap:
        print(f"Frame input: pcap={args.pcap}")
    else:
        print(
            f"Frame input: live capture iface={args.iface or '(auto)'} "
            f"count={args.count or 'unbounded'} timeout={args.timeout if args.timeout > 0 else 'none'}s"
        )
        print("Hint: DHCP renewals, ARP, ping, or normal browsing create useful frames.")

    packet_count, denied, err = capture_or_read_packets(args, records)
    if denied:
        print_sniff_permission_help()
        print("[!] Live frame capture was denied; continuing with local/neighbor/bridge evidence only.")
    elif err:
        print(f"[!] Frame capture/read note: {err}")

    rows = sorted(records.values(), key=lambda r: (classify_record(r)[0], r.frame_count, r.mac), reverse=True)
    score, status = score_suite(rows)

    print(f"\nFrames read: {packet_count}")
    print(f"Unique MAC candidates: {len(rows)}")

    if rows:
        print("\nCandidates:")
        print(f"{'MAC':<17} {'OUI/VENDOR':<42} {'SCORE':<5} {'SOURCES':<34} {'IPS':<22} HOSTNAMES")
        print("-" * 136)
        for rec in rows[:20]:
            rec_score, label, reasons = classify_record(rec)
            vendor = rec.virtual_vendor or rec.oui.upper()
            print(
                f"{rec.mac:<17} {_fmt_set({vendor}, 42):<42} {rec_score:<5} "
                f"{_fmt_set(rec.sources, 34):<34} {_fmt_set(rec.ips, 22):<22} {_fmt_set(rec.hostnames, 30)}"
            )
            if reasons:
                print(f"  -> {label}: " + "; ".join(reasons[:5]))
    else:
        print("\nNo MAC candidates found.")

    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
