#!/usr/bin/env python3
"""
Windows / legacy LAN discovery silence (LLMNR, NBNS, WS-Discovery).

Typical home Windows/Android stacks answer LLMNR (UDP 5355), NetBIOS name
service (UDP 137), and often WS-Discovery (UDP 3702). Hardened Alpine clients
are usually silent.

Host-authenticity score:
  1 = replies on 2+ discovery protocols (strong home/Windows LAN evidence)
  2 = reply on one discovery protocol
  3 = inconclusive (send/recv errors, partial bind failure)
  4 = no replies after stimulated queries (quiet / non-Windows LAN; lab-like)
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import select
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_router_gateway import default_ipv4_gateway_linux

LLMNR_ADDR = "224.0.0.252"
LLMNR_PORT = 5355
NBNS_PORT = 137
WSD_ADDR = "239.255.255.250"
WSD_PORT = 3702


@dataclass
class ProtoResult:
    name: str
    sent: bool
    replies: int
    detail: str


def _dns_name(labels: list[str]) -> bytes:
    out = b""
    for label in labels:
        raw = label.encode("ascii", errors="ignore")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_llmnr_query(name: str = "wpad") -> bytes:
    # Transaction ID + flags(0) + QDCOUNT=1 + AN/NS/AR=0
    header = struct.pack("!HHHHHH", 0x1337, 0x0000, 1, 0, 0, 0)
    question = _dns_name(name.split(".")) + struct.pack("!HH", 1, 1)  # A IN
    return header + question


def _encode_nbns_name(name: str) -> bytes:
    # First-level NetBIOS encoding of up to 15 chars + suffix 0x00 (workstation)
    padded = (name.upper() + " " * 15)[:15] + "\x00"
    encoded = b""
    for ch in padded.encode("ascii", errors="ignore"):
        encoded += bytes([((ch >> 4) & 0xF) + ord("A"), (ch & 0xF) + ord("A")])
    return bytes([32]) + encoded + b"\x00"


def build_nbns_query(name: str = "*") -> bytes:
    header = struct.pack("!HHHHHH", 0x1338, 0x0110, 1, 0, 0, 0)
    # NBNS type NB (0x20), class IN
    question = _encode_nbns_name(name) + struct.pack("!HH", 0x0020, 0x0001)
    return header + question


def build_wsd_probe() -> bytes:
    # Minimal WS-Discovery Probe (UDP).
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        "<soap:Header>"
        "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
        "<wsa:MessageID>urn:uuid:00000000-0000-0000-0000-000000001339</wsa:MessageID>"
        "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>"
        "</soap:Header>"
        "<soap:Body><wsd:Probe/></soap:Body>"
        "</soap:Envelope>"
    )
    return body.encode("utf-8")


def _recv_count(sock: socket.socket, deadline: float) -> int:
    count = 0
    while time.time() < deadline:
        remain = max(0.0, deadline - time.time())
        ready, _, _ = select.select([sock], [], [], min(0.25, remain))
        if not ready:
            continue
        try:
            data, _addr = sock.recvfrom(65535)
        except OSError:
            break
        if data:
            count += 1
    return count


def probe_llmnr(listen_s: float) -> ProtoResult:
    payload = build_llmnr_query("wpad")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        sock.sendto(payload, (LLMNR_ADDR, LLMNR_PORT))
        # Also try a workstation-style name
        sock.sendto(build_llmnr_query("desktop"), (LLMNR_ADDR, LLMNR_PORT))
        replies = _recv_count(sock, time.time() + listen_s)
        sock.close()
        return ProtoResult("LLMNR", True, replies, f"multicast {LLMNR_ADDR}:{LLMNR_PORT}")
    except OSError as exc:
        return ProtoResult("LLMNR", False, 0, f"error: {exc}")


def probe_nbns(broadcast: str, listen_s: float) -> ProtoResult:
    payload = build_nbns_query("*")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        sock.sendto(payload, (broadcast, NBNS_PORT))
        sock.sendto(payload, ("255.255.255.255", NBNS_PORT))
        replies = _recv_count(sock, time.time() + listen_s)
        sock.close()
        return ProtoResult("NBNS", True, replies, f"broadcast {broadcast}:{NBNS_PORT}")
    except OSError as exc:
        return ProtoResult("NBNS", False, 0, f"error: {exc}")


def probe_wsd(listen_s: float) -> ProtoResult:
    payload = build_wsd_probe()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        sock.sendto(payload, (WSD_ADDR, WSD_PORT))
        replies = _recv_count(sock, time.time() + listen_s)
        sock.close()
        return ProtoResult("WS-Discovery", True, replies, f"multicast {WSD_ADDR}:{WSD_PORT}")
    except OSError as exc:
        return ProtoResult("WS-Discovery", False, 0, f"error: {exc}")


def _subnet_broadcast(iface: str | None) -> str:
    if not iface:
        return "255.255.255.255"
    try:
        proc = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        out = proc.stdout or ""
    except (OSError, ValueError):
        return "255.255.255.255"

    match = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", out)
    if not match:
        return "255.255.255.255"
    try:
        return str(ipaddress.ip_interface(match.group(1)).network.broadcast_address)
    except ValueError:
        return "255.255.255.255"


def score_results(results: list[ProtoResult]) -> tuple[int, str]:
    sent_ok = [r for r in results if r.sent]
    hits = [r for r in sent_ok if r.replies > 0]
    errors = [r for r in results if not r.sent]

    if len(hits) >= 2:
        names = ", ".join(f"{r.name}={r.replies}" for r in hits)
        return 1, f"Multiple LAN discovery replies ({names}); strong home/Windows LAN evidence."
    if len(hits) == 1:
        h = hits[0]
        return 2, f"{h.name} replied ({h.replies}); some home/Windows discovery evidence."
    if errors and len(errors) == len(results):
        return 3, "Could not send discovery probes; inconclusive."
    if errors:
        return (
            3,
            "No discovery replies; some probes failed to send — inconclusive silence.",
        )
    if sent_ok and not hits:
        return (
            4,
            "No LLMNR/NBNS/WS-Discovery replies after stimulation; quiet non-Windows LAN "
            "(common on hardened Linux / lab clients).",
        )
    return 3, "LAN discovery probe inconclusive."


def main() -> int:
    ap = argparse.ArgumentParser(description="LLMNR / NBNS / WS-Discovery silence probe.")
    ap.add_argument("--listen", type=float, default=2.5, help="Seconds to listen per protocol.")
    args = ap.parse_args()

    print("=== LAN Discovery Silence (LLMNR / NBNS / WS-Discovery) ===")
    gateway, iface = default_ipv4_gateway_linux()
    broadcast = _subnet_broadcast(iface)
    print(f"Gateway: {gateway or '(unknown)'}  iface: {iface or '(unknown)'}  bcast: {broadcast}")
    print(f"Listen window: {args.listen:.1f}s per protocol\n")

    results = [
        probe_llmnr(args.listen),
        probe_nbns(broadcast, args.listen),
        probe_wsd(args.listen),
    ]
    for r in results:
        status = "REPLY" if r.replies else ("sent" if r.sent else "error")
        print(f"  {r.name:<13} {status:<6} replies={r.replies}  ({r.detail})")

    score, status = score_results(results)
    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
