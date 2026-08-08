#!/usr/bin/env python3
"""
DHCP client fingerprinting from visible LAN traffic.

The probe observes DHCP client packets and fingerprints each client using:
  - DHCP wire option order
  - Parameter Request List order (option 55)
  - Vendor Class Identifier (option 60)
  - Hostname (option 12)

Live capture actively renews the local OS DHCP client during the sniff window
so quiet lease intervals still produce authentic client packets (not crafted
Scapy DHCP, which would poison option-order fingerprints).

Host-authenticity score:
  1 = common residential/client device fingerprints observed
  2 = DHCP clients observed but classification is weak or generic
  3 = inconclusive, usually no DHCP packets captured
  4 = likely lab/VM/container naming or synthetic DHCP behavior
  5 = explicit lab/VM/container DHCP identity
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

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

try:
    from scapy.all import BOOTP, DHCP, Ether, IP, conf, rdpcap, sniff
    conf.verb = 0
    SCAPY_IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - depends on runtime environment
    BOOTP = DHCP = Ether = IP = None  # type: ignore[assignment]
    rdpcap = sniff = None  # type: ignore[assignment]
    SCAPY_IMPORT_ERROR = str(exc)


VIRTUAL_OUI = {k.lower(): v for k, v in KNOWN_VIRTUAL_OUI.items()}


DHCP_CLIENT_MESSAGE_TYPES = {
    "discover",
    "request",
    "decline",
    "release",
    "inform",
}

DHCP_OPTION_CODES: dict[str, int] = {
    "subnet_mask": 1,
    "time_zone": 2,
    "router": 3,
    "time_server": 4,
    "ien_name_server": 5,
    "name_server": 6,
    "log_server": 7,
    "hostname": 12,
    "domain": 15,
    "interface_mtu": 26,
    "broadcast_address": 28,
    "static_routes": 33,
    "ntp_servers": 42,
    "vendor_specific": 43,
    "netbios_name_server": 44,
    "netbios_dd_server": 45,
    "netbios_node_type": 46,
    "netbios_scope": 47,
    "requested_addr": 50,
    "lease_time": 51,
    "message-type": 53,
    "server_id": 54,
    "param_req_list": 55,
    "max_dhcp_size": 57,
    "renewal_time": 58,
    "rebinding_time": 59,
    "vendor_class_id": 60,
    "client_id": 61,
    "tftp_server_name": 66,
    "bootfile_name": 67,
    "user_class": 77,
    "fqdn": 81,
    "client_architecture": 93,
    "client_network_interface": 94,
    "client_machine_identifier": 97,
    "domain_search": 119,
    "classless_static_routes": 121,
    "private_classless_static_routes": 249,
    "proxy_autodiscovery": 252,
}

DHCP_CODE_NAMES = {
    1: "subnet-mask",
    3: "router",
    6: "dns",
    12: "hostname",
    15: "domain",
    26: "mtu",
    28: "broadcast",
    33: "static-routes",
    42: "ntp",
    43: "vendor-specific",
    44: "netbios-ns",
    46: "netbios-node",
    47: "netbios-scope",
    50: "requested-ip",
    51: "lease-time",
    53: "message-type",
    54: "server-id",
    55: "param-request-list",
    57: "max-dhcp-size",
    58: "renewal-time",
    59: "rebinding-time",
    60: "vendor-class",
    61: "client-id",
    66: "tftp-server",
    67: "bootfile",
    77: "user-class",
    81: "fqdn",
    93: "client-arch",
    94: "client-net-iface",
    97: "machine-id",
    119: "domain-search",
    121: "classless-routes",
    249: "ms-classless-routes",
    252: "wpad",
}


@dataclass
class DhcpObservation:
    ts: float
    mac: str
    message_type: str
    ip_src: str | None
    requested_ip: str | None
    hostname: str | None
    vendor_class: str | None
    client_id: str | None
    option_order: tuple[str, ...]
    option_codes: tuple[int | str, ...]
    requested_options: tuple[int, ...]


@dataclass
class FingerprintResult:
    mac: str
    packet_count: int
    message_types: Counter[str] = field(default_factory=Counter)
    hostnames: Counter[str] = field(default_factory=Counter)
    vendor_classes: Counter[str] = field(default_factory=Counter)
    requested_ips: Counter[str] = field(default_factory=Counter)
    option_orders: Counter[tuple[int | str, ...]] = field(default_factory=Counter)
    requested_option_orders: Counter[tuple[int, ...]] = field(default_factory=Counter)
    device_type: str = "Unknown DHCP client"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    device_score: int = 3


@dataclass
class LocalInterfaceIdentity:
    iface: str
    mac: str
    ipv4: tuple[str, ...] = ()
    virtual_vendor: str | None = None


@dataclass
class LocalDhcpIdentity:
    hostname: str | None = None
    os_release: str | None = None
    dhcp_clients: list[str] = field(default_factory=list)
    interfaces: list[LocalInterfaceIdentity] = field(default_factory=list)
    lease_files: list[str] = field(default_factory=list)
    lease_hints: list[str] = field(default_factory=list)
    score: int = 3
    classification: str = "No local DHCP identity evidence"
    evidence: list[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return bool(
            self.hostname
            or self.os_release
            or self.dhcp_clients
            or self.interfaces
            or self.lease_files
            or self.lease_hints
        )


def _decode_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        cleaned = value.split(b"\x00", 1)[0]
        text = cleaned.decode("utf-8", errors="replace").strip()
    else:
        text = str(value).strip()
    if not text:
        return None
    return "".join(ch for ch in text if ch.isprintable())


def _decode_client_id(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return ":".join(f"{b:02x}" for b in value)
    return _decode_text(value)


def _bootp_mac(pkt: Any) -> str | None:
    if BOOTP not in pkt:
        return None
    bootp = pkt[BOOTP]
    hlen = int(getattr(bootp, "hlen", 6) or 6)
    raw = bytes(getattr(bootp, "chaddr", b"") or b"")
    mac = normalize_mac_colon(raw[: max(0, min(16, hlen))])
    if mac:
        return mac
    if Ether in pkt:
        return normalize_mac_colon(pkt[Ether].src)
    return None


def _option_key_to_code(key: Any) -> int | str:
    if isinstance(key, int):
        return key
    text = str(key)
    return DHCP_OPTION_CODES.get(text, text)


def _as_int_list(value: Any) -> tuple[int, ...]:
    if value is None:
        return ()
    if isinstance(value, bytes):
        return tuple(int(b) for b in value)
    if isinstance(value, int):
        return (int(value),)
    if isinstance(value, str):
        nums = re.findall(r"\d+", value)
        return tuple(int(n) for n in nums)
    if isinstance(value, Iterable):
        out: list[int] = []
        for item in value:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                continue
        return tuple(out)
    return ()


def _message_type(value: Any) -> str:
    if isinstance(value, int):
        return {
            1: "discover",
            2: "offer",
            3: "request",
            4: "decline",
            5: "ack",
            6: "nak",
            7: "release",
            8: "inform",
        }.get(value, str(value))
    text = _decode_text(value) or ""
    return text.lower().strip()


def _extract_dhcp_options(pkt: Any) -> dict[str, Any]:
    opts: dict[str, Any] = {}
    option_order: list[str] = []
    option_codes: list[int | str] = []

    for opt in pkt[DHCP].options:
        if isinstance(opt, str):
            if opt in {"pad", "end"}:
                continue
            option_order.append(opt)
            option_codes.append(_option_key_to_code(opt))
            continue
        if not isinstance(opt, tuple) or not opt:
            continue
        key = opt[0]
        value = opt[1] if len(opt) > 1 else None
        if key in {"pad", "end"}:
            continue
        name = str(key)
        option_order.append(name)
        option_codes.append(_option_key_to_code(key))
        opts[name] = value

    opts["_option_order"] = tuple(option_order)
    opts["_option_codes"] = tuple(option_codes)
    return opts


def extract_observation(pkt: Any) -> DhcpObservation | None:
    if DHCP not in pkt or BOOTP not in pkt:
        return None
    if int(getattr(pkt[BOOTP], "op", 0) or 0) != 1:
        return None

    opts = _extract_dhcp_options(pkt)
    msg_type = _message_type(opts.get("message-type"))
    if msg_type and msg_type not in DHCP_CLIENT_MESSAGE_TYPES:
        return None

    mac = _bootp_mac(pkt)
    if not mac:
        return None

    return DhcpObservation(
        ts=float(getattr(pkt, "time", time.time())),
        mac=mac,
        message_type=msg_type or "unknown",
        ip_src=str(pkt[IP].src) if IP in pkt else None,
        requested_ip=_decode_text(opts.get("requested_addr")),
        hostname=_decode_text(opts.get("hostname")),
        vendor_class=_decode_text(opts.get("vendor_class_id")),
        client_id=_decode_client_id(opts.get("client_id")),
        option_order=tuple(str(x) for x in opts.get("_option_order", ())),
        option_codes=tuple(opts.get("_option_codes", ())),
        requested_options=_as_int_list(opts.get("param_req_list")),
    )


def _seq_similarity(observed: tuple[int, ...], expected: tuple[int, ...]) -> float:
    if not observed or not expected:
        return 0.0
    prefix = 0
    for got, want in zip(observed, expected):
        if got != want:
            break
        prefix += 1
    overlap = len(set(observed) & set(expected)) / max(1, len(set(expected)))
    order = prefix / max(1, len(expected))
    return (0.65 * order) + (0.35 * overlap)


def _hostname_hint(hostname: str | None) -> str:
    h = (hostname or "").lower()
    if not h:
        return ""
    if any(
        token in h
        for token in (
            "my-alpine-client",
            "overdrive",
            "vbox",
            "virtualbox",
            "qemu",
            "vmware",
            "docker",
            "podman",
            "container",
            "lab-client",
            "test-client",
        )
    ):
        return "explicit-lab"
    if re.search(r"(^|[-_])(alpine|kali|parrot|backbox)([-_]|$)", h):
        return "likely-lab"
    if re.search(r"\b(desktop|laptop|win)[-a-z0-9]*", h) or h.startswith("desktop-") or h.startswith("laptop-"):
        return "windows"
    if any(token in h for token in ("iphone", "ipad", "ipod", "macbook", "imac", "apple-tv", "appletv")):
        return "apple"
    if h.startswith("android-") or "pixel-" in h or "galaxy" in h:
        return "android"
    if any(token in h for token in ("xbox", "playstation", "ps4", "ps5", "nintendo", "switch")):
        return "game-console"
    if any(token in h for token in ("openwrt", "router", "gateway", "cpe")):
        return "router"
    if any(token in h for token in ("printer", "camera", "thermostat", "roku", "chromecast", "sonos", "tivo")):
        return "iot"
    if any(token in h for token in ("ubuntu", "debian", "fedora", "archlinux", "raspberrypi")):
        return "linux"
    return ""


def classify_fingerprint(result: FingerprintResult) -> None:
    hostname = result.hostnames.most_common(1)[0][0] if result.hostnames else None
    vendor = result.vendor_classes.most_common(1)[0][0] if result.vendor_classes else None
    prl = result.requested_option_orders.most_common(1)[0][0] if result.requested_option_orders else ()
    order = result.option_orders.most_common(1)[0][0] if result.option_orders else ()

    vendor_l = (vendor or "").lower()
    host_hint = _hostname_hint(hostname)
    candidates: dict[str, float] = defaultdict(float)
    evidence: dict[str, list[str]] = defaultdict(list)

    def add(label: str, weight: float, reason: str) -> None:
        candidates[label] += weight
        evidence[label].append(reason)

    if host_hint == "explicit-lab":
        add("Explicit lab/VM/container client", 2.0, f"hostname={hostname!r} is lab/VM/container-specific")
    elif host_hint == "likely-lab":
        add("Likely lab/security Linux client", 0.75, f"hostname={hostname!r} suggests a lab/security distro")

    if "pxeclient" in vendor_l:
        add("PXE/network boot client", 1.0, f"vendor_class={vendor!r}")
    if vendor_l.startswith("msft") or "microsoft" in vendor_l:
        add("Windows PC", 0.85, f"vendor_class={vendor!r}")
    if vendor_l.startswith("android-dhcp"):
        add("Android phone/tablet", 0.9, f"vendor_class={vendor!r}")
    if vendor_l.startswith("dhcpcd"):
        add("Linux/Android/macOS dhcpcd client", 0.45, f"vendor_class={vendor!r}")
    if "dhclient" in vendor_l:
        add("Linux/BSD ISC dhclient", 0.6, f"vendor_class={vendor!r}")
    if "udhcpc" in vendor_l or vendor_l.startswith("udhcp"):
        add("Embedded Linux/IoT BusyBox client", 0.55, f"vendor_class={vendor!r}")
    if "dropbear" in vendor_l or "openwrt" in vendor_l:
        add("OpenWrt/SOHO router client", 0.75, f"vendor_class={vendor!r}")

    if host_hint == "windows":
        add("Windows PC", 0.45, f"hostname={hostname!r}")
    elif host_hint == "apple":
        add("Apple iPhone/iPad/macOS", 0.65, f"hostname={hostname!r}")
    elif host_hint == "android":
        add("Android phone/tablet", 0.45, f"hostname={hostname!r}")
    elif host_hint == "game-console":
        add("Game console", 0.75, f"hostname={hostname!r}")
    elif host_hint == "router":
        add("OpenWrt/SOHO router client", 0.55, f"hostname={hostname!r}")
    elif host_hint == "iot":
        add("Consumer IoT/media device", 0.55, f"hostname={hostname!r}")
    elif host_hint == "linux":
        add("Linux desktop/server", 0.35, f"hostname={hostname!r}")

    windows_prl = (1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252)
    apple_prl = (1, 121, 3, 6, 15, 119, 252)
    linux_dhclient_prl = (1, 121, 33, 3, 6, 12, 15, 28, 51, 54, 58, 59, 119)
    android_prl = (1, 3, 6, 15, 26, 28, 51, 58, 59, 43)
    busybox_prl = (1, 3, 6, 12, 15, 28, 42)

    prl_scores = {
        "Windows PC": _seq_similarity(prl, windows_prl),
        "Apple iPhone/iPad/macOS": _seq_similarity(prl, apple_prl),
        "Linux/BSD ISC dhclient": _seq_similarity(prl, linux_dhclient_prl),
        "Android phone/tablet": _seq_similarity(prl, android_prl),
        "Embedded Linux/IoT BusyBox client": _seq_similarity(prl, busybox_prl),
    }
    for label, sim in prl_scores.items():
        if sim >= 0.58:
            add(label, min(0.35, sim * 0.35), f"option55 order resembles {label} ({_format_prl(prl)})")

    if 252 in prl and 249 in prl:
        add("Windows PC", 0.15, "option55 includes WPAD(252) and Microsoft classless routes(249)")
    elif 252 in prl and 121 in prl and 249 not in prl:
        add("Apple iPhone/iPad/macOS", 0.12, "option55 includes WPAD(252) and RFC3442 routes(121), not option 249")
    if 60 in order or "vendor_class_id" in order:
        if vendor:
            add("DHCP client with explicit vendor class", 0.12, "wire option order includes vendor class option 60")

    if not candidates:
        result.device_type = "Unknown DHCP client"
        result.confidence = 0.0
        result.evidence = ["no strong vendor, hostname, or option-order match"]
        result.device_score = 2 if result.packet_count else 3
        return

    label, raw_conf = max(candidates.items(), key=lambda item: item[1])
    confidence = min(0.99, raw_conf)
    if confidence < 0.35:
        result.device_type = "Unknown DHCP client"
        result.confidence = confidence
        result.evidence = ["weak DHCP hints only"]
        result.device_score = 2
        return

    result.device_type = label
    result.confidence = confidence
    result.evidence = evidence[label][:4]

    if label == "Explicit lab/VM/container client":
        result.device_score = 5 if confidence >= 0.8 else 4
    elif label == "Likely lab/security Linux client":
        result.device_score = 4
    elif confidence >= 0.7 and label in {
        "Windows PC",
        "Apple iPhone/iPad/macOS",
        "Android phone/tablet",
        "Game console",
        "Consumer IoT/media device",
        "OpenWrt/SOHO router client",
    }:
        result.device_score = 1
    elif confidence >= 0.45:
        result.device_score = 2
    else:
        result.device_score = 3


def _format_prl(prl: tuple[int, ...], *, limit: int = 16) -> str:
    if not prl:
        return "-"
    shown = [
        f"{code}:{DHCP_CODE_NAMES.get(code, 'opt')}"
        for code in prl[:limit]
    ]
    suffix = " ..." if len(prl) > limit else ""
    return ",".join(shown) + suffix


def _format_order(order: tuple[int | str, ...], *, limit: int = 16) -> str:
    if not order:
        return "-"
    shown = [
        DHCP_CODE_NAMES.get(code, str(code)) if isinstance(code, int) else str(code)
        for code in order[:limit]
    ]
    suffix = " ..." if len(order) > limit else ""
    return ",".join(shown) + suffix


def _short(text: str | None, width: int) -> str:
    if not text:
        return "-"
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def _run_command(cmd: list[str], *, timeout: float = 5.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _default_iface() -> str | None:
    route = Path("/proc/net/route")
    if route.is_file():
        try:
            rows = route.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
        except OSError:
            rows = []
        for row in rows:
            cols = row.split()
            if len(cols) >= 4 and cols[1] == "00000000":
                try:
                    flags = int(cols[3], 16)
                except ValueError:
                    flags = 0
                if flags & 0x2:
                    return cols[0]

    ret, out = _run_command(["ip", "route", "show", "default"], timeout=3)
    if ret == 0:
        match = re.search(r"\bdev\s+(\S+)", out)
        if match:
            return match.group(1)
    return None


def _iface_ipv4(iface: str) -> tuple[str, ...]:
    ret, out = _run_command(["ip", "-o", "-4", "addr", "show", "dev", iface], timeout=3)
    if ret != 0:
        return ()
    ips: list[str] = []
    for match in re.finditer(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/", out):
        ips.append(match.group(1))
    return tuple(ips)


def _virtual_vendor_for_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    parts = mac.lower().replace("-", ":").split(":")
    if len(parts) < 3:
        return None
    return VIRTUAL_OUI.get(":".join(parts[:3]))


def _collect_local_interfaces(preferred_iface: str | None = None) -> list[LocalInterfaceIdentity]:
    sys_class = Path("/sys/class/net")
    if not sys_class.is_dir():
        return []

    rows: list[LocalInterfaceIdentity] = []
    for path in sorted(sys_class.iterdir(), key=lambda p: (p.name != preferred_iface, p.name)):
        iface = path.name
        skip_prefixes = ("lo", "loopback", "docker", "br-", "veth", "virbr", "tun", "tap")
        if iface != preferred_iface and iface.startswith(skip_prefixes):
            continue
        try:
            mac = (path / "address").read_text(encoding="utf-8", errors="ignore").strip().lower()
        except OSError:
            continue
        if not normalize_mac_colon(mac):
            continue
        rows.append(
            LocalInterfaceIdentity(
                iface=iface,
                mac=mac,
                ipv4=_iface_ipv4(iface),
                virtual_vendor=_virtual_vendor_for_mac(mac),
            )
        )
    rows.sort(key=lambda row: (row.iface != preferred_iface, row.virtual_vendor is None, row.iface))
    return rows


def _read_os_release() -> str | None:
    path = Path("/etc/os-release")
    if not path.is_file():
        return None
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    except OSError:
        return None
    return values.get("PRETTY_NAME") or values.get("NAME") or values.get("ID")


def _proc_dhcp_clients() -> list[str]:
    names = {
        "dhcpcd",
        "dhclient",
        "udhcpc",
        "NetworkManager",
        "systemd-networkd",
        "connmand",
        "wicked",
    }
    rows: list[str] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return rows
    for path in proc.iterdir():
        if not path.name.isdigit():
            continue
        try:
            comm = (path / "comm").read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            comm = ""
        if comm not in names:
            continue
        try:
            raw_cmdline = (path / "cmdline").read_bytes()
            cmdline = raw_cmdline.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except OSError:
            cmdline = comm
        rows.append(f"{path.name}:{cmdline or comm}")
    return sorted(dict.fromkeys(rows))


def _printable_strings(data: bytes, *, limit: int = 20) -> list[str]:
    strings = [
        match.group(0).decode("utf-8", errors="replace")
        for match in re.finditer(rb"[ -~]{4,}", data)
    ]
    interesting: list[str] = []
    for text in strings:
        lower = text.lower()
        if any(
            token in lower
            for token in (
                "hostname",
                "host-name",
                "vendor",
                "dhcpcd",
                "dhclient",
                "udhcpc",
                "msft",
                "android",
                "alpine",
                "overdrive",
                "virtualbox",
                "vbox",
            )
        ):
            interesting.append(text.strip())
    return sorted(dict.fromkeys(interesting))[:limit]


def _collect_lease_hints() -> tuple[list[str], list[str]]:
    patterns = (
        "/var/lib/dhcpcd/*.lease",
        "/var/lib/dhcp/*.leases",
        "/var/lib/dhcp/dhclient*.leases",
        "/var/lib/dhclient/*.leases",
        "/var/lib/NetworkManager/*.lease",
        "/var/lib/NetworkManager/*lease",
        "/var/db/dhclient*.leases",
        "/run/NetworkManager/*.lease",
        "/run/dhcpcd/*.lease",
        "/tmp/udhcpc*.lease",
    )
    files: list[str] = []
    hints: list[str] = []
    for pattern in patterns:
        for path in sorted(Path("/").glob(pattern.lstrip("/"))):
            if not path.is_file() or str(path) in files:
                continue
            files.append(str(path))
            try:
                data = path.read_bytes()[:65536]
            except OSError:
                continue
            hints.extend(f"{path.name}: {hint}" for hint in _printable_strings(data, limit=8))
    return files[:12], sorted(dict.fromkeys(hints))[:24]


def _assess_local_identity(identity: LocalDhcpIdentity) -> None:
    if not identity.available:
        identity.score = 3
        identity.classification = "No local DHCP identity artifacts found"
        return

    score = 2
    evidence: list[str] = []
    host_hint = _hostname_hint(identity.hostname)

    if identity.hostname:
        evidence.append(f"local hostname={identity.hostname!r}")
    if identity.os_release:
        evidence.append(f"os={identity.os_release!r}")
    if identity.dhcp_clients:
        evidence.append("DHCP client process(es): " + ", ".join(identity.dhcp_clients[:3]))
    if identity.lease_files:
        evidence.append(f"DHCP lease/cache file(s) present: {len(identity.lease_files)}")
    if identity.lease_hints:
        evidence.append("lease/cache identity string(s): " + "; ".join(identity.lease_hints[:3]))

    virtual_ifaces = [iface for iface in identity.interfaces if iface.virtual_vendor]
    if virtual_ifaces:
        vendors = sorted({iface.virtual_vendor or "" for iface in virtual_ifaces})
        evidence.append("virtual NIC OUI: " + ", ".join(vendors[:3]))
        score = max(score, 4)

    if host_hint == "explicit-lab":
        score = 5
        evidence.append("hostname is explicit lab/VM/container naming evidence")
    elif host_hint == "likely-lab":
        score = max(score, 4)
        evidence.append("hostname suggests a lab/security Linux client")

    os_l = (identity.os_release or "").lower()
    if any(token in os_l for token in ("alpine", "kali", "parrot", "backbox")):
        score = max(score, 4 if (virtual_ifaces or identity.dhcp_clients) else 3)
        evidence.append("OS release is commonly used in minimal/lab client images")

    if score < 5 and virtual_ifaces and host_hint in {"likely-lab", "explicit-lab"}:
        score = 5

    identity.score = score
    identity.evidence = evidence[:8]
    if score >= 5:
        identity.classification = "Explicit lab/VM DHCP identity likely exposed on lease renewal"
    elif score == 4:
        identity.classification = "Likely lab/VM DHCP identity from local artifacts"
    elif score == 2:
        identity.classification = "Local DHCP identity artifacts found, but not VM-specific"
    else:
        identity.classification = "Local DHCP identity artifacts inconclusive"


def collect_local_dhcp_identity(preferred_iface: str | None = None) -> LocalDhcpIdentity:
    hostname = socket.gethostname().strip() or None
    lease_files, lease_hints = _collect_lease_hints()
    identity = LocalDhcpIdentity(
        hostname=hostname,
        os_release=_read_os_release(),
        dhcp_clients=_proc_dhcp_clients(),
        interfaces=_collect_local_interfaces(preferred_iface),
        lease_files=lease_files,
        lease_hints=lease_hints,
    )
    _assess_local_identity(identity)
    return identity


def build_fingerprints(observations: list[DhcpObservation]) -> list[FingerprintResult]:
    grouped: dict[str, list[DhcpObservation]] = defaultdict(list)
    for obs in observations:
        grouped[obs.mac].append(obs)

    results: list[FingerprintResult] = []
    for mac, rows in grouped.items():
        fp = FingerprintResult(mac=mac, packet_count=len(rows))
        for obs in rows:
            fp.message_types[obs.message_type] += 1
            if obs.hostname:
                fp.hostnames[obs.hostname] += 1
            if obs.vendor_class:
                fp.vendor_classes[obs.vendor_class] += 1
            if obs.requested_ip:
                fp.requested_ips[obs.requested_ip] += 1
            if obs.option_codes:
                fp.option_orders[obs.option_codes] += 1
            if obs.requested_options:
                fp.requested_option_orders[obs.requested_options] += 1
        classify_fingerprint(fp)
        results.append(fp)

    results.sort(key=lambda fp: (fp.device_score, -fp.confidence, fp.mac))
    return results


def score_suite(results: list[FingerprintResult], local_identity: LocalDhcpIdentity | None = None) -> tuple[int, str]:
    local_identity = local_identity if local_identity and local_identity.available else None

    if not results:
        if local_identity and local_identity.score >= 5:
            return (
                5,
                "No live DHCP packets captured, but local DHCP identity artifacts strongly indicate a lab/VM client.",
            )
        if local_identity and local_identity.score == 4:
            return (
                4,
                "No live DHCP packets captured, but local DHCP identity artifacts suggest a lab/VM client.",
            )
        if local_identity and local_identity.score == 2:
            return (
                2,
                "No live DHCP packets captured; local DHCP identity artifacts are present but not VM-specific.",
            )
        return (
            3,
            "No DHCP client packets captured; renew a lease or run longer on the LAN segment.",
        )

    worst_alert = max((fp.device_score for fp in results), default=3)
    if worst_alert >= 5:
        fp = next(item for item in results if item.device_score == worst_alert)
        return 5, f"Explicit lab/VM/container DHCP identity: {fp.mac} classified as {fp.device_type}."
    if worst_alert == 4:
        fp = next(item for item in results if item.device_score == worst_alert)
        return 4, f"Likely lab/synthetic DHCP identity: {fp.mac} classified as {fp.device_type}."
    if local_identity and local_identity.score > worst_alert and local_identity.score >= 4:
        return (
            local_identity.score,
            f"DHCP packets were weak, but local DHCP identity artifacts indicate: {local_identity.classification}.",
        )

    strong_common = [fp for fp in results if fp.device_score == 1]
    if strong_common:
        labels = sorted({fp.device_type for fp in strong_common})
        return 1, f"High-confidence common LAN DHCP fingerprints observed: {', '.join(labels[:4])}."

    weak = [fp for fp in results if fp.device_score == 2]
    if weak:
        return 2, f"DHCP clients observed, but fingerprints are generic or medium-confidence ({len(results)} client(s))."

    return 3, f"DHCP packets observed from {len(results)} client(s), but classification remained inconclusive."


def _read_pcap(path: str) -> list[Any]:
    if rdpcap is None:
        raise RuntimeError(f"Scapy unavailable: {SCAPY_IMPORT_ERROR}")
    return list(rdpcap(path))


def _pid_cmdline_has(pid: int, token: str) -> bool:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    return token.encode() in raw.replace(b"\x00", b" ")


def _signal_matching_pids(comm_names: set[str], sig: int, *, iface: str | None = None) -> list[str]:
    """Send ``sig`` to matching DHCP client PIDs; optionally require iface in cmdline."""
    notes: list[str] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return notes
    for path in proc.iterdir():
        if not path.name.isdigit():
            continue
        try:
            comm = (path / "comm").read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            continue
        if comm not in comm_names:
            continue
        pid = int(path.name)
        if iface and not _pid_cmdline_has(pid, iface):
            # Still allow if cmdline has no iface token (some clients omit it).
            try:
                cmdline = (path / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace")
            except OSError:
                cmdline = ""
            if cmdline and iface not in cmdline:
                continue
        try:
            os.kill(pid, sig)
            notes.append(f"{comm} pid={pid} signal={sig}")
        except OSError as exc:
            notes.append(f"{comm} pid={pid} signal-failed({exc})")
    return notes


def _udhcpc_pidfiles_renew(iface: str) -> list[str]:
    notes: list[str] = []
    roots = (Path("/var/run"), Path("/run"), Path("/var/lib/misc"))
    patterns = (f"udhcpc.{iface}.pid", f"udhcpc-{iface}.pid", "udhcpc*.pid")
    seen: set[int] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for pattern in patterns:
            for path in root.glob(pattern):
                try:
                    pid = int(path.read_text(encoding="utf-8", errors="ignore").strip().split()[0])
                except (OSError, ValueError, IndexError):
                    continue
                if pid in seen:
                    continue
                seen.add(pid)
                try:
                    os.kill(pid, signal.SIGUSR1)  # busybox udhcpc: renew
                    notes.append(f"udhcpc SIGUSR1 via {path} pid={pid}")
                except OSError as exc:
                    notes.append(f"udhcpc pidfile {path}: {exc}")
    return notes


def trigger_local_dhcp_traffic(iface: str) -> list[str]:
    """
    Encourage authentic local DHCP client packets (renew/rebind/reapply).

    Uses the host's real DHCP client so option order / vendor class stay honest.
    Avoids crafting Scapy DHCP discovers that would fake fingerprints.
    Prefers renew over release+discover to limit connectivity disruption.
    """
    if not iface:
        return ["skipped: no interface"]

    notes: list[str] = []

    # Alpine / busybox: USR1 = renew
    notes.extend(_udhcpc_pidfiles_renew(iface))
    notes.extend(_signal_matching_pids({"udhcpc"}, signal.SIGUSR1, iface=iface))

    # dhcpcd: rebind/renew without tearing the address down
    dhcpcd = shutil.which("dhcpcd")
    if dhcpcd:
        for args in (
            [dhcpcd, "--rebind", iface],
            [dhcpcd, "-n", iface],
        ):
            ret, out = _run_command(args, timeout=10)
            snippet = " ".join(out.split())[:120]
            notes.append(f"{' '.join(args)} -> rc={ret}" + (f" ({snippet})" if snippet else ""))
            if ret == 0:
                break

    # systemd-networkd
    networkctl = shutil.which("networkctl")
    if networkctl:
        ret, out = _run_command([networkctl, "renew", iface], timeout=10)
        snippet = " ".join(out.split())[:120]
        notes.append(f"networkctl renew {iface} -> rc={ret}" + (f" ({snippet})" if snippet else ""))

    # NetworkManager
    nmcli = shutil.which("nmcli")
    if nmcli:
        ret, out = _run_command([nmcli, "device", "reapply", iface], timeout=12)
        snippet = " ".join(out.split())[:120]
        notes.append(f"nmcli device reapply {iface} -> rc={ret}" + (f" ({snippet})" if snippet else ""))
        if ret != 0:
            ret2, out2 = _run_command([nmcli, "device", "connect", iface], timeout=15)
            snippet2 = " ".join(out2.split())[:120]
            notes.append(
                f"nmcli device connect {iface} -> rc={ret2}" + (f" ({snippet2})" if snippet2 else "")
            )

    # ISC dhclient: gentle reinvoke (avoid dhclient -r; that drops the address)
    dhclient = shutil.which("dhclient")
    if dhclient:
        ret, out = _run_command([dhclient, "-nw", iface], timeout=12)
        snippet = " ".join(out.split())[:120]
        notes.append(f"dhclient -nw {iface} -> rc={ret}" + (f" ({snippet})" if snippet else ""))

    # Last resort on busybox hosts with no running udhcpc pid: one-shot discover
    udhcpc = shutil.which("udhcpc")
    if udhcpc and not any("udhcpc" in n for n in notes):
        ret, out = _run_command(
            [udhcpc, "-i", iface, "-n", "-q", "-t", "2", "-T", "1"],
            timeout=12,
        )
        snippet = " ".join(out.split())[:120]
        notes.append(f"udhcpc one-shot {iface} -> rc={ret}" + (f" ({snippet})" if snippet else ""))

    if not notes:
        notes.append("no local DHCP client tooling found to stimulate traffic")
    return notes


def _capture_live(args: argparse.Namespace) -> tuple[list[Any], bool, str | None]:
    if sniff is None:
        return [], False, f"Scapy unavailable: {SCAPY_IMPORT_ERROR}"

    pkts: list[Any] = []
    denied = False
    note: str | None = None
    trigger_notes: list[str] = []

    sniff_kw: dict[str, Any] = {
        "iface": args.iface,
        "filter": args.bpf,
        "store": True,
    }
    if args.count > 0:
        sniff_kw["count"] = args.count
    if args.timeout > 0:
        sniff_kw["timeout"] = args.timeout

    stop = threading.Event()

    def _stimulate() -> None:
        nonlocal trigger_notes
        delay = max(0.2, float(getattr(args, "trigger_delay", 0.8)))
        if stop.wait(delay):
            return
        trigger_notes = trigger_local_dhcp_traffic(str(args.iface))
        # Second pulse helps clients that ignore the first renew.
        timeout = float(getattr(args, "timeout", 45.0) or 45.0)
        second_wait = min(10.0, max(2.5, timeout * 0.3))
        if stop.wait(second_wait):
            return
        more = trigger_local_dhcp_traffic(str(args.iface))
        # Keep unique notes, preserve order
        seen = set(trigger_notes)
        for item in more:
            if item not in seen:
                trigger_notes.append(item)
                seen.add(item)

    stim_thread: threading.Thread | None = None
    do_trigger = bool(args.iface) and not bool(getattr(args, "no_trigger", False))
    if do_trigger:
        stim_thread = threading.Thread(target=_stimulate, name="dhcp-traffic-stim", daemon=True)
        stim_thread.start()

    try:
        pkts = list(sniff(**sniff_kw))
    except KeyboardInterrupt:
        pass
    except PermissionError:
        denied = True
    except OSError as exc:
        if getattr(exc, "errno", None) in (1, 13):
            denied = True
        else:
            note = str(exc)
    except Exception as exc:
        note = str(exc)
    finally:
        stop.set()
        if stim_thread is not None:
            stim_thread.join(timeout=3.0)

    if do_trigger:
        if trigger_notes:
            trig = "local DHCP renew triggered: " + "; ".join(trigger_notes[:5])
        else:
            trig = "local DHCP renew trigger scheduled (no status captured)"
        note = f"{note}; {trig}" if note else trig

    return pkts, denied, note


def _write_json(
    path: str,
    results: list[FingerprintResult],
    observations: list[DhcpObservation],
    local_identity: LocalDhcpIdentity | None,
    score: int,
    status: str,
) -> None:
    payload = {
        "score": score,
        "status": status,
        "observations": [obs.__dict__ for obs in observations],
        "clients": [
            {
                "mac": fp.mac,
                "packet_count": fp.packet_count,
                "message_types": dict(fp.message_types),
                "hostnames": dict(fp.hostnames),
                "vendor_classes": dict(fp.vendor_classes),
                "requested_ips": dict(fp.requested_ips),
                "top_option_order": list(fp.option_orders.most_common(1)[0][0]) if fp.option_orders else [],
                "top_requested_option_order": list(fp.requested_option_orders.most_common(1)[0][0]) if fp.requested_option_orders else [],
                "device_type": fp.device_type,
                "confidence": fp.confidence,
                "evidence": fp.evidence,
                "device_score": fp.device_score,
            }
            for fp in results
        ],
        "local_identity": None,
    }
    if local_identity and local_identity.available:
        payload["local_identity"] = {
            "hostname": local_identity.hostname,
            "os_release": local_identity.os_release,
            "dhcp_clients": local_identity.dhcp_clients,
            "interfaces": [iface.__dict__ for iface in local_identity.interfaces],
            "lease_files": local_identity.lease_files,
            "lease_hints": local_identity.lease_hints,
            "score": local_identity.score,
            "classification": local_identity.classification,
            "evidence": local_identity.evidence,
        }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)


def _print_local_identity(identity: LocalDhcpIdentity | None) -> None:
    if not identity or not identity.available:
        print("\nLocal DHCP identity fallback: no usable local artifacts found.")
        return

    print("\nLocal DHCP identity fallback:")
    print(f"  Hostname:      {identity.hostname or '-'}")
    print(f"  OS release:    {identity.os_release or '-'}")
    print(f"  DHCP clients:  {', '.join(identity.dhcp_clients[:4]) or '-'}")
    if identity.interfaces:
        print("  Interfaces:")
        for iface in identity.interfaces[:8]:
            vendor = iface.virtual_vendor or "physical/unknown OUI"
            ips = ",".join(iface.ipv4) or "-"
            print(f"   - {iface.iface}: {iface.mac} ({vendor}) IPv4={ips}")
        if len(identity.interfaces) > 8:
            print(f"   - ... {len(identity.interfaces) - 8} more interface(s) not shown")
    else:
        print("  Interfaces:    -")
    print(f"  Lease files:   {len(identity.lease_files)}")
    for path in identity.lease_files[:5]:
        print(f"   - {path}")
    if identity.lease_hints:
        print("  Lease hints:")
        for hint in identity.lease_hints[:6]:
            print(f"   - {_short(hint, 100)}")
    print(f"  Assessment:    {identity.classification} (score {identity.score})")
    if identity.evidence:
        print("  Evidence:")
        for item in identity.evidence:
            print(f"   - {item}")


def main() -> int:
    ap = argparse.ArgumentParser(description="DHCP option-order/vendor/hostname fingerprinting with local fallback evidence.")
    ap.add_argument("--iface", default=None, help="Interface to sniff, e.g. eth0. Default: route-selected interface.")
    ap.add_argument("--timeout", type=float, default=45.0, help="Capture seconds. Default 45; 0 means no timeout.")
    ap.add_argument("--count", type=int, default=40, help="Stop after N DHCP packets. Default 40; 0 means no limit.")
    ap.add_argument("--bpf", default="udp and (port 67 or port 68)", help="BPF filter for live capture.")
    ap.add_argument("--pcap", default=None, help="Read packets from a pcap/pcapng file instead of live capture.")
    ap.add_argument(
        "--no-trigger",
        action="store_true",
        help="Do not renew/rebind the local DHCP client during live capture (pure passive).",
    )
    ap.add_argument(
        "--trigger-delay",
        type=float,
        default=0.8,
        help="Seconds to wait after sniff starts before renewing local DHCP. Default 0.8.",
    )
    ap.add_argument("--no-local", action="store_true", help="Disable local DHCP identity fallback evidence.")
    ap.add_argument("--local-only", action="store_true", help="Skip packet capture and report local DHCP identity evidence only.")
    ap.add_argument("--out-json", default=None, help="Optional JSON evidence output path.")
    args = ap.parse_args()

    if not args.iface:
        args.iface = _default_iface()

    print("=== DHCP Client Fingerprint Probe ===")
    local_identity = None if args.no_local else collect_local_dhcp_identity(args.iface)
    capture_denied = False
    capture_note: str | None = None
    packets: list[Any] = []

    if args.local_only:
        print("Input: local DHCP identity fallback only")
    elif args.pcap:
        print(f"Input: pcap={args.pcap}")
        try:
            packets = _read_pcap(args.pcap)
        except Exception as exc:
            capture_note = f"Could not read pcap: {exc}"
    else:
        print(
            f"Input: live capture iface={args.iface or '(auto)'} "
            f"count={args.count or 'unbounded'} timeout={args.timeout if args.timeout > 0 else 'none'}s"
        )
        if args.no_trigger:
            print("DHCP traffic trigger: disabled (--no-trigger)")
        else:
            print(
                "DHCP traffic trigger: will renew/rebind the local OS DHCP client "
                f"~{args.trigger_delay:.1f}s after sniff starts (authentic client packets only)."
            )
        if args.iface:
            print(f"Detected capture interface: {args.iface}")
        packets, capture_denied, capture_note = _capture_live(args)

    if capture_denied:
        print_sniff_permission_help()
        print("[!] Live capture denied; continuing with local DHCP identity fallback evidence.")
    if capture_note:
        print(f"[!] Capture/read note: {capture_note}")

    observations = [obs for pkt in packets if (obs := extract_observation(pkt)) is not None]
    results = build_fingerprints(observations)
    score, status = score_suite(results, local_identity)

    print(f"\nPackets read: {len(packets)}")
    print(f"DHCP client packets fingerprinted: {len(observations)}")

    if results:
        print("\nClients:")
        print(
            f"{'MAC':<17} {'PKTS':<4} {'TYPE':<34} {'CONF':<5} "
            f"{'HOSTNAME':<22} {'VENDOR CLASS':<24} {'MSG TYPES'}"
        )
        print("-" * 126)
        for fp in results:
            hostname = fp.hostnames.most_common(1)[0][0] if fp.hostnames else "-"
            vendor = fp.vendor_classes.most_common(1)[0][0] if fp.vendor_classes else "-"
            msg = ",".join(f"{k}:{v}" for k, v in fp.message_types.most_common())
            print(
                f"{fp.mac:<17} {fp.packet_count:<4} {_short(fp.device_type, 34):<34} "
                f"{fp.confidence:<5.2f} {_short(hostname, 22):<22} {_short(vendor, 24):<24} {msg}"
            )

        print("\nFingerprint detail:")
        for fp in results:
            prl = fp.requested_option_orders.most_common(1)[0][0] if fp.requested_option_orders else ()
            order = fp.option_orders.most_common(1)[0][0] if fp.option_orders else ()
            print(f"\n{fp.mac} -> {fp.device_type} (confidence {fp.confidence:.2f}, device score {fp.device_score})")
            print(f"  option55 order: {_format_prl(prl)}")
            print(f"  wire option order: {_format_order(order)}")
            if fp.evidence:
                print("  evidence:")
                for item in fp.evidence:
                    print(f"   - {item}")
    else:
        print("\nNo wire-captured DHCP client fingerprints found.")

    _print_local_identity(local_identity)

    if not observations and not args.local_only:
        print("\nWire-capture note:")
        print("  DHCP is bursty; quiet leases produce zero packets without a renew.")
        if args.pcap or args.no_trigger:
            print("  Re-run live capture without --no-trigger, or renew another LAN client's lease.")
        else:
            print("  Local renew was attempted; if still empty, capture may lack privileges,")
            print("  the iface may not use DHCP, or other hosts did not broadcast during the window.")

    if args.out_json:
        _write_json(args.out_json, results, observations, local_identity, score, status)
        print(f"\n[+] Wrote evidence JSON to: {args.out_json}")

    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
