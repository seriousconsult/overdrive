#!/usr/bin/env python3
"""
mDNS consumer-service diversity.

Unlike raw service counts (see mDNS_mesh.py), this probe classifies discovered
DNS-SD types into consumer categories (AirPlay, Chromecast, IPP printers,
HomeKit, smart speakers, etc.). A lived-in home LAN usually exposes several
categories; a hardened lab often exposes none.

Host-authenticity score:
  1 = 3+ distinct consumer categories
  2 = 2 consumer categories
  3 = 1 consumer category, or only generic/infra types
  4 = only non-consumer / infra mDNS (or empty after a short scan with types seen)
  5 = no mDNS/DNS-SD services discovered (lab-like silence)
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from collections import defaultdict
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from zeroconf import ServiceBrowser, ServiceListener, Zeroconf, ZeroconfServiceTypes
except ModuleNotFoundError:
    print(
        "Missing dependency: zeroconf\n"
        "  Alpine:  apk add py3-zeroconf   OR   pip3 install --break-system-packages zeroconf\n"
        "  Host venv: pip install zeroconf   (also installed by install.py)",
        file=sys.stderr,
    )
    raise SystemExit(1) from None

# Substring markers in service type -> consumer category label.
# Order matters: first match wins.
CONSUMER_TYPE_MARKERS: list[tuple[str, str]] = [
    ("_airplay.", "AirPlay"),
    ("_raop.", "AirPlay"),
    ("_appletv.", "AirPlay"),
    ("_companion-link.", "AirPlay"),
    ("_googlecast.", "Chromecast"),
    ("_googlezone.", "Chromecast"),
    ("_androidtvremote", "Android TV"),
    ("_nvstream.", "Game streaming"),
    ("_spotify-connect.", "Smart speaker / Spotify"),
    ("_sonos.", "Smart speaker / Spotify"),
    ("_roku.", "Streaming stick"),
    ("_ipp.", "Printer (IPP)"),
    ("_ipps.", "Printer (IPP)"),
    ("_printer.", "Printer"),
    ("_pdl-datastream.", "Printer"),
    ("_scanner.", "Scanner"),
    ("_hap.", "HomeKit / HAP"),
    ("_homekit.", "HomeKit / HAP"),
    ("_matter.", "Matter / Thread"),
    ("_hue.", "Smart lighting"),
    ("_nanoleaf.", "Smart lighting"),
    ("_ewelink.", "Smart IoT"),
    ("_tuya.", "Smart IoT"),
    ("_axis-video.", "IP camera"),
    ("_smb.", "File share"),
    ("_afpovertcp.", "File share"),
    ("_rfb.", "Remote desktop"),
    ("_vnc.", "Remote desktop"),
]

# Infra / generic types that are not strong consumer-home evidence alone.
INFRA_MARKERS = (
    "_http._tcp",
    "_https._tcp",
    "_ssh._tcp",
    "_sftp-ssh.",
    "_workstation.",
    "_device-info.",
    "_services._dns-sd.",
)


class DiversityListener(ServiceListener):
    def __init__(self) -> None:
        self.services: dict[str, str] = {}  # instance name -> type
        self.by_type: dict[str, set[str]] = defaultdict(set)

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        if name in self.services:
            return
        self.services[name] = type_
        self.by_type[type_].add(name)
        info = zc.get_service_info(type_, name, timeout=1500)
        addrs: list[str] = []
        if info and info.addresses:
            addrs = [socket.inet_ntoa(a) for a in info.addresses]
        addr_s = ", ".join(addrs) if addrs else "-"
        cat = classify_service_type(type_)
        print(f"[+] {name}")
        print(f"    type={type_}  category={cat or 'infra/other'}  ips={addr_s}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass


def classify_service_type(service_type: str) -> str | None:
    low = service_type.lower()
    for marker, label in CONSUMER_TYPE_MARKERS:
        if marker in low:
            return label
    return None


def is_infra_type(service_type: str) -> bool:
    low = service_type.lower()
    return any(m in low for m in INFRA_MARKERS)


def score_diversity(
    categories: set[str],
    service_count: int,
    type_count: int,
) -> tuple[int, str]:
    n = len(categories)
    if n >= 3:
        cats = ", ".join(sorted(categories))
        return (
            1,
            f"Diverse consumer mDNS ({n} categories: {cats}); strong residential LAN evidence.",
        )
    if n == 2:
        cats = ", ".join(sorted(categories))
        return 2, f"Two consumer mDNS categories ({cats}); residential-like LAN."
    if n == 1:
        only = next(iter(categories))
        return 3, f"Single consumer mDNS category ({only}); weak home evidence."
    if service_count > 0:
        return (
            4,
            f"mDNS present ({service_count} service(s), {type_count} type(s)) but no "
            "consumer categories (AirPlay/Cast/IPP/HomeKit/…); weak or infra-only LAN.",
        )
    return 5, "No mDNS/DNS-SD services discovered; lab-like multicast silence."


def main() -> int:
    ap = argparse.ArgumentParser(description="mDNS consumer-service diversity probe.")
    ap.add_argument(
        "--duration",
        type=float,
        default=20.0,
        help="Seconds to browse after enumerating types (default 20).",
    )
    args = ap.parse_args()
    duration = max(3.0, float(args.duration))

    print("=== mDNS Consumer Diversity ===")
    print(f"Browse duration: {duration:.0f}s\n")

    zc = Zeroconf()
    listener = DiversityListener()
    browsers: list[ServiceBrowser] = []

    try:
        try:
            all_types = list(ZeroconfServiceTypes.find(zc=zc, timeout=3))
        except Exception as exc:  # noqa: BLE001 — zeroconf raises varied errors
            print(f"Service-type enum failed ({exc}); using common consumer types.")
            all_types = []

        # Always include known consumer types even if enum is sparse.
        seed_types = [
            "_airplay._tcp.local.",
            "_raop._tcp.local.",
            "_googlecast._tcp.local.",
            "_ipp._tcp.local.",
            "_ipps._tcp.local.",
            "_printer._tcp.local.",
            "_hap._tcp.local.",
            "_spotify-connect._tcp.local.",
            "_smb._tcp.local.",
            "_http._tcp.local.",
        ]
        type_set: list[str] = []
        seen: set[str] = set()
        for t in list(all_types) + seed_types:
            if "_sub." in t or t in seen:
                continue
            seen.add(t)
            type_set.append(t)

        print(f"Browsing {len(type_set)} service type(s)…")
        for service_type in type_set:
            try:
                browsers.append(ServiceBrowser(zc, service_type, listener))
            except Exception:
                continue

        start = time.time()
        try:
            while time.time() - start < duration:
                remaining = int(max(0.0, duration - (time.time() - start)))
                print(
                    f"Scanning… {remaining}s left "
                    f"(services={len(listener.services)})",
                    end="\r",
                )
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\nInterrupted.")
    finally:
        print("\n")
        zc.close()

    categories: set[str] = set()
    infra_only = 0
    for _name, stype in listener.services.items():
        cat = classify_service_type(stype)
        if cat:
            categories.add(cat)
        elif is_infra_type(stype):
            infra_only += 1

    print(f"Services: {len(listener.services)}")
    print(f"Types:    {len(listener.by_type)}")
    print(f"Consumer categories: {len(categories)}")
    if categories:
        for cat in sorted(categories):
            print(f"  - {cat}")
    if infra_only:
        print(f"Infra/other instances: {infra_only}")

    score, status = score_diversity(
        categories,
        service_count=len(listener.services),
        type_count=len(listener.by_type),
    )
    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
