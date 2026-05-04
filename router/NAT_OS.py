#!/usr/bin/env python3
# Executable entry: first line must stay env-based for Windows/editors; we immediately
# re-exec to ../virtual_env/bin/python when present so Linux setcap/NOPASSWD on that
# binary applies when you run ./NAT_OS.py from router/.
"""
The "NAT" Pattern (Behavioral Analysis) based on operating system
Because a router's job is to sit in front of other devices, its traffic looks "crowded" compared to a single computer.

The OS Jumble: If one IP address is sending traffic that looks like an iPhone (TTL 64) and a Windows PC (TTL 128)
simultaneously, the "device" at that IP is almost certainly a router performing NAT for a household.

Unified suspicion score **1–5** (aligned with Overdrive): **higher** = stronger NAT / multi-host behind one IP.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _reexec_to_repo_venv_python() -> None:
    """If this file was started via `env python3`, switch to repo virtual_env/bin/python when it exists."""
    script = Path(__file__).resolve()
    vpy = script.parents[1] / "virtual_env" / "bin" / "python"
    if not vpy.is_file():
        return
    try:
        if Path(sys.executable).resolve() == vpy.resolve():
            return
    except OSError:
        return
    try:
        os.execv(str(vpy), [str(vpy), str(script), *sys.argv[1:]])
    except OSError:
        pass


_reexec_to_repo_venv_python()

import argparse
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict

from scapy.all import IP, TCP, conf, sniff

conf.verb = 0

# Small outbound GETs while sniffing so quiet interfaces still see IPv4 traffic (this host + peers).
_PROBE_URLS: tuple[str, ...] = (
    "https://example.com/",
    "http://example.com/",
    "https://one.one.one.one/",
)


def _print_sniff_permission_help() -> None:
    script = Path(__file__).resolve()
    repo = script.parents[1]
    vpy = repo / "virtual_env" / "bin" / "python"
    print("[!] Packet capture needs raw sockets (Linux: root or cap_net_raw+cap_net_admin on the venv Python).")
    print("    From repo root, for example:")
    print(f"        sudo -n {vpy} {script}")
    print("    Or grant capabilities once (then you can run without sudo):")
    print(f"        sudo setcap cap_net_raw,cap_net_admin+eip {vpy}")
    print("    See README: Passwordless sudo / capture scripts.")


def _background_probe_loop(stop: threading.Event, urls: tuple[str, ...], pause_s: float) -> None:
    n = 0
    while not stop.is_set():
        url = urls[n % len(urls)]
        n += 1
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "overdrive-router-probe/1.0", "Connection": "close"},
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                resp.read(8192)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            pass
        if stop.wait(pause_s):
            break


def _analyze_ip(ttls: set[int]) -> tuple[bool, bool, int]:
    """Returns (has_linux_range, has_windows_range, distinct_ttl_count)."""
    tlist = list(ttls)
    has_linux = any(50 <= t <= 80 for t in tlist)
    has_windows = any(100 <= t <= 128 for t in tlist)
    return has_linux, has_windows, len(tlist)


def compute_nat_score(stats: dict[str, dict[str, set]]) -> tuple[int, str]:
    """
    5 — OS jumble (Linux-range + Windows-range TTL from same src): strong NAT/router signal.
    4 — Multiple TTL buckets from one IP without full jumble (ambiguous multi-host).
    3 — Mixed evidence / borderline.
    2 — Mostly uniform TTL families (single-stack-ish).
    1 — Too little data to infer NAT from TTL alone.
    """
    if not stats:
        return 1, "No IPv4 packets observed."

    best = 1
    best_note = "No source showed both Linux- and Windows-range TTLs."

    for src_ip, data in stats.items():
        ttls = data.get("ttls") or set()
        if not ttls:
            continue
        has_linux, has_windows, dttl = _analyze_ip(ttls)
        if has_linux and has_windows:
            return (
                5,
                f"NAT pattern: {src_ip} shows Linux- and Windows-range TTLs in one source ({sorted(ttls)[:12]}…).",
            )
        if dttl >= 4:
            best = max(best, 4)
            best_note = f"{src_ip} shows {dttl} distinct TTL values (unusual for a single OS)."
        elif dttl >= 3:
            best = max(best, 3)
            best_note = f"{src_ip} shows {dttl} distinct TTL values."
        elif dttl >= 2:
            best = max(best, 2)

    if best == 1 and stats:
        return 2, "Traffic seen; TTL families look single-stack per source (no strong NAT signal)."
    return best, best_note


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Observe IPv4/TCP MSS patterns for NAT 'OS jumble' (bounded capture)."
    )
    ap.add_argument("--iface", default=None, help="Interface (optional).")
    ap.add_argument(
        "--count",
        type=int,
        default=120,
        help="Stop after N IPv4 packets (0 = no packet limit). Default 120.",
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="Wall-clock seconds to capture; return sooner if --count reached. "
        "Default 45 so batch runners do not hang on quiet networks. Use 0 for no time limit.",
    )
    ap.add_argument("--bpf", default="ip", help="BPF filter (default: ip).")
    ap.add_argument(
        "--no-probe",
        action="store_true",
        help="Do not generate outbound HTTP(S) traffic during capture (passive only).",
    )
    ap.add_argument(
        "--probe-interval",
        type=float,
        default=0.22,
        help="Seconds between outbound probe requests when probing is enabled.",
    )
    args = ap.parse_args()

    network_stats: dict[str, dict[str, set]] = defaultdict(lambda: {"ttls": set(), "mss": set()})

    def on_pkt(pkt) -> None:
        if not pkt.haslayer(IP):
            return
        src_ip = pkt[IP].src
        network_stats[src_ip]["ttls"].add(int(pkt[IP].ttl))
        if pkt.haslayer(TCP):
            opts = dict(pkt[TCP].options)
            if "MSS" in opts:
                network_stats[src_ip]["mss"].add(opts["MSS"])

    print("=== NAT / OS-jumble observer (TTL heuristic) ===")
    tmo = None if args.timeout <= 0 else args.timeout
    print(
        f"iface={args.iface or '(auto)'} count={args.count or '∞'} "
        f"timeout={tmo or 'none'}s bpf={args.bpf!r}"
    )
    if args.no_probe:
        print("Outbound probe traffic: disabled (--no-probe)")
    else:
        print("Outbound probe traffic: enabled (HTTP GETs in background during capture)")
    print("Capturing… (Ctrl+C to stop early)")

    sniff_kw: dict = {
        "iface": args.iface,
        "filter": args.bpf,
        "prn": on_pkt,
        "store": False,
    }
    if args.count > 0:
        sniff_kw["count"] = args.count
    if tmo is not None:
        sniff_kw["timeout"] = tmo

    stop_probe = threading.Event()
    probe_thr: threading.Thread | None = None
    if not args.no_probe:
        probe_thr = threading.Thread(
            target=_background_probe_loop,
            args=(stop_probe, _PROBE_URLS, max(0.05, float(args.probe_interval))),
            daemon=True,
            name="overdrive-outbound-probe",
        )
        probe_thr.start()
        time.sleep(0.25)

    capture_denied = False
    try:
        sniff(**sniff_kw)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        capture_denied = True
    except OSError as exc:
        if getattr(exc, "errno", None) in (1, 13):  # EPERM / EACCES
            capture_denied = True
        else:
            raise
    finally:
        if probe_thr is not None:
            stop_probe.set()
            probe_thr.join(timeout=4.0)

    if capture_denied:
        _print_sniff_permission_help()
        print("-" * 30)
        print("SCORE: 1")
        print(" No capture: run with sudo or Linux capabilities on venv python (see above).")
        raise SystemExit(1)

    score, note = compute_nat_score(dict(network_stats))

    for src_ip, data in sorted(network_stats.items(), key=lambda x: len(x[1]["ttls"]), reverse=True)[:12]:
        ttls = sorted(data["ttls"])
        mss = sorted(data["mss"])
        print(f"\n{src_ip}: TTLs={ttls} MSS={mss}")

    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {note}")


if __name__ == "__main__":
    main()
