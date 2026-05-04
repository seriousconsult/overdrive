#!/usr/bin/env python3
# Executable entry: first line must stay env-based for Windows/editors; we immediately
# re-exec to ../virtual_env/bin/python when present so Linux setcap/NOPASSWD on that
# binary applies when you run ./TTL.py from router/.
"""
(Layer 3)
The TTL "Signature" (Time-to-Live)
Every operating system has a default TTL value (a counter that tells a packet how many "hops" it can take before being deleted).
Linux/Mac/Android: Usually start at 64.
Windows: Usually starts at 128.
Cisco/Generic Routers: Often start at 255.
If you are analyzing traffic and see a packet with a TTL of 254 or 255, it's a massive clue that you're
talking directly to a piece of networking hardware (like a router) rather than a PC or a phone.

Unified suspicion score **1–5** (aligned with Overdrive): **higher** = stronger router/hardware–TTL signal.
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
import json
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict

from scapy.all import sniff, IP, conf

conf.verb = 0  # scapy quiet

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


_PROBE_URLS: tuple[str, ...] = (
    "https://example.com/",
    "http://example.com/",
    "https://one.one.one.one/",
)


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


def compute_suspicion(ttls):
    """
    TTL-based suspicion scoring (heuristic).
    Returns: (label, score_1_to_5, stats)
    """
    ttls = list(map(int, ttls))
    ttls_sorted = sorted(ttls)
    n = len(ttls_sorted)
    median = ttls_sorted[n // 2] if n % 2 == 1 else (ttls_sorted[n // 2 - 1] + ttls_sorted[n // 2]) / 2
    min_ttl = ttls_sorted[0]
    max_ttl = ttls_sorted[-1]

    score = 1
    label = "No strong TTL anomaly (heuristic)"

    if max_ttl >= 254:
        score = 5
        label = "Very suspicious: router-ish / network hardware TTL (max ≥ 254)"
    elif median >= 240:
        score = 4
        label = "Likely network hardware (very high median TTL)"
    elif max_ttl >= 250:
        score = 4
        label = "Very high TTL observed (possible hardware path)"

    if score <= 2:
        if 110 <= median <= 140:
            score = max(score, 2)
            label = "Possible Windows-ish stack (heuristic TTL)"
        elif 40 <= median <= 80:
            score = max(score, 2)
            label = "Possible Linux/mac/IoT-ish stack (heuristic TTL)"

    stats = {
        "count": n,
        "median_ttl": median,
        "min_ttl": min_ttl,
        "max_ttl": max_ttl,
    }
    return label, score, stats


def main():
    ap = argparse.ArgumentParser(description="Capture IPv4 TTL and evaluate Top Suspects (heuristic scoring).")
    ap.add_argument("--iface", default=None, help="Interface (e.g., eth0). Optional.")
    ap.add_argument(
        "--count",
        type=int,
        default=120,
        help="Stop after N packets (0 = no packet limit). Default 120.",
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="Wall-clock seconds to capture; return sooner if --count reached. "
        "Default 45 so batch runners do not hang on quiet networks. Use 0 for no time limit.",
    )
    ap.add_argument("--bpf", default="ip", help="BPF filter. Default: ip")
    ap.add_argument("--min-samples", type=int, default=8, help="Packets per src_ip before scoring it.")
    ap.add_argument("--top", type=int, default=10, help="How many suspects to display.")
    ap.add_argument("--local-ip", default=None, help="If set, enables inbound/outbound filtering + labeling.")
    ap.add_argument(
        "--mode",
        choices=["both", "inbound", "outbound"],
        default="both",
        help="Direction relative to --local-ip (only used if --local-ip is provided).",
    )
    ap.add_argument(
        "--print-interval",
        type=int,
        default=10,
        help="Seconds between interim prints (0 disables interim prints).",
    )
    ap.add_argument("--out-jsonl", default=None, help="Optional: also append captured packets as JSONL.")
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

    ttl_by_src = defaultdict(list)
    seen_any = False

    out_f = None
    if args.out_jsonl:
        out_f = open(args.out_jsonl, "a", buffering=1)

    tmo = None if args.timeout <= 0 else args.timeout
    print("=== TTL Suspect Capture (heuristic) ===")
    print(
        f"iface={args.iface or '(auto)'} count={args.count or '∞'} "
        f"timeout={tmo or 'none'}s min_samples={args.min_samples} top={args.top}"
    )
    print(f"bpf='{args.bpf}' local-ip={args.local_ip or '(none)'} mode={args.mode}")
    if args.no_probe:
        print("Outbound probe traffic: disabled (--no-probe)")
    else:
        print("Outbound probe traffic: enabled (HTTP GETs in background during capture)")

    start = time.time()
    last_print = start

    def maybe_print(final=False):
        nonlocal last_print
        suspects = []
        for src, ttls in ttl_by_src.items():
            if len(ttls) >= args.min_samples:
                label, score, stats = compute_suspicion(ttls)
                suspects.append((score, src, label, stats))

        suspects.sort(reverse=True)
        suspects = suspects[: args.top]

        tag = "FINAL" if final else "INTERIM"
        print(f"\n--- {tag} Suspect Report ---")
        if not suspects:
            print("No suspects yet (need more samples per src_ip).")
        else:
            for i, (score, src, label, stats) in enumerate(suspects, 1):
                print(f"{i:02d}. score={score} src={src} label={label}")
                print(
                    f"    samples={stats['count']} median_ttl={stats['median_ttl']} "
                    f"min={stats['min_ttl']} max={stats['max_ttl']}"
                )

        last_print = time.time()

    def on_pkt(pkt):
        nonlocal seen_any
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        src = ip.src

        if args.local_ip:
            if args.mode == "inbound" and ip.dst != args.local_ip:
                return
            if args.mode == "outbound" and ip.src != args.local_ip:
                return

        ttl = int(ip.ttl)
        ttl_by_src[src].append(ttl)

        if out_f:
            rec = {
                "ts": time.time(),
                "src": ip.src,
                "dst": ip.dst,
                "ttl": ttl,
                "proto": int(ip.proto),
            }
            out_f.write(json.dumps(rec) + "\n")

        seen_any = True

        if args.print_interval and (time.time() - last_print) >= args.print_interval:
            maybe_print(final=False)

    print("Starting capture... (Ctrl+C to stop early)")
    sniff_kw = {
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
        if getattr(exc, "errno", None) in (1, 13):
            capture_denied = True
        else:
            raise
    finally:
        if probe_thr is not None:
            stop_probe.set()
            probe_thr.join(timeout=4.0)
        if out_f:
            out_f.close()

    if capture_denied:
        _print_sniff_permission_help()
        print("-" * 30)
        print("SCORE: 1")
        print(" No capture: run with sudo or Linux capabilities on venv python (see above).")
        raise SystemExit(1)

    suite_score = 1
    suite_note = "Insufficient samples for per-source TTL scoring."

    if seen_any:
        maybe_print(final=True)
        suspects = []
        for src, ttls in ttl_by_src.items():
            if len(ttls) >= args.min_samples:
                label, score, stats = compute_suspicion(ttls)
                suspects.append((score, src, label, stats))
        if suspects:
            suspects.sort(reverse=True)
            top_score, top_src, top_label, _stats = suspects[0]
            suite_score = top_score
            suite_note = f"Strongest suspect {top_src}: {top_label}"
        elif ttl_by_src:
            suite_note = "Captured traffic but no src_ip reached min_samples; weak signal."
            suite_score = 2
    else:
        print("No IPv4 packets captured. Check permissions/iface/BPF filter.")

    print("-" * 30)
    print(f"SCORE: {suite_score}")
    print(f"STATUS: {suite_note}")


if __name__ == "__main__":
    main()
