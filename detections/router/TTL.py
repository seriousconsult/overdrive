#!/usr/bin/env python3
# Executable entry: first line must stay env-based for Windows/editors; we immediately
# re-exec to ../virtual_env/bin/python when present so Linux setcap/NOPASSWD on that
# binary applies when you run ./TTL.py from detections/router/.
"""
(Layer 3)
The TTL "Signature" (Time-to-Live)

The TTL visible in a captured packet is not the sender's original value. It is the
remaining value after each routed hop decrements it. This probe therefore maps
observed TTLs to the nearest common initial TTL family:

- 32: legacy/embedded stacks
- 64: Linux, macOS, iOS, Android, many IoT devices
- 128: Windows-like stacks
- 255: routers, network appliances, some Unix/BSD appliances

High observed TTLs close to 255 are strong evidence that the sender is nearby
network hardware. Mixed initial TTL families from one source can indicate NAT or
multi-host behavior. Ordinary 64/128-family endpoint traffic is weak home-like
evidence, not proof of a router.

Host-authenticity score: 1 = residential/router TTL evidence, 3 = ambiguous,
5 = definitely artificial host. This probe does not normally emit 5 because TTL
alone cannot prove artificial hosting.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_config import LAN_PROBE_URLS
from detections.common.common_router_capture import (
    background_probe_loop,
    print_sniff_permission_help,
    reexec_to_repo_venv_python,
)


if __name__ == "__main__":
    reexec_to_repo_venv_python()

COMMON_INITIAL_TTLS = (32, 64, 128, 255)
INITIAL_TTL_LABELS = {
    32: "legacy/embedded-ish",
    64: "Unix-like/mobile/IoT-ish",
    128: "Windows-ish",
    255: "router/network-appliance-ish",
}


def _median(values: list[int]) -> float:
    ordered = sorted(values)
    n = len(ordered)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2


def estimate_initial_ttl(observed_ttl: int) -> tuple[int | None, int | None]:
    """
    Return the nearest common initial TTL and estimated hop count.

    The estimate intentionally uses the smallest common initial TTL that could
    have produced the observed value. For example, observed 61 maps to 64 with
    an estimated 3 routed hops.
    """
    try:
        observed = int(observed_ttl)
    except (TypeError, ValueError):
        return None, None
    if observed <= 0 or observed > 255:
        return None, None
    for initial in COMMON_INITIAL_TTLS:
        if observed <= initial:
            return initial, initial - observed
    return None, None


def _format_counter(counter: Counter, labeler=None, limit: int = 5) -> str:
    parts = []
    for value, count in counter.most_common(limit):
        label = labeler(value) if labeler else str(value)
        parts.append(f"{label}x{count}")
    return ", ".join(parts) if parts else "-"


def _significant_initials(counter: Counter, sample_count: int) -> list[int]:
    floor = max(2, int(sample_count * 0.12))
    return sorted(int(ttl) for ttl, count in counter.items() if count >= floor)


def analyze_ttl_samples(ttls: list[int]) -> dict:
    values: list[int] = []
    invalid_count = 0
    for ttl in ttls:
        try:
            value = int(ttl)
        except (TypeError, ValueError):
            invalid_count += 1
            continue
        if value <= 0 or value > 255:
            invalid_count += 1
            continue
        values.append(value)

    if not values:
        return {
            "count": 0,
            "invalid_count": invalid_count,
            "median_ttl": 0,
            "min_ttl": 0,
            "max_ttl": 0,
            "distinct_ttl_count": 0,
            "ttl_counts": Counter(),
            "initial_ttl_counts": Counter(),
            "family_counts": Counter(),
            "dominant_initial_ttl": None,
            "dominant_initial_ratio": 0.0,
            "median_hops": None,
            "min_hops": None,
            "max_hops": None,
            "significant_initial_ttls": [],
        }

    ttl_counts = Counter(values)
    estimates = [estimate_initial_ttl(ttl) for ttl in values]
    initial_counts = Counter(initial for initial, _hops in estimates if initial is not None)
    family_counts = Counter(
        INITIAL_TTL_LABELS.get(initial, str(initial))
        for initial in initial_counts.elements()
    )
    hop_values = [int(hops) for _initial, hops in estimates if hops is not None]
    dominant_initial, dominant_count = initial_counts.most_common(1)[0]

    return {
        "count": len(values),
        "invalid_count": invalid_count,
        "median_ttl": _median(values),
        "min_ttl": min(values),
        "max_ttl": max(values),
        "distinct_ttl_count": len(ttl_counts),
        "ttl_counts": ttl_counts,
        "initial_ttl_counts": initial_counts,
        "family_counts": family_counts,
        "dominant_initial_ttl": int(dominant_initial),
        "dominant_initial_ratio": dominant_count / len(values),
        "median_hops": _median(hop_values) if hop_values else None,
        "min_hops": min(hop_values) if hop_values else None,
        "max_hops": max(hop_values) if hop_values else None,
        "significant_initial_ttls": _significant_initials(initial_counts, len(values)),
    }


def score_ttl_analysis(stats: dict) -> tuple[str, int]:
    """
    TTL-based host-authenticity scoring.

    1 - strong residential/router/NAT evidence
    2 - weak home-like endpoint evidence
    3 - inconclusive
    4 - unusual or misleading TTL pattern
    5 - reserved; TTL alone should not claim this
    """
    count = int(stats.get("count") or 0)
    if count == 0:
        return "No valid IPv4 TTL samples for this source.", 3

    invalid_count = int(stats.get("invalid_count") or 0)
    if invalid_count and invalid_count >= count:
        return "Only invalid TTL values were observed.", 4

    median_ttl = float(stats.get("median_ttl") or 0)
    max_ttl = int(stats.get("max_ttl") or 0)
    distinct_ttl_count = int(stats.get("distinct_ttl_count") or 0)
    dominant_initial = stats.get("dominant_initial_ttl")
    dominant_ratio = float(stats.get("dominant_initial_ratio") or 0)
    significant_initials = set(stats.get("significant_initial_ttls") or [])
    median_hops = stats.get("median_hops")

    if median_ttl <= 4:
        return "Very low residual TTL; traffic may be crafted, expired-path, or otherwise misleading.", 4

    if {64, 128}.issubset(significant_initials):
        return "One source shows significant 64- and 128-family traffic; NAT/multi-host behavior is likely.", 1

    if len(significant_initials) >= 3:
        return "One source shows three or more initial TTL families; strong NAT/multi-host evidence.", 1

    if dominant_initial == 255:
        if max_ttl >= 252 or (median_hops is not None and float(median_hops) <= 3):
            return "Observed TTL is close to 255; likely nearby router or network appliance.", 1
        return "Dominant initial TTL family is 255, but not close enough to prove a nearby router.", 2

    if len(significant_initials) == 2:
        return "One source shows two initial TTL families; possible NAT, load-balancing, or mixed-host path.", 2

    if distinct_ttl_count >= 4:
        return "Multiple residual TTL values from one source; weak NAT or multi-path evidence.", 2

    if dominant_initial == 128:
        return "Dominant TTL family is Windows-like endpoint traffic; weak home-like evidence.", 2

    if dominant_initial == 64:
        return "Dominant TTL family is Unix-like/mobile/IoT endpoint traffic; weak home-like evidence.", 2

    if dominant_initial == 32:
        return "Dominant TTL family is legacy/embedded; inconclusive without corroborating evidence.", 3

    if dominant_ratio < 0.7:
        return "No dominant TTL family; pattern is ambiguous.", 3

    return "No strong residential TTL evidence.", 3


def compute_suspicion(ttls):
    """
    Backward-compatible helper used by tests and older callers.

    Returns: (label, score_1_to_5, stats)
    """
    stats = analyze_ttl_samples(list(ttls))
    label, score = score_ttl_analysis(stats)
    return label, score, stats


def discover_local_ipv4s() -> set[str]:
    """Best-effort local IPv4 discovery using Linux tools, then socket fallback."""
    ips: set[str] = set()
    try:
        proc = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                fields = line.split()
                if "inet" not in fields:
                    continue
                inet_idx = fields.index("inet")
                if inet_idx + 1 < len(fields):
                    ips.add(fields[inet_idx + 1].split("/", 1)[0])
    except (OSError, subprocess.SubprocessError, ValueError):
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass

    return {ip for ip in ips if ip}


def classify_address(addr: str, local_ips: set[str]) -> str:
    if addr in local_ips:
        return "local-host"
    try:
        ip_obj = ipaddress.ip_address(addr)
    except ValueError:
        return "invalid"
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_link_local:
        return "link-local"
    if ip_obj.is_private:
        return "private-lan"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_reserved:
        return "reserved"
    return "public"


def packet_direction(src: str, dst: str, local_ips: set[str]) -> str:
    src_local = src in local_ips or classify_address(src, local_ips) == "loopback"
    dst_local = dst in local_ips or classify_address(dst, local_ips) == "loopback"
    if src_local and dst_local:
        return "local"
    if src_local:
        return "outbound"
    if dst_local:
        return "inbound"
    return "observed"


def build_source_reports(
    ttl_by_src: dict[str, list[int]],
    direction_by_src: dict[str, Counter],
    local_ips: set[str],
    min_samples: int,
    include_local_src: bool,
) -> tuple[list[dict], list[str]]:
    reports: list[dict] = []
    skipped_local: list[str] = []

    for src, ttls in ttl_by_src.items():
        scope = classify_address(src, local_ips)
        is_local_source = scope in {"local-host", "loopback"}
        if is_local_source and not include_local_src:
            skipped_local.append(src)
            continue
        if len(ttls) < min_samples:
            continue

        label, score, stats = compute_suspicion(ttls)
        reports.append(
            {
                "src": src,
                "scope": scope,
                "directions": Counter(direction_by_src.get(src, Counter())),
                "score": score,
                "label": label,
                "stats": stats,
            }
        )

    reports.sort(key=lambda item: (item["score"], -int(item["stats"]["count"]), item["src"]))
    return reports, sorted(skipped_local)


def main():
    ap = argparse.ArgumentParser(description="Capture IPv4 TTLs and estimate source TTL families.")
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
    ap.add_argument("--top", type=int, default=10, help="How many sources to display.")
    ap.add_argument(
        "--local-ip",
        default=None,
        help="Optional local IPv4 override. If omitted, Linux interface addresses are auto-detected.",
    )
    ap.add_argument(
        "--no-auto-local",
        action="store_true",
        help="Do not auto-detect local IPv4 addresses; use only --local-ip if supplied.",
    )
    ap.add_argument(
        "--include-local-src",
        action="store_true",
        help="Include this host's own source IPs in scoring. By default they are reported as skipped.",
    )
    ap.add_argument(
        "--mode",
        choices=["both", "inbound", "outbound"],
        default="both",
        help="Direction relative to local IPs. If --local-ip is omitted, discovered local IPs are used.",
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

    local_ips: set[str] = set()
    if not args.no_auto_local:
        local_ips.update(discover_local_ipv4s())
    if args.local_ip:
        local_ips.add(args.local_ip)

    ttl_by_src: dict[str, list[int]] = defaultdict(list)
    direction_by_src: dict[str, Counter] = defaultdict(Counter)
    seen_any = False

    out_f = None
    if args.out_jsonl:
        out_f = open(args.out_jsonl, "a", buffering=1)

    tmo = None if args.timeout <= 0 else args.timeout
    print("=== TTL Source-Family Capture (heuristic) ===")
    print(
        f"iface={args.iface or '(auto)'} count={args.count or '∞'} "
        f"timeout={tmo or 'none'}s min_samples={args.min_samples} top={args.top}"
    )
    print(f"bpf='{args.bpf}' mode={args.mode}")
    print(f"local IPv4s used for direction/scoring: {', '.join(sorted(local_ips)) or '(none)'}")
    if not args.include_local_src:
        print("Local-source traffic: skipped for scoring, because outbound probe TTL is this host's own stack.")
    else:
        print("Local-source traffic: included in scoring (--include-local-src)")
    if args.mode != "both" and not local_ips:
        print("Direction filter requested, but no local IP was available; capture will be unfiltered.")
    if args.no_probe:
        print("Outbound probe traffic: disabled (--no-probe)")
    else:
        print("Outbound probe traffic: enabled (HTTP GETs in background during capture)")

    try:
        from scapy.all import IP, conf, sniff

        conf.verb = 0  # scapy quiet
    except ModuleNotFoundError:
        print("-" * 30)
        print("SCORE: 3")
        print("STATUS: Scapy is unavailable; cannot capture or parse IPv4 TTL values.")
        raise SystemExit(1)
    except PermissionError:
        print_sniff_permission_help()
        print("-" * 30)
        print("SCORE: 3")
        print("STATUS: No capture; raw socket permissions are unavailable during Scapy initialization.")
        raise SystemExit(1)
    except OSError as exc:
        if getattr(exc, "errno", None) in (1, 13):
            print_sniff_permission_help()
            print("-" * 30)
            print("SCORE: 3")
            print("STATUS: No capture; raw socket permissions are unavailable during Scapy initialization.")
            raise SystemExit(1)
        raise

    last_print = time.time()

    def maybe_print(final=False):
        nonlocal last_print
        reports, skipped_local = build_source_reports(
            dict(ttl_by_src),
            dict(direction_by_src),
            local_ips,
            args.min_samples,
            args.include_local_src,
        )
        reports = reports[: args.top]

        tag = "FINAL" if final else "INTERIM"
        print(f"\n--- {tag} TTL Source Report ---")
        if skipped_local and not args.include_local_src:
            print(f"Skipped local-source IPs: {', '.join(skipped_local[:6])}")
        if not reports:
            print("No scoreable remote sources yet (need more samples per src_ip).")
        else:
            for i, report in enumerate(reports, 1):
                stats = report["stats"]
                initial_counts = stats["initial_ttl_counts"]
                ttl_counts = stats["ttl_counts"]
                family_counts = stats["family_counts"]
                directions = report["directions"]
                dominant_initial = stats["dominant_initial_ttl"]
                dominant_label = INITIAL_TTL_LABELS.get(dominant_initial, str(dominant_initial))
                print(
                    f"{i:02d}. score={report['score']} src={report['src']} "
                    f"scope={report['scope']} label={report['label']}"
                )
                print(
                    f"    samples={stats['count']} observed_ttl median={stats['median_ttl']:.1f} "
                    f"min={stats['min_ttl']} max={stats['max_ttl']} distinct={stats['distinct_ttl_count']}"
                )
                print(
                    f"    estimated_initial={dominant_initial} ({dominant_label}) "
                    f"ratio={stats['dominant_initial_ratio']:.2f} "
                    f"hops median={stats['median_hops']} range={stats['min_hops']}..{stats['max_hops']}"
                )
                print(
                    f"    initial_families={_format_counter(initial_counts)} "
                    f"families={_format_counter(family_counts)} ttl_values={_format_counter(ttl_counts)} "
                    f"directions={_format_counter(directions)}"
                )

        last_print = time.time()

    def passes_direction_filter(src: str, dst: str) -> bool:
        if args.mode == "both" or not local_ips:
            return True
        if args.mode == "inbound":
            return dst in local_ips
        if args.mode == "outbound":
            return src in local_ips
        return True

    def on_pkt(pkt):
        nonlocal seen_any
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if not passes_direction_filter(src, dst):
            return

        ttl = int(ip.ttl)
        ttl_by_src[src].append(ttl)
        direction_by_src[src][packet_direction(src, dst, local_ips)] += 1

        if out_f:
            initial, hops = estimate_initial_ttl(ttl)
            rec = {
                "ts": time.time(),
                "src": src,
                "dst": dst,
                "ttl": ttl,
                "estimated_initial_ttl": initial,
                "estimated_hops": hops,
                "src_scope": classify_address(src, local_ips),
                "direction": packet_direction(src, dst, local_ips),
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
            target=background_probe_loop,
            args=(stop_probe, LAN_PROBE_URLS, max(0.05, float(args.probe_interval))),
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
        print_sniff_permission_help()
        print("-" * 30)
        print("SCORE: 3")
        print("STATUS: No capture; run with sudo or Linux capabilities on venv python (see above).")
        raise SystemExit(1)

    suite_score = 3
    suite_note = "Insufficient samples for per-source TTL scoring."

    if seen_any:
        maybe_print(final=True)
        reports, skipped_local = build_source_reports(
            dict(ttl_by_src),
            dict(direction_by_src),
            local_ips,
            args.min_samples,
            args.include_local_src,
        )
        if reports:
            best = reports[0]
            suite_score = int(best["score"])
            suite_note = f"Strongest TTL evidence {best['src']}: {best['label']}"
        elif ttl_by_src:
            if skipped_local and len(skipped_local) == len(ttl_by_src):
                suite_note = "Only this host's own source traffic was captured; not useful for router evidence."
            else:
                suite_note = "Captured IPv4 traffic, but no remote src_ip reached min_samples; inconclusive."
            suite_score = 3
    else:
        print("No IPv4 packets captured. Check permissions/iface/BPF filter.")

    print("-" * 30)
    print(f"SCORE: {suite_score}")
    print(f"STATUS: {suite_note}")


if __name__ == "__main__":
    main()
