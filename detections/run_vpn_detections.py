#!/usr/bin/env python3
"""Run VPN detections without and with the local insecure test tunnel."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.run_detections import (
    BASE_DIR,
    DETECTIONS_DIR,
    VENV_PYTHON,
    collect_detection_results,
    generate_html_report,
    print_results_summary,
    select_detection_folders,
)


TUNNEL_HELPER = DETECTIONS_DIR / "vpn" / "insecure_vpn_tunnel_for_testing.py"


def is_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def tunnel_command(command: str) -> tuple[int, str]:
    base_cmd = VENV_PYTHON + [str(TUNNEL_HELPER), command]
    cmd = base_cmd if is_root() else ["sudo", "-n", *base_cmd]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"{type(exc).__name__}: {exc}"
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def run_vpn_phase(label: str, report_name: str) -> dict[str, list[tuple[str, str, str]]]:
    print("\n" + "=" * 60)
    print(label)
    print("=" * 60)
    start = time.time()
    scripts_map, folder_order, rc = select_detection_folders(["vpn"])
    if rc != 0:
        raise RuntimeError("could not select vpn detection folder")
    results = collect_detection_results(scripts_map, folder_order)
    print_results_summary(results, folder_order)

    elapsed = time.time() - start
    html_path = BASE_DIR / report_name
    html_path.write_text(generate_html_report(results, folder_order, elapsed), encoding="utf-8")
    minutes, seconds = divmod(int(elapsed), 60)
    print(f"\nHTML report: {html_path}")
    print(f"Phase time: {minutes}m {seconds}s")
    return results


def flatten_vpn_results(
    results: dict[str, list[tuple[str, str, str]]],
) -> dict[str, tuple[str, str]]:
    return {script: (str(score), comment) for script, score, comment in results.get("vpn", [])}


def score_delta(before: str, after: str) -> str:
    if before.isdigit() and after.isdigit():
        delta = int(after) - int(before)
        if delta > 0:
            return f"+{delta}"
        return str(delta)
    if before == after:
        return "0"
    return "n/a"


def quick_meaning(script: str, before: str, after: str) -> str:
    if before == "Error" or after == "Error":
        return "one run failed; inspect the comments"
    if not (before.isdigit() and after.isdigit()):
        return "not numeric; inspect the comments"
    delta = int(after) - int(before)
    if delta > 0:
        return "more VPN-like with test tunnel"
    if delta < 0:
        return "less VPN-like with test tunnel"
    if script in {"ASN.py", "DNS.py", "TLS_handshake.py", "timing_latency.py"}:
        return "expected: this test tunnel does not change internet exit"
    return "no score change"


def print_comparison(
    without_tunnel: dict[str, list[tuple[str, str, str]]],
    with_tunnel: dict[str, list[tuple[str, str, str]]],
) -> None:
    before = flatten_vpn_results(without_tunnel)
    after = flatten_vpn_results(with_tunnel)
    scripts = sorted(set(before) | set(after), key=str.lower)

    changed = []
    higher = []
    for script in scripts:
        b_score = before.get(script, ("N/A", ""))[0]
        a_score = after.get(script, ("N/A", ""))[0]
        if b_score != a_score:
            changed.append(script)
        if b_score.isdigit() and a_score.isdigit() and int(a_score) > int(b_score):
            higher.append(script)

    print("\n" + "=" * 80)
    print("VPN DETECTION COMPARISON: WITHOUT TEST TUNNEL vs WITH TEST TUNNEL")
    print("=" * 80)
    print(
        "Plain meaning: the insecure test artifact should mostly affect local tunnel signs "
        "(wg-named interface, MTU, WireGuard-ish UDP port). It does not change your public internet exit."
    )
    print()
    print(f"{'Detection':<28} {'Without':<9} {'With':<7} {'Change':<8} Meaning")
    print("-" * 80)
    for script in scripts:
        b_score = before.get(script, ("N/A", ""))[0]
        a_score = after.get(script, ("N/A", ""))[0]
        delta = score_delta(b_score, a_score)
        meaning = quick_meaning(script, b_score, a_score)
        print(f"{script:<28} {b_score:<9} {a_score:<7} {delta:<8} {meaning}")

    print("-" * 80)
    print(f"Changed detections: {len(changed)} of {len(scripts)}")
    print(f"More VPN-like with tunnel: {len(higher)}")
    if higher:
        print("Most useful signal changes: " + ", ".join(higher[:8]))
    print()
    print("How to read this quickly:")
    print("  - Changes in tunnel_interface.py and MTU.py are the main expected wins.")
    print("  - ASN.py, DNS.py, and egress-like checks may stay the same by design.")
    print("  - If nothing changes, the insecure local test helper may not have started correctly.")
    print("=" * 80)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run VPN detections once without and once with the local insecure test tunnel.",
    )
    parser.add_argument(
        "--keep-tunnel-up",
        action="store_true",
        help="Leave the insecure test tunnel up after the comparison.",
    )
    parser.add_argument(
        "--single",
        action="store_true",
        help="Old behavior: run VPN detections once, without tunnel comparison.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.single:
        return 0 if run_vpn_phase("OVERDRIVE VPN DETECTION SUITE", "vpn_detection_results.html") else 1

    print("=" * 60)
    print("OVERDRIVE VPN DETECTION COMPARISON")
    print("=" * 60)
    print("Step 1: ensure insecure test tunnel is down, then run baseline detections.")
    rc, out = tunnel_command("down")
    if rc != 0:
        print("\nCould not force the test tunnel down.")
        print(out or "(no output)")
        print(
            "\nThis comparison needs root or passwordless sudo for "
            "insecure_vpn_tunnel_for_testing.py."
        )
        return rc

    without_tunnel = run_vpn_phase(
        "PHASE 1: VPN DETECTIONS WITHOUT TEST TUNNEL",
        "vpn_detection_results_without_tunnel.html",
    )

    print("\nStep 2: start insecure local VPN-like test artifact.")
    rc, out = tunnel_command("up")
    if out:
        print(out)
    if rc != 0:
        print("\nCould not start the insecure test tunnel; comparison stopped after baseline.")
        return rc

    try:
        with_tunnel = run_vpn_phase(
            "PHASE 2: VPN DETECTIONS WITH INSECURE TEST TUNNEL",
            "vpn_detection_results_with_tunnel.html",
        )
        print_comparison(without_tunnel, with_tunnel)
    finally:
        if args.keep_tunnel_up:
            print("\nLeaving insecure test tunnel up because --keep-tunnel-up was set.")
        else:
            print("\nCleaning up insecure test tunnel.")
            rc_down, out_down = tunnel_command("down")
            if out_down:
                print(out_down)
            if rc_down != 0:
                print("Warning: cleanup failed; run sudo ./insecure_vpn_tunnel_for_testing.py down")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
