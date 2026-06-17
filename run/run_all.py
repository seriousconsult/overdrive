#!/usr/bin/env python3
"""Run VM setup/verification, then run the detection suite."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_runner import run_step


RUN_DIR = Path(__file__).resolve().parent
REPO_ROOT = RUN_DIR.parent
RUN_VMS = RUN_DIR / "run_VMs.py"
RUN_DETECTIONS = RUN_DIR / "run_detections.py"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run VM setup/verification first, then run all detections.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without running them.",
    )
    parser.add_argument(
        "--skip-vms",
        action="store_true",
        help="Skip run_VMs.py and only run detections.",
    )
    parser.add_argument(
        "--skip-detections",
        action="store_true",
        help="Run VM setup/verification only.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Run detections even if VM setup/verification fails.",
    )
    parser.add_argument(
        "--vm-arg",
        action="append",
        default=[],
        help="Pass one argument through to run_VMs.py; repeat for multiple args.",
    )
    args = parser.parse_args()

    failures: list[tuple[str, int]] = []

    if not args.skip_vms:
        rc = run_step(
            [sys.executable, str(RUN_VMS), *args.vm_arg],
            cwd=REPO_ROOT,
            dry_run=args.dry_run,
            name="VM setup and verification",
        )
        if rc != 0:
            failures.append(("run_VMs.py", rc))
            if not args.keep_going:
                return rc

    if not args.skip_detections:
        rc = run_step(
            [sys.executable, str(RUN_DETECTIONS)],
            cwd=REPO_ROOT,
            dry_run=args.dry_run,
            name="Detection suite",
        )
        if rc != 0:
            failures.append(("run_detections.py", rc))
            if not args.keep_going:
                return rc

    if failures:
        print("\n[!] Completed with failures:")
        for name, rc in failures:
            print(f"    - {name}: exit code {rc}")
        return failures[0][1]

    print("\n[+] All requested steps completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
