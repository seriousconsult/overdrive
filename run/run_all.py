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
RUN_DETECTIONS = REPO_ROOT / "detections" / "run_detections.py"
DIRTY_WORDS = REPO_ROOT / "dirty_words.py"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run VM setup/verification first, then run all detections.",
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
        "--skip-dirty-words",
        action="store_true",
        help="Skip dirty_words.py identity/secret hygiene scan.",
    )
    parser.add_argument(
        "--vm-arg",
        action="append",
        default=[],
        help="Pass one argument through to run_VMs.py; repeat for multiple args.",
    )
    parser.add_argument(
        "--dirty-words-arg",
        action="append",
        default=[],
        help="Pass one argument through to dirty_words.py; repeat for multiple args.",
    )
    args = parser.parse_args()

    if not args.skip_vms:
        rc = run_step(
            [sys.executable, str(RUN_VMS), *args.vm_arg],
            cwd=REPO_ROOT,
            dry_run=False,
            name="VM setup and verification",
        )
        if rc != 0:
            return rc

    if not args.skip_detections:
        rc = run_step(
            [sys.executable, str(RUN_DETECTIONS)],
            cwd=REPO_ROOT,
            dry_run=False,
            name="Detection suite",
        )
        if rc != 0:
            return rc

    if not args.skip_dirty_words:
        rc = run_step(
            [sys.executable, str(DIRTY_WORDS), *args.dirty_words_arg],
            cwd=REPO_ROOT,
            dry_run=False,
            name="Dirty words / identity hygiene scan",
        )
        if rc != 0:
            return rc

    print("\n[+] All requested steps completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
