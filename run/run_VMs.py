#!/usr/bin/env python3
"""Run the VirtualBox lab setup scripts, then verify the lab wiring.

This is intentionally separate from ``run_all_detections.py`` because VM
creation scripts mutate VirtualBox state and can start GUI/headless guests.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


RUN_DIR = Path(__file__).resolve().parent
REPO_ROOT = RUN_DIR.parent
SCRIPT_DIR = REPO_ROOT / "VM"

PREFERRED_CREATE_ORDER = (
    "create_VM_OpenWrt_router.py",
    "create_VM_client_browser_pipe.py",
)
VERIFY_SCRIPT = "verify_lab_from_host.py"


def script_has_todo(script_path: Path) -> bool:
    try:
        return "TODO" in script_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False


def discover_create_scripts(*, include_todo: bool) -> list[Path]:
    """Return create_VM_*.py scripts in lab-friendly order."""
    all_scripts = {p.name: p for p in SCRIPT_DIR.glob("create_VM_*.py") if p.is_file()}
    ordered: list[Path] = []

    for name in PREFERRED_CREATE_ORDER:
        path = all_scripts.pop(name, None)
        if path is not None:
            ordered.append(path)

    ordered.extend(all_scripts[name] for name in sorted(all_scripts))

    if include_todo:
        return ordered

    runnable = []
    for path in ordered:
        if script_has_todo(path):
            print(f"[skip] {path.name}: contains TODO; use --include-todo to run it anyway.")
            continue
        runnable.append(path)
    return runnable


def run_step(command: list[str], *, dry_run: bool) -> int:
    print()
    print("[run] " + " ".join(command))
    if dry_run:
        return 0
    result = subprocess.run(command, cwd=str(REPO_ROOT), check=False)
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create/refresh the OpenWrt lab VMs, then verify host-side wiring.",
    )
    parser.add_argument(
        "--include-todo",
        action="store_true",
        help="Also run create_VM_*.py scripts whose source contains TODO.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue to later scripts even if one step fails.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the commands without running them.",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Run VM creation scripts but skip verify_lab_from_host.py.",
    )
    args = parser.parse_args()

    scripts = discover_create_scripts(include_todo=args.include_todo)
    if not scripts:
        print("[!] No runnable create_VM_*.py scripts found.")
        return 1

    failures: list[tuple[str, int]] = []
    for script in scripts:
        rc = run_step([sys.executable, str(script)], dry_run=args.dry_run)
        if rc != 0:
            failures.append((script.name, rc))
            if not args.keep_going:
                print(f"\n[!] Stopping after {script.name} failed with exit code {rc}.")
                return rc

    if not args.skip_verify:
        verify_path = SCRIPT_DIR / VERIFY_SCRIPT
        rc = run_step([sys.executable, str(verify_path)], dry_run=args.dry_run)
        if rc != 0:
            failures.append((VERIFY_SCRIPT, rc))
            if not args.keep_going:
                return rc

    if failures:
        print("\n[!] Completed with failures:")
        for name, rc in failures:
            print(f"    - {name}: exit code {rc}")
        return failures[0][1]

    print("\n[+] VM setup and verification completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
