#!/usr/bin/env python3
"""Run the VirtualBox lab setup scripts, then verify the lab wiring.

This is intentionally separate from ``run_all_detections.py`` because VM
creation scripts mutate VirtualBox state and can start GUI guests.
"""

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

from detections.common.common_runner import file_contains_token, run_step
from detections.common.common_vm import (
    OPENWRT_CLIENT_VM_NAME,
    find_vboxmanage,
    get_system_paths,
    get_vm_state,
    is_wsl_environment,
    spawn_wsl_interactive_terminal,
)


RUN_DIR = Path(__file__).resolve().parent
REPO_ROOT = RUN_DIR.parent
SCRIPT_DIR = REPO_ROOT / "VM"

PREFERRED_CREATE_ORDER = (
    "create_VM_OpenWrt_router.py",
)
DEFAULT_SKIP_CREATE_SCRIPTS = frozenset()
VERIFY_SCRIPT = "verify_lab_from_host.py"


def script_has_todo(script_path: Path) -> bool:
    return file_contains_token(script_path, "TODO")


def discover_create_scripts(*, include_todo: bool) -> list[Path]:
    """Return create_VM_*.py scripts in lab-friendly order."""
    all_scripts = {p.name: p for p in SCRIPT_DIR.glob("create_VM_*.py") if p.is_file()}
    ordered: list[Path] = []

    for name in PREFERRED_CREATE_ORDER:
        path = all_scripts.pop(name, None)
        if path is not None:
            ordered.append(path)

    ordered.extend(all_scripts[name] for name in sorted(all_scripts))

    runnable = []
    for path in ordered:
        if not include_todo and script_has_todo(path):
            print(f"[skip] {path.name}: contains TODO")
            continue
        runnable.append(path)
    return runnable


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
    parser.add_argument(
        "--include-client",
        action="store_true",
        help="Deprecated no-op; the client VM and serial pipe are always required.",
    )
    parser.add_argument(
        "--client-boot-grace",
        type=float,
        default=45.0,
        help="Seconds to wait after the client VM is running before serial probing.",
    )
    parser.add_argument(
        "--client-vm-running-timeout",
        type=float,
        default=180.0,
        help="Seconds to wait for VirtualBox to report the client VM as running.",
    )
    parser.add_argument(
        "--client-serial-ready-timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for required guest serial output before failing VM setup.",
    )
    args = parser.parse_args()

    scripts = discover_create_scripts(
        include_todo=args.include_todo,
    )
    if not scripts:
        print("[!] No runnable create_VM_*.py scripts found.")
        return 1

    failures: list[tuple[str, int]] = []

    for script in scripts:
        command = [sys.executable, str(script)]
        if script.name == "create_VM_OpenWrt_router.py":
            command.extend(["--start-type", "gui", "--wan-mode", "nat", "--start-alpine-client"])

        rc = run_step(command, cwd=REPO_ROOT, dry_run=args.dry_run)

        if rc != 0:
            failures.append((script.name, rc))
            if not args.keep_going:
                print(f"\n[!] Stopping after {script.name} failed with exit code {rc}.")
                return rc

    if not args.skip_verify:
        verify_path = SCRIPT_DIR / VERIFY_SCRIPT
        rc = run_step([sys.executable, str(verify_path)], cwd=REPO_ROOT, dry_run=args.dry_run)
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
