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
    "create_VM_client_browser_pipe.py",
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


def wait_for_client_vm_running(timeout_s: float, *, poll_s: float = 2.0) -> bool:
    """Wait until VirtualBox reports the client VM as running."""
    paths = get_system_paths(OPENWRT_CLIENT_VM_NAME)
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        print("[!] VBoxManage not found; cannot wait for client VM state.")
        return False

    deadline = time.monotonic() + timeout_s
    last_state: str | None = None
    while True:
        state = get_vm_state(vboxmanage, OPENWRT_CLIENT_VM_NAME)
        if state == "running":
            print(f"[wait] {OPENWRT_CLIENT_VM_NAME} is running.")
            return True

        if state != last_state:
            print(f"[wait] {OPENWRT_CLIENT_VM_NAME} state: {state or 'not registered'}")
            last_state = state

        remaining_s = deadline - time.monotonic()
        if remaining_s <= 0:
            print(
                f"[!] Timed out after {timeout_s:.0f}s waiting for "
                f"{OPENWRT_CLIENT_VM_NAME} to be running."
            )
            return False

        time.sleep(min(poll_s, remaining_s))


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

    def run_client_pipe_step(
        script: Path,
        *,
        dry_run: bool,
        vm_running_timeout_s: float,
        boot_grace_s: float,
        serial_ready_timeout_s: float,
    ) -> int:
        """Start the client VM synchronously, then open serial in a separate terminal."""
        setup_cmd = [sys.executable, str(script), "--no-connect-serial", "--recreate"]
        check_cmd = [
            sys.executable,
            str(script),
            "--serial-check-only",
            "--serial-ready-timeout",
            str(serial_ready_timeout_s),
        ]
        serial_cmd = [sys.executable, str(script), "--serial-only"]

        print()
        print(f"=== {script.name} (VM setup, readiness check, then serial window) ===")
        print("[run] " + " ".join(setup_cmd))
        if dry_run:
            print("[run] " + " ".join(check_cmd))
            print("[run] " + " ".join(serial_cmd) + "  # new terminal")
            return 0

        rc = subprocess.run(setup_cmd, cwd=str(REPO_ROOT), check=False).returncode
        if rc != 0:
            return rc

        if vm_running_timeout_s > 0 and not wait_for_client_vm_running(vm_running_timeout_s):
            return 1

        if boot_grace_s > 0:
            print(
                f"[wait] Giving {script.stem} {boot_grace_s:.0f}s after VM-running state "
                "before serial probing..."
            )
            time.sleep(boot_grace_s)

        print("[run] " + " ".join(check_cmd))
        rc = subprocess.run(check_cmd, cwd=str(REPO_ROOT), check=False).returncode
        if rc != 0:
            print(
                "[!] Client serial is not usable from WSL. The TCP endpoint may be reachable, "
                "but no guest ttyS0 output was observed.\n"
                "    Treating this as a VM setup failure because WSL serial control is required."
            )
            return rc

        print("[run] " + " ".join(serial_cmd) + "  # new terminal")
        if is_wsl_environment():
            if spawn_wsl_interactive_terminal(
                serial_cmd,
                cwd=REPO_ROOT,
                title="OpenWrt client serial",
            ):
                print("[+] Serial console opened in a new Windows terminal tab.")
                return 0
            print(
                "[!] Could not open a new terminal tab. Attach manually:\n"
                f"    {' '.join(serial_cmd)}"
            )
            return 0

        flags = subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0
        try:
            subprocess.Popen(
                serial_cmd,
                cwd=str(REPO_ROOT),
                creationflags=flags,
                start_new_session=(os.name != "nt"),
            )
            print("[+] Serial console started in a new terminal window.")
            return 0
        except Exception as exc:
            print(f"[!] Failed to start serial console process: {type(exc).__name__}: {exc}")
            return 1

    for script in scripts:
        if script.name == "create_VM_client_browser_pipe.py":
            rc = run_client_pipe_step(
                script,
                dry_run=args.dry_run,
                vm_running_timeout_s=args.client_vm_running_timeout,
                boot_grace_s=args.client_boot_grace,
                serial_ready_timeout_s=args.client_serial_ready_timeout,
            )
        else:
            command = [sys.executable, str(script)]
            if script.name == "create_VM_OpenWrt_router.py":
                command.extend(["--start-type", "gui", "--wan-mode", "nat"])

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
