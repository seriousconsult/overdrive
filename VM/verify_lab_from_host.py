#!/usr/bin/env python3
"""
Verify QEMU/KVM lab wiring from WSL or Linux on the host.

Checks hypervisor process state, the ``test-lan`` bridge, and serial TCP
endpoints. It does **not** prove DHCP or routing inside guests — run
``ip addr`` / ``ping`` **inside** the client VM for that.

Exit codes: 0 = all checks passed, 1 = failed check(s), 2 = QEMU tools missing.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from detections.common.common_qemu import (
    LAB_BRIDGE_NAME,
    TAP_CLIENTA,
    TAP_CLIENTK,
    TAP_ROUTER_LAN,
    find_qemu_system,
    is_qemu_vm_running,
    lab_vms_root,
    require_qemu_tools,
)
from detections.common.common_vm import (
    CLIENTK_SERIAL_TCP_PORT,
    ROUTER_SERIAL_TCP_PORT,
    SERIAL_TCP_HOST,
    TEST_CLIENTA_VM_NAME,
    TEST_CLIENTK_VM_NAME,
    TEST_LAN_INTNET_NAME,
    TEST_ROUTER_VM_NAME,
    probe_tcp_serial,
)

ROUTER_VM = TEST_ROUTER_VM_NAME
LAN_BRIDGE = TEST_LAN_INTNET_NAME
CLIENTA_SERIAL_PORT = 2325


def serial_attach_is_locked(port: int) -> bool:
    if os.name == "nt":
        return False
    try:
        import fcntl
    except ImportError:
        return False

    lock_path = Path("/tmp") / f"overdrive-serial-{port}.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def _iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def resolve_lab_client_vm() -> tuple[str, int, str]:
    """Prefer Kali clientk; fall back to Alpine. Returns (name, serial_port, tap)."""
    root = Path(lab_vms_root())
    if is_qemu_vm_running(TEST_CLIENTK_VM_NAME):
        return TEST_CLIENTK_VM_NAME, CLIENTK_SERIAL_TCP_PORT, TAP_CLIENTK
    if is_qemu_vm_running(TEST_CLIENTA_VM_NAME):
        return TEST_CLIENTA_VM_NAME, CLIENTA_SERIAL_PORT, TAP_CLIENTA
    if (root / TEST_CLIENTK_VM_NAME).is_dir():
        return TEST_CLIENTK_VM_NAME, CLIENTK_SERIAL_TCP_PORT, TAP_CLIENTK
    if (root / TEST_CLIENTA_VM_NAME).is_dir():
        return TEST_CLIENTA_VM_NAME, CLIENTA_SERIAL_PORT, TAP_CLIENTA
    return TEST_CLIENTK_VM_NAME, CLIENTK_SERIAL_TCP_PORT, TAP_CLIENTK


def check_bridge_and_taps(verbose: bool, client_tap: str) -> list[str]:
    errs: list[str] = []
    if not _iface_exists(LAN_BRIDGE):
        errs.append(f"lab bridge {LAN_BRIDGE!r} does not exist")
    else:
        print(f"[+] bridge {LAN_BRIDGE!r} exists")
        if verbose:
            print(f"  [i] expected taps: {TAP_ROUTER_LAN}, {client_tap}")

    for tap, label in ((TAP_ROUTER_LAN, "router LAN"), (client_tap, "client LAN")):
        if _iface_exists(tap):
            print(f"[+] tap {tap!r} ({label}) exists")
        else:
            # Tap may be absent if VM is not running yet.
            print(f"[·] tap {tap!r} ({label}) not present (ok if that VM is stopped)")
    return errs


def check_serial(vm_name: str, port: int, *, running: bool) -> list[str]:
    errs: list[str] = []
    if not running:
        print(
            f"  [i] {vm_name} is not running — serial TCP :{port} cannot accept connections yet."
        )
        return errs
    if serial_attach_is_locked(port):
        print(
            f"  [i] {vm_name} serial TCP :{port} is already attached; "
            "skipping socket probe to avoid disrupting the console."
        )
        return errs
    ok, detail = probe_tcp_serial(SERIAL_TCP_HOST, port)
    if ok:
        print(f"  [+] {vm_name} serial TCP socket accepts a client: {SERIAL_TCP_HOST}:{port}")
        print(
            "      Socket-level check only; this does not prove guest ttyS0 output."
        )
    else:
        errs.append(f"{vm_name} serial TCP :{port} did not accept a client ({detail})")
        print(f"  [!] {vm_name} serial TCP probe failed: {detail}")
    return errs


def verify_all_vms(verbose: bool) -> list[str]:
    all_errs: list[str] = []
    client_vm, client_port, client_tap = resolve_lab_client_vm()
    print(f"Lab client VM:         {client_vm} (serial TCP {client_port})")
    if client_vm == TEST_CLIENTK_VM_NAME and is_qemu_vm_running(TEST_CLIENTA_VM_NAME):
        print(
            f"  [i] Alpine {TEST_CLIENTA_VM_NAME!r} is also running; "
            "verification focuses on Kali as the active test client."
        )
    print()

    all_errs.extend(check_bridge_and_taps(verbose, client_tap))
    print()

    for vm, port, role in (
        (ROUTER_VM, ROUTER_SERIAL_TCP_PORT, "router"),
        (client_vm, client_port, "client"),
    ):
        running = is_qemu_vm_running(vm)
        mark = "+" if running else "·"
        print(f"[{mark}] {vm}: {'running' if running else 'not running'} ({role})")
        if not running:
            # Missing router or preferred client is a failure; both should be up after run_VMs.
            all_errs.append(f"VM {vm!r} is not running.")
            continue
        all_errs.extend(check_serial(vm, port, running=True))

    return all_errs


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify lab QEMU/KVM networking and client serial from the host.",
    )
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print extra bridge/tap detail.",
    )
    ns = ap.parse_args()

    qemu = find_qemu_system()
    if not qemu:
        print(
            "[!] qemu-system-x86_64 not found. Install: sudo apt install -y qemu-system-x86 qemu-utils",
            file=sys.stderr,
        )
        return 2
    try:
        require_qemu_tools()
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    print("--- Laboratory Verification ---")
    print(f"Using Hypervisor Tool: {qemu}")
    print(f"Target LAN Segment:    {LAN_BRIDGE} (Linux bridge)")
    print(f"Lab VMs directory:     {lab_vms_root()}\n")

    all_errs = verify_all_vms(ns.verbose)

    if all_errs:
        print("\n[!] VERIFICATION FAILED:")
        for e in all_errs:
            print(f"    - {e}")
        return 1

    print("\n[+] SUCCESS: QEMU/KVM 'Layer 1' wiring looks correct.")
    print("    You can now proceed to test Layer 3 (DHCP/Ping) inside the guests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
