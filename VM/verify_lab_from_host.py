#!/usr/bin/env python3
"""
Verify VirtualBox wiring for the OpenWrt lab **from WSL or Linux on the host**.

This checks what the hypervisor is configured to do. It does **not** prove DHCP or routing inside
guests — run ``ip addr`` / ``ping`` **inside** the client VM for that (see LAB_TOPOLOGY.md).

Why: the LAN segment (``192.168.1.0/24`` on intnet ``openwrt-lan``) is **not** visible to the host
OS; only VirtualBox guests on that intnet can talk to each other there.

Exit codes: 0 = all checks passed, 1 = failed check(s), 2 = VBoxManage not found.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys

# Must match create_VM_OpenWrt_router.py / create_VM_client_browser.py
ROUTER_VM = "OpenWrt_2026_Router"
CLIENT_VM = "OpenWrt_LAN_Client"
LAN_INTNET_NAME = "openwrt-lan"


def is_wsl() -> bool:
    return "microsoft" in platform.release().lower() or os.path.exists(
        "/proc/sys/fs/binfmt_misc/WSLInterop"
    )


def find_vboxmanage() -> str | None:
    if is_wsl():
        win_vbox = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
        if os.path.isfile(win_vbox):
            return win_vbox
        return shutil.which("VBoxManage.exe") or shutil.which("VBoxManage")
    return shutil.which("VBoxManage") or shutil.which("VBoxManage.exe")


def vm_registered(vboxmanage: str, name: str) -> bool:
    r = subprocess.run(
        [vboxmanage, "list", "vms"],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        return False
    return f'"{name}"' in r.stdout


def vm_state(vboxmanage: str, name: str) -> str | None:
    if not vm_registered(vboxmanage, name):
        return None
    r = subprocess.run(
        [vboxmanage, "showvminfo", name, "--machinereadable"],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        if line.startswith("VMState="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def parse_machinereadable(vboxmanage: str, name: str) -> dict[str, str]:
    r = subprocess.run(
        [vboxmanage, "showvminfo", name, "--machinereadable"],
        capture_output=True,
        text=True,
        check=False,
    )
    if r.returncode != 0:
        return {}
    out: dict[str, str] = {}
    for line in r.stdout.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"')
    return out


def check_router(info: dict[str, str], verbose: bool) -> list[str]:
    errs: list[str] = []
    nic1 = info.get("nic1", "")
    int1 = info.get("intnet1", "")
    nic2 = info.get("nic2", "")

    if nic1 != "intnet":
        errs.append(f"router NIC1: expected intnet, got {nic1!r}")
    if int1 != LAN_INTNET_NAME:
        errs.append(
            f"router intnet1: expected {LAN_INTNET_NAME!r}, got {int1!r}"
        )
    if nic2 not in ("bridged", "nat"):
        errs.append(
            f"router NIC2: expected bridged or nat (WAN), got {nic2!r}"
        )

    if verbose:
        print(
            f"  [{ROUTER_VM}] nic1={nic1!r} intnet1={int1!r} | nic2={nic2!r} "
            f"(bridgeadapter2={info.get('bridgeadapter2', '')!r})"
        )
    return errs


def check_client(info: dict[str, str], verbose: bool) -> list[str]:
    errs: list[str] = []
    nic1 = info.get("nic1", "")
    int1 = info.get("intnet1", "")

    if nic1 != "intnet":
        errs.append(f"client NIC1: expected intnet, got {nic1!r}")
    if int1 != LAN_INTNET_NAME:
        errs.append(
            f"client intnet1: expected {LAN_INTNET_NAME!r}, got {int1!r}"
        )

    if verbose:
        print(
            f"  [{CLIENT_VM}] nic1={nic1!r} intnet1={int1!r}"
        )
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify OpenWrt lab VM networking from the host (VBoxManage only).",
    )
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print parsed NIC fields and VM power state.",
    )
    ns = ap.parse_args()

    vbox = find_vboxmanage()
    if not vbox:
        print(
            "[!] VBoxManage not found. Install VirtualBox or use WSL with "
            "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe",
            file=sys.stderr,
        )
        return 2

    print(f"Using: {vbox}")
    print(
        "Note: this does not ping 192.168.1.1 from the host — intnet is guest-only.\n"
    )

    all_errs: list[str] = []

    for vm, label in (
        (ROUTER_VM, "router"),
        (CLIENT_VM, "client"),
    ):
        if not vm_registered(vbox, vm):
            all_errs.append(f"VM {vm!r} is not registered (create it with the VM/*.py scripts).")
            print(f"[ ] {vm}: not registered")
            continue
        st = vm_state(vbox, vm)
        print(f"[{'+' if st == 'running' else '·'}] {vm}: state={st!r}")
        info = parse_machinereadable(vbox, vm)
        if not info:
            all_errs.append(f"Could not read machinereadable info for {vm!r}.")
            continue
        if vm == ROUTER_VM:
            all_errs.extend(check_router(info, ns.verbose))
        else:
            all_errs.extend(check_client(info, ns.verbose))

    if all_errs:
        print("\nFAIL:")
        for e in all_errs:
            print(f"  - {e}")
        print(
            "\nFix: recreate VMs with VM/create_VM_OpenWrt_router.py and "
            "VM/create_VM_client_browser.py, or adjust NICs in VirtualBox Manager "
            f"to match LAB_TOPOLOGY.md (intnet name: {LAN_INTNET_NAME!r})."
        )
        return 1

    print("\nOK: VirtualBox NIC wiring matches the documented lab topology.")
    print("    Confirm DHCP and ping 192.168.1.1 **inside** the client guest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
