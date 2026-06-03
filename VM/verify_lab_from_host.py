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

# Ensure sibling common/ package is importable when running this script from VM/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from common.common_vm import (
    get_system_paths,
    is_wsl_environment as is_wsl,
    find_vboxmanage,
    vm_is_registered as vm_registered,
    get_vm_state as vm_state,
)

# Must match create_VM_OpenWrt_router.py / create_VM_client_browser.py
ROUTER_VM = "OpenWrt_2026_Router"
CLIENT_VM = "OpenWrt_LAN_Client"
LAN_INTNET_NAME = "openwrt-lan"
SERIAL_WINDOWS_PIPE_NAME = r"\\.\pipe\OpenWrt_LAN_Client_serial"
SERIAL_WINDOWS_PIPE_BASENAME = "OpenWrt_LAN_Client_serial"
SERIAL_UNIX_SOCKET_PATH = "/tmp/OpenWrt_LAN_Client_serial.sock"


def vboxmanage_targets_windows(vboxmanage: str) -> bool:
    """True when this shell is controlling Windows VirtualBox through VBoxManage.exe."""
    return os.path.basename(vboxmanage).lower().endswith(".exe")


def expected_serial_pipe(vboxmanage: str) -> str:
    """Return the host-side serial endpoint expected for this VirtualBox host."""
    if vboxmanage_targets_windows(vboxmanage):
        return SERIAL_WINDOWS_PIPE_NAME
    return SERIAL_UNIX_SOCKET_PATH


def find_vboxmanage_for_verify(paths: dict[str, str | bool | None]) -> str | None:
    """Find VBoxManage, including common Windows install paths when running from PowerShell."""
    found = find_vboxmanage(paths)
    if found:
        return found
    for candidate in (
        r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
        r"C:\Program Files\VirtualBox\VBoxManage.exe",
    ):
        if os.path.exists(candidate):
            return candidate
    return None


def find_windows_powershell() -> str | None:
    """Find Windows PowerShell from Windows or WSL."""
    candidates = [
        shutil.which("powershell.exe"),
        "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe",
        "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def probe_windows_named_pipe(pipe_basename: str, timeout_ms: int = 5000) -> tuple[bool, str]:
    """Connect to a Windows named pipe using a bounded PowerShell client."""
    powershell = find_windows_powershell()
    if not powershell:
        return False, "Windows PowerShell not found; cannot probe Windows named pipe from this shell."

    ps_script = f"""
$ErrorActionPreference = 'Stop'
$client = [System.IO.Pipes.NamedPipeClientStream]::new('.', '{pipe_basename}', [System.IO.Pipes.PipeDirection]::InOut)
try {{
  $client.Connect({timeout_ms})
  if ($client.IsConnected) {{
    Write-Output 'CONNECTED'
  }} else {{
    Write-Output 'NOT_CONNECTED'
  }}
}} catch {{
  Write-Output ('FAILED: ' + $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' '))
}} finally {{
  $client.Dispose()
}}
"""
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            check=False,
            timeout=(timeout_ms / 1000) + 5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"PowerShell pipe probe did not complete: {exc}"

    combined = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    return "CONNECTED" in result.stdout.splitlines(), combined or f"PowerShell exited {result.returncode}"


def check_client_serial_pipe(vbox: str, info: dict[str, str], verbose: bool) -> list[str]:
    """Verify the client VM serial console endpoint is configured and accepts a host connection."""
    errs: list[str] = []
    expected_pipe = expected_serial_pipe(vbox)
    uart1 = info.get("uart1", "")
    uartmode1 = info.get("uartmode1", "")

    if uart1 in ("", "off"):
        errs.append(f"client serial: expected COM1 enabled, got uart1={uart1!r}")
    if uartmode1 != f"server,{expected_pipe}":
        errs.append(
            f"client serial: expected uartmode1='server,{expected_pipe}', got {uartmode1!r}"
        )
        return errs

    if vboxmanage_targets_windows(vbox):
        ok, detail = probe_windows_named_pipe(SERIAL_WINDOWS_PIPE_BASENAME)
        if ok:
            print(f"  [+] {CLIENT_VM} serial pipe accepts a Windows named-pipe client: {expected_pipe}")
        else:
            errs.append(
                "client serial pipe did not accept a Windows named-pipe client. "
                f"Probe output: {detail}"
            )
            print(f"  [!] {CLIENT_VM} serial pipe probe failed: {detail}")
    else:
        if os.path.exists(expected_pipe):
            print(f"  [+] {CLIENT_VM} serial socket exists: {expected_pipe}")
        else:
            errs.append(f"client serial socket does not exist: {expected_pipe}")

    if verbose:
        print(f"  [{CLIENT_VM}] uart1={uart1!r} uartmode1={uartmode1!r}")
    return errs


def check_advanced_nic(info: dict[str, str], vm_name: str) -> list[str]:
    """Checks for Promiscuous mode and Adapter Type."""
    errs = []
    # Check NIC 1 (usually the LAN in your setup)
    promisc = info.get("promisc1", "deny")
    adapter_type = info.get("nictype1", "")
    
    if promisc == "deny":
        # Warning only, as it might work without it, but allow-vms is safer for bridges
        print(f"  [!] {vm_name} NIC1 Promiscuous mode is 'deny'. If bridge fails, set to 'allow-vms'.")
    
    if "virtio" not in adapter_type.lower():
        print(f"  [i] {vm_name} NIC1 uses {adapter_type}. VirtIO is recommended for OpenWrt performance.")
    
    return errs


def check_mac_collisions(vbox: str, vms: list[str]) -> list[str]:
    """Ensures router and client don't have the same virtual hardware ID."""
    macs = {}
    errs = []
    for vm in vms:
        info = parse_machinereadable(vbox, vm)
        # Check NIC 1 and 2
        for i in ["1", "2"]:
            mac = info.get(f"macaddress{i}")
            if mac:
                if mac in macs:
                    errs.append(f"MAC Collision: {vm} and {macs[mac]} both use MAC {mac}")
                macs[mac] = vm
    return errs


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


def verify_all_vms(vbox: str, verbose: bool) -> list[str]:
    """
    Performs a deep-dive verification of the Router and Client networking.
    This is the 'stronger' loop that checks for physical-link issues.
    """
    all_errs = []
    target_vms = [
        (ROUTER_VM, "router"),
        (CLIENT_VM, "client")
    ]
    
    # Track MACs to find hidden collisions
    seen_macs: dict[str, str] = {}

    for vm, label in target_vms:
        if not vm_registered(vbox, vm):
            all_errs.append(f"VM {vm!r} is not registered.")
            print(f"[ ] {vm}: NOT FOUND")
            continue

        st = vm_state(vbox, vm)
        print(f"[{'+' if st == 'running' else '·'}] {vm}: state={st!r}")

        info = parse_machinereadable(vbox, vm)
        if not info:
            all_errs.append(f"Could not read metadata for {vm}.")
            continue

        # 1. Physical Link Check (The 'Cable Connected' toggle)
        # VirtualBox uses 'cableconnected1', 'cableconnected2', etc.
        for i in range(1, 3):
            nic_mode = info.get(f"nic{i}")
            if nic_mode and nic_mode != "none":
                if info.get(f"cableconnected{i}") == "off":
                    all_errs.append(f"{vm}: NIC{i} ({nic_mode}) cable is UNPLUGGED in VirtualBox settings.")

        # 2. MAC Address Collision Check
        for i in range(1, 3):
            mac = info.get(f"macaddress{i}")
            if mac:
                if mac in seen_macs:
                    all_errs.append(f"CRITICAL: MAC Collision! {vm} and {seen_macs[mac]} both use {mac}.")
                seen_macs[mac] = vm

        # 3. OpenWrt Bridge Compatibility (Promiscuous Mode)
        # OpenWrt needs to 'see' traffic for other MACs (like clients) on its LAN port
        if vm == ROUTER_VM:
            # Assuming NIC1 is your LAN/Internal Network based on earlier logs
            promisc = info.get("promisc1", "deny")
            if promisc == "deny":
                print(f"  [!] Warning: {vm} LAN is 'deny' promisc. OpenWrt bridges often need 'allow-vms'.")

        # 4. Standard Topology Check (Calls your existing logic)
        if vm == ROUTER_VM:
            all_errs.extend(check_router(info, verbose))
        else:
            all_errs.extend(check_client(info, verbose))
            all_errs.extend(check_client_serial_pipe(vbox, info, verbose))

    return all_errs


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Verify OpenWrt lab VM networking and client serial pipe from the host.",
    )
    ap.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print detailed NIC metadata, MAC addresses, and promiscuous modes.",
    )
    ns = ap.parse_args()

    # 1. Locate the VBoxManage executable
    paths = get_system_paths(ROUTER_VM)
    vbox = find_vboxmanage_for_verify(paths)
    if not vbox:
        print(
            "[!] VBoxManage not found. Ensure VirtualBox is installed.\n"
            "    If using WSL, ensure it is at: /mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe",
            file=sys.stderr,
        )
        return 2

    print(f"--- Laboratory Verification ---")
    print(f"Using Hypervisor Tool: {vbox}")
    print(f"Target LAN Segment:    {LAN_INTNET_NAME}\n")

    # 2. Run the 'Stronger' Verification Loop
    # This checks registration, power state, cables, MACs, and Promisc mode.
    all_errs = verify_all_vms(vbox, ns.verbose)

    # 3. Handle Results
    if all_errs:
        print("\n[!] VERIFICATION FAILED:")
        for e in all_errs:
            print(f"    - {e}")
        
        print("\nPossible Solutions:")
        print(f"  1. Run the 'create_VM_*.py' scripts to reset the NICs.")
        print(f"  2. Open VirtualBox GUI -> Settings -> Network -> Advanced.")
        print(f"     Ensure 'Cable Connected' is checked and 'Promiscuous Mode' is NOT 'Deny'.")
        print(f"  3. If only the serial pipe is busy/stuck, refresh the live UART backend:")
        print(f"     VBoxManage.exe controlvm {CLIENT_VM} changeuartmode1 disconnected")
        print(f"     VBoxManage.exe controlvm {CLIENT_VM} changeuartmode1 server {SERIAL_WINDOWS_PIPE_NAME}")
        return 1

    print("\n[+] SUCCESS: VirtualBox 'Layer 1' wiring is correct.")
    print("    You can now proceed to test Layer 3 (DHCP/Ping) inside the guests.")
    return 0


if __name__ == "__main__":
    # SystemExit ensures the script returns the correct shell exit code (0 or 1)
    # This is useful if you later want to chain this in a bash script (e.g., verify && run)
    raise SystemExit(main())
