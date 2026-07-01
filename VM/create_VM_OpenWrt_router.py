#!/usr/bin/env python3

"""Create an OpenWrt router VM in VirtualBox (WSL or Linux).

**NIC order vs stock OpenWrt:** The x86 image defaults to **LAN** on ``eth0`` (``br-lan``) and **WAN**
on ``eth1``. VirtualBox presents adapters in order as ``eth0``, ``eth1``. So **NIC1** is the **LAN**
leg (internal network ``openwrt-lan``) and **NIC2** is **WAN** (bridged or NAT). Client VMs use
``--nic1 intnet`` on the same intnet name — no UCI edits required on first boot.

At startup, any **existing VirtualBox VM with the same name** and the matching folder under
``~/VirtualBox VMs/<VM_NAME>/`` are **removed** (power off, ``unregistervm --delete``, then delete
leftover directory) so the script always builds the same thing from a clean slate.
"""

import argparse
import gzip
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


# Ensure the repo package path is importable when running this script from VM/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from detections.common.common_vm import (
    find_vboxmanage,
    get_active_bridged_interface,
    get_linux_distro_id,
    get_system_paths,
    get_vboxmanage_install_hint,
    OPENWRT_IMAGE_NAME,
    OPENWRT_LAN_INTNET_NAME,
    OPENWRT_ROUTER_VM_NAME,
    OPENWRT_URL,
    OPENWRT_VDI_NAME,
    remove_existing_vm,
    resolve_vbox_settings_path,
    run_vboxmanage,
    vm_is_registered,
    wsl_to_windows_path,
)

VM_NAME = OPENWRT_ROUTER_VM_NAME
# Downstream VMs: ``VBoxManage modifyvm <name> --nic1 intnet --intnet1 openwrt-lan``
LAN_INTNET_NAME = OPENWRT_LAN_INTNET_NAME
IMAGE_NAME = OPENWRT_IMAGE_NAME
VDI_NAME = OPENWRT_VDI_NAME


def download_openwrt_image(url: str, dest_path: str) -> None:
    dest = Path(dest_path)
    if dest.exists():
        print(f"OpenWrt raw image already exists at {dest}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading OpenWrt image to {dest}...")
    with urllib.request.urlopen(url) as response:
        if response.status != 200:
            raise RuntimeError(f"Download failed with HTTP {response.status}")
        with gzip.GzipFile(fileobj=response) as gz:
            with open(dest, "wb") as out_file:
                shutil.copyfileobj(gz, out_file)
    print("Download complete.")



def try_remove_vbox_storage_controller(vboxmanage: str, vm_name: str, ctl_name: str) -> None:
    """Remove a storage controller if it exists (fresh VMs may not have IDE — avoid noisy errors)."""
    r = subprocess.run(
        [vboxmanage, "storagectl", vm_name, "--name", ctl_name, "--remove"],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        return
    combined = ((r.stderr or "") + (r.stdout or "")).lower()
    if "could not find" in combined and "controller" in combined:
        return
    if "vbox_e_object_not_found" in combined:
        return
    msg = (r.stderr or r.stdout or "").strip() or f"exit {r.returncode}"
    raise RuntimeError(
        f"VBoxManage storagectl --remove {ctl_name!r} failed unexpectedly: {msg}"
    )

def try_remove_vbox_storage_controller_with_retry(
    vboxmanage: str,
    vm_name: str,
    ctl_name: str,
    *,
    retries: int = 12,
    delay_s: float = 1.0,
) -> None:
    """Remove a storage controller, retrying transient VirtualBox machine locks."""
    for attempt in range(retries + 1):
        try:
            try_remove_vbox_storage_controller(vboxmanage, vm_name, ctl_name)
            return
        except RuntimeError as exc:
            msg = str(exc).lower()
            locked = (
                "already locked for a session" in msg
                or "being unlocked" in msg
                or "vbox_e_invalid_object_state" in msg
                or "0x80bb0007" in msg
            )
            if not locked or attempt >= retries:
                raise
            if attempt == 0:
                print("VirtualBox still has a machine lock; waiting before storage cleanup...")
            time.sleep(delay_s)


def remove_existing_router_vm(
    vboxmanage: str,
    vm_base: str,
    *,
    medium_path_for_vbox: str,
) -> None:
    """Compatibility wrapper; use ``common_vm.remove_existing_vm`` for new code."""
    remove_existing_vm(
        vboxmanage,
        VM_NAME,
        vm_base,
        medium_path_for_vbox=medium_path_for_vbox,
    )
    return
    if vm_is_registered(vboxmanage, VM_NAME):
        state = get_vm_state(vboxmanage, VM_NAME)
        if state == "saved":
            print(f"Discarding saved state for {VM_NAME!r}…")
            subprocess.run(
                [vboxmanage, "discardstate", VM_NAME], capture_output=True, text=True
            )
            state = get_vm_state(vboxmanage, VM_NAME)
        if state in ("running", "paused", "stopping", "starting"):
            print(f"Powering off existing VM {VM_NAME!r} ({state})…")
            subprocess.run([vboxmanage, "controlvm", VM_NAME, "poweroff"], check=False)
            for _ in range(45):
                time.sleep(1)
                st = get_vm_state(vboxmanage, VM_NAME)
                if st in (None, "poweroff", "aborted"):
                    break
            else:
                print(
                    f"[!] VM {VM_NAME!r} did not reach poweroff in time; "
                    "unregister may fail — close the VM window or run ``VBoxManage controlvm … poweroff``."
                )
        # Extra beat so Manager / GUI releases the machine session after poweroff.
        time.sleep(3)

        print(f"Unregistering and deleting VirtualBox VM {VM_NAME!r} (all media)…")
        if not try_unregistervm_delete(vboxmanage, VM_NAME):
            raise RuntimeError(
                f"Could not unregister {VM_NAME!r} (VirtualBox still has it locked). "
                "Close any window showing that VM, exit stray VBoxManage sessions, then re-run."
            )

    # Stale registry entry (e.g. old run deleted files without unregister): clear before new VDI.
    vbox_closemedium_disk_delete_best_effort(vboxmanage, medium_path_for_vbox)

    if os.path.isdir(vm_base):
        print(f"Removing leftover VM directory {vm_base!r}…")
        shutil.rmtree(vm_base, ignore_errors=True)


def setup_openwrt_vm(start_type: str = "separate", *, wan_mode: str = "nat") -> None:
    paths = get_system_paths(VM_NAME, IMAGE_NAME)
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError(get_vboxmanage_install_hint())

    distro_id = get_linux_distro_id()
    if distro_id == "fedora":
        print(
            "Detected Fedora host. Using native Linux VirtualBox paths; if startvm fails, "
            "check that the VirtualBox kernel modules are built for the running kernel."
        )

    img_path = paths["img_path"]
    vm_base = paths["vm_base"]
    vms_root = paths["vms_root"]
    vdi_path = os.path.join(vm_base, VDI_NAME)
    dst_path = wsl_to_windows_path(vdi_path) if paths["is_wsl"] else vdi_path

    print(f"Fresh rebuild: removing existing {VM_NAME!r} registration and disk first.")
    remove_existing_vm(
        vboxmanage, VM_NAME, vm_base, medium_path_for_vbox=dst_path
    )

    os.makedirs(vms_root, exist_ok=True)
    os.makedirs(vm_base, exist_ok=True)

    download_openwrt_image(OPENWRT_URL, img_path)

    src_path = wsl_to_windows_path(img_path) if paths["is_wsl"] else img_path
    vms_root_for_vbox = wsl_to_windows_path(vms_root) if paths["is_wsl"] else vms_root

    if not os.path.exists(vdi_path):
        print("Converting raw image to VDI...")
        run_vboxmanage(vboxmanage, ["convertfromraw", src_path, dst_path, "--format", "VDI"])
    else:
        print("VDI already exists; skipping conversion.")

    # ``createvm --basefolder`` must be the *parent* ``VirtualBox VMs`` dir (Windows path for VBoxManage.exe).
    if not vm_is_registered(vboxmanage, VM_NAME):
        existing_vbox = resolve_vbox_settings_path(vm_base, VM_NAME)
        if existing_vbox:
            reg_path = (
                wsl_to_windows_path(existing_vbox)
                if paths["is_wsl"]
                else existing_vbox
            )
            print(f"Registering existing settings file: {existing_vbox}")
            run_vboxmanage(vboxmanage, ["registervm", reg_path])
        else:
            run_vboxmanage(
                vboxmanage,
                [
                    "createvm",
                    "--name",
                    VM_NAME,
                    "--ostype",
                    "Linux_64",
                    "--basefolder",
                    vms_root_for_vbox,
                    "--register",
                ],
            )

    # NIC1 = LAN: matches OpenWrt default br-lan on eth0. NIC2 = WAN: matches wan on eth1.
    lan_nic_args = [
        "--nic1",
        "intnet",
        "--intnet1",
        LAN_INTNET_NAME,
        "--nicpromisc1",
        "allow-vms",
    ]

    bridge_interface = get_active_bridged_interface(vboxmanage) if wan_mode == "bridged" else None
    if wan_mode == "bridged" and bridge_interface:
        wan_nic_args = ["--nic2", "bridged", "--bridgeadapter2", bridge_interface]
        wan_note = f"bridged → {bridge_interface!r} (WAN / uplink)"
    else:
        wan_nic_args = ["--nic2", "nat"]
        if wan_mode == "bridged":
            wan_note = "NAT (WAN fallback — no bridged adapter resolved)"
        else:
            wan_note = "NAT (WAN / reliable lab uplink)"

    print(f"Configuring VM {VM_NAME}…")
    print(
        f"  LAN (NIC1): internal network {LAN_INTNET_NAME!r} — stock OpenWrt ``br-lan`` on ``eth0``."
    )
    print(
        f"  WAN (NIC2): {wan_note} — stock OpenWrt ``wan`` on ``eth1``."
    )
    print(
        "  Client VMs: ``--nic1 intnet`` on the same intnet name (see create_VM_client_browser.py)."
    )
    run_vboxmanage(
        vboxmanage,
        [
            "modifyvm",
            VM_NAME,
            "--memory",
            "512",
            "--cpus",
            "1",
            "--graphicscontroller",
            "vmsvga",
            *lan_nic_args,
            *wan_nic_args,
        ],
    )

    try_remove_vbox_storage_controller_with_retry(vboxmanage, VM_NAME, "IDE")

    run_vboxmanage(vboxmanage, ["storagectl", VM_NAME, "--name", "IDE", "--add", "ide", "--controller", "PIIX4"])
    run_vboxmanage(
        vboxmanage,
        ["storageattach", VM_NAME, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "hdd", "--medium", dst_path],
    )

    if start_type == "none":
        print("VM configured. Skipping start because --start-type none was selected.")
        return

    print(f"Starting VM ({start_type})...")

    def dump_vbox_diagnostics(exc: Exception, which: str) -> None:
        ts = time.strftime("%Y%m%d_%H%M%S")
        out_dir = Path(REPO_ROOT) / "VM" / "vbox_logs"
        out_dir.mkdir(parents=True, exist_ok=True)

        # 1) Write a summary of VM info (includes Log folder, when VirtualBox creates it)
        summary_path = out_dir / f"{VM_NAME}_showvminfo_{which}_{ts}.txt"
        r = subprocess.run(
            [vboxmanage, "showvminfo", VM_NAME],
            capture_output=True,
            text=True,
            check=False,
        )
        summary_path.write_text(
            (r.stdout or "") + (r.stderr or ""),
            encoding="utf-8",
            errors="replace",
        )

        # 2) Dump release/VBox logs by index: 0=VBox.log, 1=VBoxHardening.log, 2+=others
        for idx in range(0, 6):
            p = out_dir / f"{VM_NAME}_showvminfo_log{idx}_{which}_{ts}.txt"
            r = subprocess.run(
                [vboxmanage, "showvminfo", VM_NAME, f"--log={idx}"],
                capture_output=True,
                text=True,
                check=False,
            )
            p.write_text(
                (r.stdout or "") + (r.stderr or ""),
                encoding="utf-8",
                errors="replace",
            )

        print(f"\n[!] VBox startup failed during {which}: {exc}")
        print(f"[!] Wrote VirtualBox diagnostics to: {out_dir}")

    def try_start(type_to_try: str) -> None:
        run_vboxmanage(vboxmanage, ["startvm", VM_NAME, "--type", type_to_try])

    try:
        try_start(start_type)
        return
    except RuntimeError as e_headless:
        # Headless-only bug workaround: if headless fails, retry GUI.
        if start_type == "headless":
            print(f"[!] Headless start crashed ({e_headless}). Retrying with GUI mode...")

            # Best-effort poweroff to clear half-started state.
            try:
                run_vboxmanage(vboxmanage, ["controlvm", VM_NAME, "poweroff"])
            except Exception:
                pass
            time.sleep(2)

            # Dump diagnostics for the headless attempt
            dump_vbox_diagnostics(e_headless, which="headless_fail")

            # Now retry GUI
            try:
                try_start("gui")
                print("[+] Router started successfully with GUI fallback.")
                return
            except RuntimeError as e_gui:
                dump_vbox_diagnostics(e_gui, which="gui_fail")
                raise

        # For non-headless start types, keep existing behavior: dump diagnostics and raise.
        dump_vbox_diagnostics(e_headless, which=start_type)
        raise
    


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create / refresh an OpenWrt router VM in VirtualBox.",
    )
    parser.add_argument(
        "--start-type",
        choices=("gui", "headless", "separate", "none"),
        default="seperate",
        help=(
            "How to start the VM after creation. Fedora servers or SSH sessions "
            "usually want 'separate' or 'none'. Default: separate."
        ),
    )
    parser.add_argument(
        "--wan-mode",
        choices=("nat", "bridged"),
        default="nat",
        help=(
            "Router WAN VirtualBox mode. Default: nat, which avoids Wi-Fi bridge issues "
            "and LAN subnet overlap with OpenWrt's default 192.168.1.0/24 LAN."
        ),
    )
    args = parser.parse_args()
    setup_openwrt_vm(start_type=args.start_type, wan_mode=args.wan_mode)


if __name__ == "__main__":
    main()
