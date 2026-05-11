#!/usr/bin/env python3

"""Create an OpenWrt router VM in VirtualBox (WSL or Linux).

**NIC order vs stock OpenWrt:** The x86 image defaults to **LAN** on ``eth0`` (``br-lan``) and **WAN**
on ``eth1``. VirtualBox presents adapters in order as ``eth0``, ``eth1``. So **NIC1** is the **LAN**
leg (internal network ``openwrt-lan``) and **NIC2** is **WAN** (bridged or NAT). Client VMs use
``--nic1 intnet`` on the same intnet name — no UCI edits required on first boot.

At startup, any **existing VirtualBox VM with the same name** and the matching folder under
``~/VirtualBox VMs/<VM_NAME>/`` are **removed** (power off, ``unregistervm --delete``, then delete
leftover directory) so the script always builds from a clean slate.
"""

import gzip
import os
import platform
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

VM_NAME = "OpenWrt_2026_Router"
# Downstream VMs: ``VBoxManage modifyvm <name> --nic1 intnet --intnet1 openwrt-lan``
LAN_INTNET_NAME = "openwrt-lan"
OPENWRT_URL = "https://downloads.openwrt.org/releases/25.12.2/targets/x86/64/openwrt-25.12.2-x86-64-generic-ext4-combined.img.gz"
IMAGE_NAME = "openwrt_2026.img"
VDI_NAME = "openwrt.vdi"


def is_wsl_environment() -> bool:
    return "microsoft" in platform.release().lower() or os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop")


def wsl_to_windows_path(path: str) -> str:
    try:
        result = subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        if path.startswith("/mnt/"):
            drive, _, rest = path[1:].partition("/")
            return f"{drive.upper()}:\\{rest.replace('/', '\\')}"
        return path


def get_system_paths() -> dict:
    linux_home = str(Path.home())
    vms_root = os.path.join(linux_home, "VirtualBox VMs")
    vm_base = os.path.join(vms_root, VM_NAME)
    if is_wsl_environment():
        try:
            proc = subprocess.run(["cmd.exe", "/c", "echo", "%USERPROFILE%"], capture_output=True, text=True, check=True)
            win_profile = proc.stdout.strip()
        except subprocess.CalledProcessError:
            win_profile = None
        return {
            "is_wsl": True,
            "linux_home": linux_home,
            "win_profile": win_profile,
            "img_path": os.path.join(linux_home, "Downloads", IMAGE_NAME),
            "vms_root": vms_root,
            "vm_base": vm_base,
        }
    return {
        "is_wsl": False,
        "linux_home": linux_home,
        "win_profile": None,
        "img_path": os.path.join(linux_home, "Downloads", IMAGE_NAME),
        "vms_root": vms_root,
        "vm_base": vm_base,
    }


def find_vboxmanage(paths: dict) -> str:
    if paths["is_wsl"]:
        windows_path = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
        if os.path.exists(windows_path):
            return windows_path
        return shutil.which("VBoxManage.exe") or shutil.which("VBoxManage")
    return shutil.which("VBoxManage") or shutil.which("VBoxManage.exe")


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


def get_active_bridged_interface(vboxmanage: str) -> str | None:
    """Prefer an interface with Status=Up; otherwise first listed bridged adapter."""
    try:
        result = subprocess.run([vboxmanage, "list", "-l", "bridgedifs"], capture_output=True, text=True, check=True)
        blocks = [block for block in result.stdout.split("\n\n") if block.strip()]
        first_name: str | None = None
        for block in blocks:
            attrs = {}
            for line in block.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                attrs[key.strip()] = value.strip()
            name = attrs.get("Name")
            if name and first_name is None:
                first_name = name
            if attrs.get("Status") == "Up" and name:
                return name
        return first_name
    except subprocess.CalledProcessError:
        pass
    return None


def run_vboxmanage(vboxmanage: str, args: list[str], **kwargs) -> None:
    print(f"Executing: {vboxmanage} {' '.join(args)}")
    subprocess.run([vboxmanage] + args, check=True, **kwargs)


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


def resolve_vbox_settings_path(vm_dir: str, vm_name: str) -> str | None:
    """Find ``.vbox`` (flat or legacy nested layout from wrong ``--basefolder``)."""
    flat = os.path.join(vm_dir, f"{vm_name}.vbox")
    if os.path.isfile(flat):
        return flat
    nested = os.path.join(vm_dir, vm_name, f"{vm_name}.vbox")
    if os.path.isfile(nested):
        return nested
    try:
        for p in Path(vm_dir).rglob(f"{vm_name}.vbox"):
            if p.is_file():
                return str(p)
    except OSError:
        pass
    return None


def vm_is_registered(vboxmanage: str, vm_name: str) -> bool:
    out = subprocess.run(
        [vboxmanage, "list", "vms"], capture_output=True, text=True, check=True
    ).stdout
    return f'"{vm_name}"' in out


def get_vm_state(vboxmanage: str, vm_name: str) -> str | None:
    if not vm_is_registered(vboxmanage, vm_name):
        return None
    r = subprocess.run(
        [vboxmanage, "showvminfo", vm_name, "--machinereadable"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        if line.startswith("VMState="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def vbox_closemedium_disk_delete_best_effort(vboxmanage: str, medium_path: str) -> None:
    """
    Remove a disk from VirtualBox's media registry and delete the file if present.

    Needed when a previous run deleted files on disk but left a stale UUID in
    ``VirtualBox.xml`` (UUID mismatch on ``startvm`` / ``storageattach``).
    """
    r = subprocess.run(
        [vboxmanage, "closemedium", "disk", medium_path, "--delete"],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        combined = ((r.stderr or "") + (r.stdout or "")).lower()
        if (
            "vbox_e_object_not_found" in combined
            or "could not find" in combined
            or "does not exist" in combined
        ):
            return


def try_unregistervm_delete(
    vboxmanage: str,
    vm_name: str,
    *,
    max_wait_s: int = 120,
    poll_s: float = 3.0,
) -> bool:
    """``unregistervm --delete``, retrying while the session reports the VM as locked."""
    deadline = time.monotonic() + max_wait_s
    warned = False
    while time.monotonic() < deadline:
        ur = subprocess.run(
            [vboxmanage, "unregistervm", vm_name, "--delete"],
            capture_output=True,
            text=True,
        )
        if ur.returncode == 0:
            return True
        err = ((ur.stderr or "") + (ur.stdout or "")).lower()
        if "locked" in err or "invalid_object_state" in err or "0x80bb0007" in err:
            if not warned:
                print(
                    "Waiting for VirtualBox to release the VM lock "
                    "(close the guest window or Manager details tab if open)…"
                )
                warned = True
            time.sleep(poll_s)
            continue
        msg = (ur.stderr or ur.stdout or "").strip()
        if msg:
            print(f"[!] unregistervm --delete: {msg}")
        return False
    print(
        f"[!] Timed out after {max_wait_s}s; VM {vm_name!r} is still locked. "
        "Close VirtualBox UI for that VM, then re-run this script."
    )
    return False


def remove_existing_router_vm(
    vboxmanage: str,
    vm_base: str,
    *,
    medium_path_for_vbox: str,
) -> None:
    """Drop any prior VM + disk folder for ``VM_NAME`` so this run starts clean."""
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


def setup_openwrt_vm() -> None:
    paths = get_system_paths()
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError("VBoxManage not found. Install VirtualBox or add it to PATH.")

    img_path = paths["img_path"]
    vm_base = paths["vm_base"]
    vms_root = paths["vms_root"]
    vdi_path = os.path.join(vm_base, VDI_NAME)
    dst_path = wsl_to_windows_path(vdi_path) if paths["is_wsl"] else vdi_path

    remove_existing_router_vm(
        vboxmanage, vm_base, medium_path_for_vbox=dst_path
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
    lan_nic_args = ["--nic1", "intnet", "--intnet1", LAN_INTNET_NAME]

    bridge_interface = get_active_bridged_interface(vboxmanage)
    if bridge_interface:
        wan_nic_args = ["--nic2", "bridged", "--bridgeadapter2", bridge_interface]
        wan_note = f"bridged → {bridge_interface!r} (WAN / uplink)"
    else:
        wan_nic_args = ["--nic2", "nat"]
        wan_note = "NAT (WAN fallback — no bridged adapter resolved)"

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

    try_remove_vbox_storage_controller(vboxmanage, VM_NAME, "IDE")

    run_vboxmanage(vboxmanage, ["storagectl", VM_NAME, "--name", "IDE", "--add", "ide", "--controller", "PIIX4"])
    run_vboxmanage(vboxmanage, ["storageattach", VM_NAME, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "hdd", "--medium", dst_path])

    print("Starting VM...")
    run_vboxmanage(vboxmanage, ["startvm", VM_NAME, "--type", "gui"])


if __name__ == "__main__":
    setup_openwrt_vm()
