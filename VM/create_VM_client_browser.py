#!/usr/bin/env python3
"""
Create a Linux desktop VM in VirtualBox for use **behind** the OpenWrt router from
``create_VM_OpenWrt_router.py``.

Networking (lab):
  * **NIC1** — VirtualBox **internal network** ``openwrt-lan`` (same name as the router’s LAN leg).
    The guest gets DHCP from OpenWrt’s LAN; default gateway is the OpenWrt LAN IP (e.g. 192.168.1.1).

This VM is **not** bridged to your Windows/WSL LAN. WSL **mirrored** mode only affects the Linux
namespace on the host; it does not change VirtualBox intnet isolation. To browse from the host
through OpenWrt, use RDP/guest tools or a second setup—this script targets the standard “client on
router LAN” topology.

**Clipboard (host ↔ guest):** The VM uses **bidirectional** shared clipboard. By default this script
tries to **inject Guest Additions into the VDI while the VM is off** using ``virt-customize``
(``libguestfs-tools`` on WSL/Ubuntu), matching the **host** ISO from VirtualBox. That avoids manual
steps inside the guest. Use ``--skip-guest-additions`` to skip injection (clipboard will not work
until you install additions yourself). If the VM is **running**, injection is skipped unless you
pass ``--force-poweroff-for-ga``.

Requires: ``VBoxManage``, ``7z``. Optional: ``virt-customize`` (``sudo apt install libguestfs-tools``).
Network only for first-time OSBoxes download.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

import requests

# Must match ``LAN_INTNET_NAME`` in create_VM_OpenWrt_router.py
LAN_INTNET_NAME = "openwrt-lan"

VM_NAME = "OpenWrt_LAN_Client"
CLIENT_VDI_NAME = "client_browser.vdi"

# Ubuntu 24.10 server image from OSBoxes (desktop-capable; install a browser in-guest if needed)
OSBOXES_URL = (
    "https://downloads.sourceforge.net/project/osboxes/v/vb/59-U-u-svr/24.10/64bit.7z"
)
ARCHIVE_NAME = "ubuntu_osboxes_2410.7z"


def is_wsl_environment() -> bool:
    return "microsoft" in platform.release().lower() or os.path.exists(
        "/proc/sys/fs/binfmt_misc/WSLInterop"
    )


def wsl_to_windows_path(path: str) -> str:
    try:
        result = subprocess.run(
            ["wslpath", "-w", path], capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        if path.startswith("/mnt/"):
            drive, _, rest = path[1:].partition("/")
            return f"{drive.upper()}:\\{rest.replace('/', '\\')}"
        return path


def get_system_paths() -> dict:
    linux_home = str(Path.home())
    if is_wsl_environment():
        try:
            proc = subprocess.run(
                ["cmd.exe", "/c", "echo", "%USERPROFILE%"],
                capture_output=True,
                text=True,
                check=True,
            )
            win_profile = proc.stdout.strip()
        except subprocess.CalledProcessError:
            win_profile = None
        vms_root = os.path.join(linux_home, "VirtualBox VMs")
        return {
            "is_wsl": True,
            "linux_home": linux_home,
            "win_profile": win_profile,
            "downloads": os.path.join(linux_home, "Downloads"),
            "vms_root": vms_root,
            "vm_base": os.path.join(vms_root, VM_NAME),
        }
    vms_root = os.path.join(linux_home, "VirtualBox VMs")
    return {
        "is_wsl": False,
        "linux_home": linux_home,
        "win_profile": None,
        "downloads": os.path.join(linux_home, "Downloads"),
        "vms_root": vms_root,
        "vm_base": os.path.join(vms_root, VM_NAME),
    }


def find_vboxmanage(paths: dict) -> str:
    if paths["is_wsl"]:
        windows_path = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
        if os.path.exists(windows_path):
            return windows_path
        return shutil.which("VBoxManage.exe") or shutil.which("VBoxManage") or ""
    return shutil.which("VBoxManage") or shutil.which("VBoxManage.exe") or ""


def get_half_cpus() -> int:
    total = os.cpu_count() or 2
    return max(1, total // 2)


def run_vboxmanage(vboxmanage: str, args: list[str], **kwargs) -> None:
    print(f"Executing: {vboxmanage} {' '.join(args)}")
    subprocess.run([vboxmanage] + args, check=True, **kwargs)


def resolve_vbox_settings_path(vm_dir: str, vm_name: str) -> str | None:
    """
    Return path to an existing ``.vbox`` file for this VM.

    VirtualBox expects ``<vms_root>/<vm_name>/<vm_name>.vbox``. Older buggy runs of this script
    used ``--basefolder`` pointing at ``.../<vm_name>``, which created an extra nested folder.
    """
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


def find_guest_additions_iso() -> str | None:
    candidates = [
        "/mnt/c/Program Files/Oracle/VirtualBox/VBoxGuestAdditions.iso",
        "/usr/share/virtualbox/VBoxGuestAdditions.iso",
        "/usr/lib/virtualbox/additions/VBoxGuestAdditions.iso",
    ]
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return None


def extract_vbox_linux_additions_run(iso_path: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["7z", "e", "-y", f"-o{out_dir}", iso_path, "VBoxLinuxAdditions.run"],
        check=True,
    )
    run_file = out_dir / "VBoxLinuxAdditions.run"
    if not run_file.is_file():
        raise RuntimeError(
            "7z did not extract VBoxLinuxAdditions.run from Guest Additions ISO."
        )
    return run_file


def guest_additions_present_in_vdi(vdi_linux: str) -> bool:
    vc = shutil.which("virt-customize")
    if not vc:
        return False
    r = subprocess.run(
        [
            vc,
            "-a",
            vdi_linux,
            "--run-command",
            "test -x /usr/sbin/VBoxService",
        ],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0


def inject_guest_additions_into_vdi(
    vdi_linux: str,
    vboxmanage: str,
    vm_name: str,
    work_root: Path,
    *,
    force_poweroff: bool,
) -> bool:
    """
    Install Oracle Guest Additions into the **powered-off** VDI via libguestfs (no manual guest steps).

    Returns True if additions are present afterward, False if skipped or failed.
    """
    vc = shutil.which("virt-customize")
    if not vc:
        print(
            "[!] virt-customize not found; skipping Guest Additions injection.\n"
            "    Install: sudo apt install libguestfs-tools\n"
            "    Then re-run this script, or install additions manually in the guest.",
        )
        return False

    state = get_vm_state(vboxmanage, vm_name)
    if state == "running" or state == "paused":
        if not force_poweroff:
            print(
                f"[!] VM {vm_name!r} is {state}; cannot safely modify the VDI.\n"
                "    Power it off and re-run, or pass --force-poweroff-for-ga.",
            )
            return False
        print(f"Powering off {vm_name} so the VDI can be modified…")
        subprocess.run([vboxmanage, "controlvm", vm_name, "poweroff"], check=False)
        for _ in range(30):
            time.sleep(1)
            st = get_vm_state(vboxmanage, vm_name)
            if st in (None, "poweroff", "aborted"):
                break
        else:
            print("[!] VM did not power off in time; skipping Guest Additions injection.")
            return False

    if guest_additions_present_in_vdi(vdi_linux):
        print("Guest Additions already present in disk image; skipping injection.")
        return True

    iso = find_guest_additions_iso()
    if not iso:
        print(
            "[!] VBoxGuestAdditions.iso not found (expected under "
            "C:\\Program Files\\Oracle\\VirtualBox\\ on Windows).\n"
            "    Skipping injection.",
        )
        return False

    ga_dir = work_root / "vbox_ga_extract"
    if ga_dir.exists():
        shutil.rmtree(ga_dir, ignore_errors=True)
    print(f"Extracting Guest Additions installer from {iso} …")
    ga_run = extract_vbox_linux_additions_run(iso, ga_dir)

    print(
        "Injecting Guest Additions into the VDI (virt-customize; may take several minutes)…"
    )
    try:
        subprocess.run(
            [
                vc,
                "-a",
                vdi_linux,
                "--verbose",
                "--update",
                "--run-command",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                "linux-headers-$(uname -r) build-essential dkms bzip2 psmisc",
            ],
            check=True,
        )
        subprocess.run(
            [
                vc,
                "-a",
                vdi_linux,
                "--copy-in",
                f"{ga_run}:/root/VBoxLinuxAdditions.run",
            ],
            check=True,
        )
        subprocess.run(
            [
                vc,
                "-a",
                vdi_linux,
                "--run-command",
                "chmod +x /root/VBoxLinuxAdditions.run",
            ],
            check=True,
        )
        subprocess.run(
            [
                vc,
                "-a",
                vdi_linux,
                "--run-command",
                "DEBIAN_FRONTEND=noninteractive /root/VBoxLinuxAdditions.run --nox11",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(
            f"[!] Guest Additions injection failed ({e}).\n"
            "    You can install manually: Devices → Insert Guest Additions CD image in the VM window.",
        )
        shutil.rmtree(ga_dir, ignore_errors=True)
        return False

    shutil.rmtree(ga_dir, ignore_errors=True)
    print("[+] Guest Additions injected into the VDI. First boot may take a moment.")
    return True


def setup_client_vm(
    *,
    install_guest_additions: bool = True,
    force_poweroff_for_ga: bool = False,
    start_vm: bool = True,
    guest_additions_only: bool = False,
) -> None:
    paths = get_system_paths()
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError("VBoxManage not found. Install VirtualBox or add it to PATH.")

    vm_base = paths["vm_base"]
    vms_root = paths["vms_root"]
    download_dir = paths["downloads"]
    os.makedirs(vm_base, exist_ok=True)
    os.makedirs(vms_root, exist_ok=True)
    os.makedirs(download_dir, exist_ok=True)

    archive_path = os.path.join(download_dir, ARCHIVE_NAME)
    extract_dir = os.path.join(download_dir, "temp_osboxes_client_extract")
    vdi_wsl = os.path.join(vm_base, CLIENT_VDI_NAME)

    # Paths passed to Windows VBoxManage must be Windows-style when running from WSL.
    # ``createvm --basefolder`` must be the *parent* ``VirtualBox VMs`` dir, not ``.../<VM_NAME>``.
    if paths["is_wsl"]:
        vdi_for_vbox = wsl_to_windows_path(vdi_wsl)
        vms_root_for_vbox = wsl_to_windows_path(vms_root)
    else:
        vdi_for_vbox = vdi_wsl
        vms_root_for_vbox = vms_root

    if os.path.exists(vdi_wsl):
        print(f"VDI already exists at {vdi_wsl}; skipping download/extract.")
    else:
        if not os.path.exists(archive_path):
            print(f"Downloading OSBoxes archive to {archive_path}...")
            r = requests.get(OSBOXES_URL, stream=True, allow_redirects=True, timeout=120)
            r.raise_for_status()
            with open(archive_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

        print("Extracting VDI (requires p7zip: sudo apt install p7zip-full)...")
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        os.makedirs(extract_dir, exist_ok=True)
        subprocess.run(["7z", "x", archive_path, f"-o{extract_dir}", "-y"], check=True)

        found_vdi: str | None = None
        for root, _, files in os.walk(extract_dir):
            for name in files:
                if name.lower().endswith((".vdi", ".vmdk")):
                    found_vdi = os.path.join(root, name)
                    break
            if found_vdi:
                break

        if not found_vdi:
            raise RuntimeError("No .vdi/.vmdk found inside OSBoxes archive.")
        shutil.copy2(found_vdi, vdi_wsl)
        shutil.rmtree(extract_dir, ignore_errors=True)

    work_root = Path(download_dir)

    do_ga = guest_additions_only or install_guest_additions
    if do_ga:
        inject_guest_additions_into_vdi(
            vdi_wsl,
            vboxmanage,
            VM_NAME,
            work_root,
            force_poweroff=force_poweroff_for_ga,
        )
    elif not guest_additions_only:
        print("Skipping Guest Additions injection (--skip-guest-additions).")

    if guest_additions_only:
        print("Guest Additions step finished (--guest-additions-only).")
        return

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
                    "Ubuntu_64",
                    "--basefolder",
                    vms_root_for_vbox,
                    "--register",
                ],
            )

    # NIC1 = LAN leg behind OpenWrt (DHCP from OpenWrt br-lan)
    print(
        f"Networking: NIC1 → internal network {LAN_INTNET_NAME!r} "
        f"(attach OpenWrt router NIC2 to the same intnet; start router before client DHCP)."
    )
    run_vboxmanage(
        vboxmanage,
        [
            "modifyvm",
            VM_NAME,
            "--memory",
            "4096",
            "--cpus",
            str(get_half_cpus()),
            "--graphicscontroller",
            "vmsvga",
            "--vram",
            "128",
            "--nic1",
            "intnet",
            "--intnet1",
            LAN_INTNET_NAME,
            # Host ↔ guest cut/paste (needs Guest Additions in the guest; see post-setup message)
            "--clipboard",
            "bidirectional",
        ],
    )

    # SATA controller + disk (ignore error if controller already exists)
    try:
        run_vboxmanage(
            vboxmanage,
            ["storagectl", VM_NAME, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci"],
        )
    except subprocess.CalledProcessError:
        pass

    run_vboxmanage(
        vboxmanage,
        [
            "storageattach",
            VM_NAME,
            "--storagectl",
            "SATA",
            "--port",
            "0",
            "--device",
            "0",
            "--type",
            "hdd",
            "--medium",
            vdi_for_vbox,
        ],
    )

    # Left Ctrl as host key (same as prior script)
    print("Setting host key to Left CTRL...")
    run_vboxmanage(
        vboxmanage,
        ["setextradata", VM_NAME, "GUI/Input/HostKeyCombination", "16777249"],
    )

    print(
        f"\nDone. Start the OpenWrt VM first, then start {VM_NAME}.\n"
        f"In the guest: install a browser if needed (e.g. apt install firefox) and run "
        f"Overdrive ``router/*.py`` with default gateway = OpenWrt LAN IP, or ``--ip`` that IP.\n"
        "\n"
        "--- Clipboard ---\n"
        "VM uses bidirectional shared clipboard. If injection succeeded, log in once; if paste fails,\n"
        "confirm VirtualBox menu: Devices → Shared Clipboard → Bidirectional.\n"
        "Manual fallback: Insert Guest Additions CD image → run VBoxLinuxAdditions.run in the guest.\n"
    )
    if start_vm:
        run_vboxmanage(vboxmanage, ["startvm", VM_NAME, "--type", "gui"])
    else:
        print("Not starting VM (--no-start).")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Create / refresh OpenWrt LAN client VM (VirtualBox).",
    )
    ap.add_argument(
        "--skip-guest-additions",
        action="store_true",
        help="Do not inject Guest Additions into the VDI (shared clipboard will not work until you install manually).",
    )
    ap.add_argument(
        "--force-poweroff-for-ga",
        action="store_true",
        help="If the VM is running, power it off so Guest Additions can be injected into the disk image.",
    )
    ap.add_argument(
        "--no-start",
        action="store_true",
        help="Configure the VM but do not start it.",
    )
    ap.add_argument(
        "--guest-additions-only",
        action="store_true",
        help="Only run the Guest Additions injection step (VDI must exist); then exit.",
    )
    ns = ap.parse_args()
    setup_client_vm(
        install_guest_additions=not ns.skip_guest_additions,
        force_poweroff_for_ga=ns.force_poweroff_for_ga,
        start_vm=not ns.no_start,
        guest_additions_only=ns.guest_additions_only,
    )
