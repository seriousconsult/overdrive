#!/usr/bin/env python3
import gzip
import os
import platform
import shutil
import subprocess
import urllib.request
from pathlib import Path

"""Create a basic OpenWrt router VM in VirtualBox from WSL or native Linux.

Two network legs (typical home-router style in a lab):
  * NIC1 — WAN: bridged to the host’s physical adapter (or VirtualBox NAT if no bridge is found)
  * NIC2 — LAN: internal network; attach other VMs with the same intnet name to sit “behind” OpenWrt
"""

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
            "vm_base": os.path.join(linux_home, "VirtualBox VMs", VM_NAME),
        }
    return {
        "is_wsl": False,
        "linux_home": linux_home,
        "win_profile": None,
        "img_path": os.path.join(linux_home, "Downloads", IMAGE_NAME),
        "vm_base": os.path.join(linux_home, "VirtualBox VMs", VM_NAME),
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


def setup_openwrt_vm() -> None:
    paths = get_system_paths()
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError("VBoxManage not found. Install VirtualBox or add it to PATH.")

    img_path = paths["img_path"]
    vm_base = paths["vm_base"]
    vdi_path = os.path.join(vm_base, VDI_NAME)
    os.makedirs(vm_base, exist_ok=True)

    download_openwrt_image(OPENWRT_URL, img_path)

    src_path = wsl_to_windows_path(img_path) if paths["is_wsl"] else img_path
    dst_path = wsl_to_windows_path(vdi_path) if paths["is_wsl"] else vdi_path

    if not os.path.exists(vdi_path):
        print("Converting raw image to VDI...")
        run_vboxmanage(vboxmanage, ["convertfromraw", src_path, dst_path, "--format", "VDI"])
    else:
        print("VDI already exists; skipping conversion.")

    registered_vms = subprocess.run([vboxmanage, "list", "vms"], capture_output=True, text=True, check=True).stdout
    if f'"{VM_NAME}"' not in registered_vms:
        vmx_file = os.path.join(vm_base, f"{VM_NAME}.vbox")
        if os.path.exists(vmx_file):
            run_vboxmanage(vboxmanage, ["registervm", vmx_file])
        else:
            run_vboxmanage(vboxmanage, ["createvm", "--name", VM_NAME, "--ostype", "Linux_64", "--basefolder", vm_base, "--register"])

    bridge_interface = get_active_bridged_interface(vboxmanage)
    if bridge_interface:
        wan_args = ["--nic1", "bridged", "--bridgeadapter1", bridge_interface]
        wan_note = f"bridged → {bridge_interface!r} (WAN / uplink)"
    else:
        wan_args = ["--nic1", "nat"]
        wan_note = "NAT (WAN fallback — no bridged adapter resolved)"

    lan_args = ["--nic2", "intnet", "--intnet2", LAN_INTNET_NAME]

    print(f"Configuring VM {VM_NAME}…")
    print(f"  WAN (NIC1): {wan_note}")
    print(
        f"  LAN (NIC2): internal network {LAN_INTNET_NAME!r} — "
        "client VMs use e.g. "
        f"`VBoxManage modifyvm <vm> --nic1 intnet --intnet1 {LAN_INTNET_NAME}`"
    )
    print(
        "  In OpenWrt, map NIC1→WAN and NIC2→LAN (often eth0 / eth1); "
        "assign LAN subnet & DHCP under Network → Interfaces."
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
            *wan_args,
            *lan_args,
        ],
    )

    try:
        run_vboxmanage(vboxmanage, ["storagectl", VM_NAME, "--name", "IDE", "--remove"])
    except subprocess.CalledProcessError:
        pass

    run_vboxmanage(vboxmanage, ["storagectl", VM_NAME, "--name", "IDE", "--add", "ide", "--controller", "PIIX4"])
    run_vboxmanage(vboxmanage, ["storageattach", VM_NAME, "--storagectl", "IDE", "--port", "0", "--device", "0", "--type", "hdd", "--medium", dst_path])

    print("Starting VM...")
    run_vboxmanage(vboxmanage, ["startvm", VM_NAME, "--type", "gui"])


if __name__ == "__main__":
    setup_openwrt_vm()
