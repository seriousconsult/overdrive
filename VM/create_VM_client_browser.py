#!/usr/bin/env python3
"""
Create a Linux VM in VirtualBox for use **behind** the OpenWrt router from
``create_VM_OpenWrt_router.py``.

The default OSBoxes image is **Ubuntu Server** (URL contains ``svr``): first boot ends at a **text
console** (``osboxes login:``), not a full desktop. A black screen with green ``[ OK ]`` lines is
normal—it is **not** frozen. Click the VM window, press **Enter**, log in, then optionally install a
desktop (see printed hints). Confirm current password on https://www.osboxes.org/

Networking (lab):
  * **NIC1** — VirtualBox **internal network** ``openwrt-lan`` (same name as the router’s LAN leg).
    The guest gets DHCP from OpenWrt’s LAN; default gateway is the OpenWrt LAN IP (e.g. 192.168.1.1).

The client often has **no path to the Internet** until OpenWrt DHCP works, so **this script** (on the
**WSL host**, which does have Internet) runs ``virt-customize`` to pre-install ``isc-dhcp-client``,
``ping``, ``dig``, and a ``lab-net-troubleshoot`` helper **into the VDI before first lab boot**. Use
``--skip-vdi-prime`` only if you know what you are doing.

This VM is **not** bridged to your Windows/WSL LAN. WSL **mirrored** mode only affects the Linux
namespace on the host; it does not change VirtualBox intnet isolation. To browse from the host
through OpenWrt, use RDP/guest tools or a second setup—this script targets the standard “client on
router LAN” topology.


Requires: ``VBoxManage``, ``7z``. **Strongly recommended:** ``virt-customize``
(``sudo apt install libguestfs-tools`` on WSL) so the guest gets DHCP tools without in-guest ``apt``.
Network on the **host** for OSBoxes download + ``virt-customize`` package installs into the VDI.
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

# Ubuntu 24.10 **Server** from OSBoxes (no GUI until you install one in the guest).
OSBOXES_URL = (
    "https://downloads.sourceforge.net/project/osboxes/v/vb/59-U-u-svr/24.10/64bit.7z"
)
ARCHIVE_NAME = "ubuntu_osboxes_2410.7z"
# Default OSBoxes credentials (verify on the OSBoxes download page for this image).
OSBOXES_LOGIN_USER = "osboxes"
OSBOXES_LOGIN_PASSWORD_HINT = "osboxes.org"

# If VDI priming was skipped and the guest somehow has Internet, this still works:
IN_GUEST_INSTALL_ISC_DHCP_CLIENT = "sudo apt install -y isc-dhcp-client"

# Installed into the guest by ``prime_client_vdi_for_intnet_lab`` (host-side virt-customize).
LAB_NET_TROUBLESHOOT_SCRIPT = r"""#!/bin/bash
# Installed by create_VM_client_browser.py — run: lab-net-troubleshoot  (uses sudo when needed)
set -u
echo "================================================================"
echo " Lab network troubleshoot (OpenWrt intnet client)"
echo " Run: lab-net-troubleshoot   (or sudo lab-net-troubleshoot)"
echo "================================================================"
echo ""
echo "=== IPv4 addresses ==="
ip -br -4 addr 2>/dev/null || true
echo ""
echo "=== Routes ==="
ip route 2>/dev/null || true
echo ""
echo "=== Default IPv4 route ==="
if ip -4 route show default 2>/dev/null | grep -q .; then
  ip -4 route show default
else
  echo "(none) — no DHCP lease or no gateway from OpenWrt."
fi
echo ""
echo "=== DHCP on each Ethernet-like interface ==="
if ! command -v dhclient >/dev/null 2>&1; then
  echo "ERROR: dhclient missing. Re-run create_VM_client_browser.py on WSL with libguestfs-tools."
  exit 1
fi
for IFACE in /sys/class/net/*; do
  IFACE=$(basename "$IFACE")
  [ "$IFACE" = lo ] && continue
  [ ! -e "/sys/class/net/$IFACE/device" ] && continue
  echo "--- dhclient $IFACE ---"
  if [ "$(id -u)" -eq 0 ]; then
    dhclient -v -1 "$IFACE" 2>&1 | tail -25 || true
  else
    sudo dhclient -v -1 "$IFACE" 2>&1 | tail -25 || true
  fi
done
echo ""
echo "=== After DHCP ==="
ip -br -4 addr 2>/dev/null || true
ip -4 route show default 2>/dev/null || true
echo ""
echo "=== Static fallback (OpenWrt LAN often 192.168.1.1/24) ==="
echo "  IFACE=enp0s3    # from: ip -br link"
echo '  sudo ip addr flush dev "$IFACE" 2>/dev/null || true'
echo '  sudo ip addr add 192.168.1.50/24 dev "$IFACE"'
echo '  sudo ip link set "$IFACE" up'
echo '  sudo ip route replace default via 192.168.1.1 dev "$IFACE"'
echo "  ping -c2 192.168.1.1"
echo ""
if command -v dig >/dev/null 2>&1; then
  echo "=== dig via router (optional) ==="
  dig +short @192.168.1.1 openwrt.org 2>/dev/null || true
fi
"""


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


def prime_client_vdi_for_intnet_lab(
    vdi_linux: str,
    vboxmanage: str,
    vm_name: str,
    work_root: Path,
    *,
    force_poweroff: bool,
    skip_prime: bool,
) -> bool:
    """
    On the **WSL/Linux host** (which has Internet), inject DHCP client, ping, dig, and
    ``lab-net-troubleshoot`` into the VDI so the guest works **without** in-guest ``apt`` when
    OpenWrt has not yet provided a route.
    """
    if skip_prime:
        print(
            "[!] --skip-vdi-prime: skipping offline lab network tools. "
            "The guest may have no dhclient until you fix networking another way."
        )
        return False

    vc = shutil.which("virt-customize")
    if not vc:
        print(
            "\n" + "*" * 62 + "\n"
            "WARNING: ``virt-customize`` not found (install libguestfs-tools on **this** WSL host).\n"
            "  sudo apt install -y libguestfs-tools\n"
            "Without it, the lab client may ship **without** dhclient. If OpenWrt DHCP fails, the\n"
            "guest has **no Internet**, so ``apt install isc-dhcp-client`` inside the guest will fail.\n"
            "Re-run this script after installing libguestfs-tools (VM powered off).\n" + "*" * 62 + "\n"
        )
        return False

    if not _poweroff_vm_for_vdi_edit(vboxmanage, vm_name, force_poweroff=force_poweroff):
        print("[!] VDI priming skipped (VM running). Power off or use --force-poweroff-for-vdi.")
        return False

    script_host = work_root / "lab_net_troubleshoot.sh"
    script_host.write_text(LAB_NET_TROUBLESHOOT_SCRIPT, encoding="utf-8")
    script_host.chmod(0o644)

    print(
        "Priming VDI on **host** (virt-customize): isc-dhcp-client, ping, dig, lab-net-troubleshoot…"
    )
    try:
        subprocess.run(
            [
                vc,
                "-a",
                vdi_linux,
                "--update",
                "--run-command",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                "isc-dhcp-client iputils-ping dnsutils",
            ],
            check=True,
        )
        subprocess.run(
            [
                vc,
                "-a",
                vdi_linux,
                "--copy-in",
                f"{script_host.resolve()}:/usr/local/bin/lab-net-troubleshoot",
            ],
            check=True,
        )
        subprocess.run(
            [
                vc,
                "-a",
                vdi_linux,
                "--chmod",
                "0755:/usr/local/bin/lab-net-troubleshoot",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"[!] VDI priming failed ({e}). Fix WSL networking/apt, then re-run with VM off.")
        return False

    print(
        "[+] VDI primed: guest has dhclient/ping/dig + ``lab-net-troubleshoot`` (no in-guest apt needed)."
    )
    return True


def _poweroff_vm_for_vdi_edit(
    vboxmanage: str, vm_name: str, *, force_poweroff: bool
) -> bool:
    """Return True if the VM is off (or we powered it off)."""
    state = get_vm_state(vboxmanage, vm_name)
    if state not in ("running", "paused"):
        return True
    if not force_poweroff:
        print(
            f"[!] VM {vm_name!r} is {state}; power it off to modify the VDI, "
            "or pass --force-poweroff-for-vdi."
        )
        return False
    print(f"Powering off {vm_name} for VDI maintenance…")
    subprocess.run([vboxmanage, "controlvm", vm_name, "poweroff"], check=False)
    for _ in range(30):
        time.sleep(1)
        st = get_vm_state(vboxmanage, vm_name)
        if st in (None, "poweroff", "aborted"):
            return True
    print("[!] VM did not power off in time.")
    return False


def setup_client_vm(
    *,
    force_poweroff_for_vdi: bool = False,
    start_vm: bool = True,
    skip_vdi_prime: bool = False,
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

    prime_client_vdi_for_intnet_lab(
        vdi_wsl,
        vboxmanage,
        VM_NAME,
        work_root,
        force_poweroff=force_poweroff_for_vdi,
        skip_prime=skip_vdi_prime,
    )

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
        "\n"
        "--- Lab networking (no guest Internet required) ---\n"
        "This script should have **pre-installed** dhclient/ping/dig on the **disk from WSL**.\n"
        "After login run:   lab-net-troubleshoot\n"
        "That script renews DHCP and prints static-IP fallback commands if OpenWrt has no DHCP.\n"
        "Only if the guest **does** have Internet and tools are missing:\n"
        f"  sudo apt update && {IN_GUEST_INSTALL_ISC_DHCP_CLIENT}\n"
        "\n"
        "--- If ``ip -4 route show default`` prints nothing ---\n"
        "There is no default IPv4 route (usually DHCP from OpenWrt never ran or failed).\n"
        "• Start the **OpenWrt** VM **before** this client; both NICs must use intnet ``openwrt-lan`` for LAN.\n"
        "• In OpenWrt (LuCI): LAN = static or DHCP **server** on br-lan, firewall zone LAN→WAN allowed.\n"
        "• In the client: ``ip -br a`` and ``ip route`` — confirm an address on the LAN interface.\n"
        "• Run ``lab-net-troubleshoot`` first; only then try ``sudo networkctl renew <iface>``.\n"
        "• Manual test route: ``sudo ip route add default via 192.168.1.1 dev <iface>`` (use your OpenWrt LAN IP).\n"
        "\n"
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
        "--force-poweroff-for-vdi",
        action="store_true",
        help="If the VM is running, power it off so virt-customize can modify the VDI (priming).",
    )
    ap.add_argument(
        "--no-start",
        action="store_true",
        help="Configure the VM but do not start it.",
    )
    ap.add_argument(
        "--skip-vdi-prime",
        action="store_true",
        help="Do not inject DHCP/ping/dig/lab-net-troubleshoot via virt-customize (not recommended).",
    )
    ns = ap.parse_args()
    setup_client_vm(
        force_poweroff_for_vdi=ns.force_poweroff_for_vdi,
        start_vm=not ns.no_start,
        skip_vdi_prime=ns.skip_vdi_prime,
    )
