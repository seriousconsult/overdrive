#!/usr/bin/env python3
r"""
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


Serial console named pipe:
  1. The VM serial port is the "hole in the wall": a small text-only COM port that is separate
     from Internet, Wi-Fi, DHCP, and graphics.
  2. The VirtualBox named pipe / host socket is the "plastic tube" attached to that serial port.
     One end is connected to the VM; the other end appears on the Linux host as a Unix socket such
     as ``/tmp/OpenWrt_LAN_Client_serial.sock``. If WSL is controlling Windows VirtualBox through
     ``VBoxManage.exe``, the host end is instead the Windows pipe
     ``\\.\pipe\OpenWrt_LAN_Client_serial``.
  3. ``socat`` + ``screen`` is the "walkie-talkie" on Linux/WSL. Connect ``socat`` to the Unix
     socket, have it create a temporary PTY, then attach ``screen`` at ``115200`` baud. Anything
     typed there goes into the VM serial login; anything the VM writes to the serial console comes
     back to your terminal.


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
import sys
import time
from pathlib import Path

import requests
from requests.exceptions import RequestException

# Ensure sibling common/ package is importable when running this script from VM/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from common.common_vm import (
    is_wsl_environment,
    wsl_to_windows_path,
    get_system_paths,
    find_vboxmanage,
    get_half_cpus,
    run_vboxmanage,
    resolve_vbox_settings_path,
    vbox_closemedium_disk_delete_best_effort,
    try_unregistervm_delete,
    vm_is_registered,
    get_vm_state,
)

# Must match ``LAN_INTNET_NAME`` in create_VM_OpenWrt_router.py
LAN_INTNET_NAME = "openwrt-lan"

VM_NAME = "OpenWrt_LAN_Client"
CLIENT_VDI_NAME = "client_browser.vdi"
SERIAL_WINDOWS_PIPE_NAME = r"\\.\pipe\OpenWrt_LAN_Client_serial"
SERIAL_UNIX_SOCKET_PATH = "/tmp/OpenWrt_LAN_Client_serial.sock"
SERIAL_PTY_LINK_PATH = "/tmp/OpenWrt_LAN_Client_serial.pty"
SERIAL_BAUD = "115200"

# Ubuntu 24.04 **Server** from OSBoxes (no GUI until you install one in the guest).
OSBOXES_URL = (
    "https://sourceforge.net/projects/osboxes/files/v/vm/59-Uu--svr/24.04/64bit.7z/download"
)
ARCHIVE_NAME = "ubuntu_osboxes_2404.7z"
# Default OSBoxes credentials (verify on the OSBoxes download page for this image).
OSBOXES_LOGIN_USER = "osboxes"
OSBOXES_LOGIN_PASSWORD_HINT = "osboxes.org"


def download_osboxes_archive(url: str, archive_path: str) -> None:
    """Download the OSBoxes archive with a useful error when the host has no route."""
    print(f"Downloading OSBoxes archive to {archive_path}...")
    try:
        r = requests.get(url, stream=True, allow_redirects=True, timeout=120)
        r.raise_for_status()
    except RequestException as e:
        raise RuntimeError(
            "Could not download the OSBoxes archive.\n"
            f"  URL: {url}\n"
            f"  Destination: {archive_path}\n"
            f"  Error: {e}\n\n"
            "Your shell currently has no working outbound network route, or SourceForge is "
            "not reachable from it. Download the archive from a machine/network that can "
            "reach SourceForge, then rerun with:\n"
            "  ./create_VM_client_browser.py --archive-path /path/to/ubuntu_osboxes_2404.7z"
        ) from None

    with open(archive_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

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


def guest_serial_console_commands() -> list[str]:
    """Commands run inside the guest image so ttyS0 has a login prompt."""
    return [
        f"systemctl enable serial-getty@ttyS0.service",
        (
            "if [ -f /etc/default/grub ]; then "
            "sed -i "
            "'s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"console=tty0 console=ttyS0,"
            f"{SERIAL_BAUD}n8\"/' "
            "/etc/default/grub; "
            "update-grub || true; "
            "fi"
        ),
    ]


def vboxmanage_targets_windows(vboxmanage: str) -> bool:
    """Return True when WSL/Linux is controlling Windows VirtualBox via VBoxManage.exe."""
    return Path(vboxmanage).name.lower().endswith(".exe")


def serial_pipe_name_for_vbox(vboxmanage: str) -> str:
    """Return the host-side pipe/socket path VirtualBox should expose."""
    if vboxmanage_targets_windows(vboxmanage):
        return SERIAL_WINDOWS_PIPE_NAME
    return SERIAL_UNIX_SOCKET_PATH


def serial_console_instructions(vboxmanage: str, pipe_name: str) -> str:
    """Host-specific commands for attaching to the VM serial console."""
    if vboxmanage_targets_windows(vboxmanage):
        return (
            "--- Serial console named pipe ---\n"
            f"VirtualBox exposes COM1 as: {pipe_name}\n"
            "Because this is Windows VirtualBox, connect with PuTTY on Windows:\n"
            "  Connection type: Serial\n"
            f"  Serial line:     {pipe_name}\n"
            f"  Speed:           {SERIAL_BAUD}\n"
            "Start the VM first, then connect PuTTY to the pipe. The guest should show a ttyS0 login.\n"
        )
    return (
        "--- Serial console host socket ---\n"
        f"VirtualBox exposes COM1 as: {pipe_name}\n"
        "On Linux/WSL, attach with socat plus screen:\n"
        f"  rm -f {SERIAL_PTY_LINK_PATH}\n"
        f"  socat -d -d UNIX-CONNECT:{pipe_name} PTY,link={SERIAL_PTY_LINK_PATH},raw,echo=0\n"
        f"  screen {SERIAL_PTY_LINK_PATH} {SERIAL_BAUD}\n"
        "Run the socat command in one terminal after the VM starts, then screen from another terminal.\n"
        "Detach screen with Ctrl-a then k. The guest should show a ttyS0 login.\n"
    )


def configure_serial_named_pipe(vboxmanage: str, pipe_name: str) -> None:
    """Expose COM1 as a host pipe/socket that a terminal program can attach to."""
    print(
        f"Serial console: COM1 -> host pipe/socket {pipe_name} "
        f"({SERIAL_BAUD} baud; VirtualBox is the pipe server)."
    )
    run_vboxmanage(
        vboxmanage,
        [
            "modifyvm",
            VM_NAME,
            "--uart1",
            "0x3F8",
            "4",
            "--uartmode1",
            "server",
            pipe_name,
        ],
    )











def remove_existing_client_vm(
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
        time.sleep(3)

        print(f"Unregistering and deleting VirtualBox VM {VM_NAME!r} (all media)…")
        if not try_unregistervm_delete(vboxmanage, VM_NAME):
            raise RuntimeError(
                f"Could not unregister {VM_NAME!r} (VirtualBox still has it locked). "
                "Close any window showing that VM, exit stray VBoxManage sessions, then re-run."
            )

    vbox_closemedium_disk_delete_best_effort(vboxmanage, medium_path_for_vbox)

    if os.path.isdir(vm_base):
        print(f"Removing leftover VM directory {vm_base!r}…")
        shutil.rmtree(vm_base, ignore_errors=True)



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
        for command in guest_serial_console_commands():
            subprocess.run([vc, "-a", vdi_linux, "--run-command", command], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] VDI priming failed ({e}). Fix WSL networking/apt, then re-run with VM off.")
        return False

    print(
        "[+] VDI primed: guest has dhclient/ping/dig, ``lab-net-troubleshoot``, "
        "and a ttyS0 serial login."
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
    archive_override: str | None = None,
) -> None:
    paths = get_system_paths(VM_NAME)
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError("VBoxManage not found. Install VirtualBox or add it to PATH.")

    vm_base = paths["vm_base"]
    vms_root = paths["vms_root"]
    download_dir = paths["downloads"]
    os.makedirs(download_dir, exist_ok=True)
    serial_pipe_name = serial_pipe_name_for_vbox(vboxmanage)

    archive_path = archive_override or os.path.join(download_dir, ARCHIVE_NAME)
    if archive_override:
        archive_path = os.path.abspath(os.path.expanduser(archive_path))
        if not os.path.isfile(archive_path):
            raise RuntimeError(f"--archive-path does not exist or is not a file: {archive_path}")
    elif not os.path.exists(archive_path):
        download_osboxes_archive(OSBOXES_URL, archive_path)
    else:
        print(f"Using OSBoxes archive at {archive_path}")

    # Remove any stale client VM registration/files from prior runs before recreating.
    remove_existing_client_vm(
        vboxmanage,
        vm_base,
        medium_path_for_vbox=wsl_to_windows_path(os.path.join(vm_base, CLIENT_VDI_NAME))
        if paths["is_wsl"]
        else os.path.join(vm_base, CLIENT_VDI_NAME),
    )

    os.makedirs(vm_base, exist_ok=True)
    os.makedirs(vms_root, exist_ok=True)

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
        f"(OpenWrt router LAN is NIC1 on the same intnet; start router before client DHCP)."
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
    configure_serial_named_pipe(vboxmanage, serial_pipe_name)

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
        "• Start the **OpenWrt** VM **before** this client; router **LAN (NIC1)** and this client **NIC1** must use intnet ``openwrt-lan``.\n"
        "• In OpenWrt (LuCI): LAN = static or DHCP **server** on br-lan, firewall zone LAN→WAN allowed.\n"
        "• In the client: ``ip -br a`` and ``ip route`` — confirm an address on the LAN interface.\n"
        "• Run ``lab-net-troubleshoot`` first; only then try ``sudo networkctl renew <iface>``.\n"
        "• Manual test route: ``sudo ip route add default via 192.168.1.1 dev <iface>`` (use your OpenWrt LAN IP).\n"
        "\n"
    )
    print(serial_console_instructions(vboxmanage, serial_pipe_name))
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
    ap.add_argument(
        "--archive-path",
        help=(
            "Use an already downloaded OSBoxes 24.04 7z archive instead of downloading "
            f"{ARCHIVE_NAME} into ~/Downloads."
        ),
    )
    ns = ap.parse_args()
    setup_client_vm(
        force_poweroff_for_vdi=ns.force_poweroff_for_vdi,
        start_vm=not ns.no_start,
        skip_vdi_prime=ns.skip_vdi_prime,
        archive_override=ns.archive_path,
    )
