#!/usr/bin/env python3
"""Shared VirtualBox and WSL helpers used by VM setup scripts."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import time
from pathlib import Path

__all__ = [
    "CLIENT_VDI_NAME",
    "OPENWRT_CLIENT_VM_NAME",
    "OPENWRT_IMAGE_NAME",
    "OPENWRT_LAN_INTNET_NAME",
    "OPENWRT_ROUTER_VM_NAME",
    "OPENWRT_URL",
    "OPENWRT_VDI_NAME",
    "OSBOXES_ARCHIVE_NAME",
    "OSBOXES_LOGIN_PASSWORD_HINT",
    "OSBOXES_LOGIN_USER",
    "OSBOXES_URL",
    "SERIAL_BAUD",
    "SERIAL_PTY_LINK_PATH",
    "SERIAL_TCP_HOST",
    "SERIAL_TCP_PORT",
    "SERIAL_UNIX_SOCKET_PATH",
    "find_vboxmanage",
    "find_vboxmanage_with_windows_fallback",
    "vboxmanage_targets_windows",
    "get_active_bridged_interface",
    "get_half_cpus",
    "get_linux_distro_id",
    "get_system_paths",
    "get_vboxmanage_install_hint",
    "get_vm_state",
    "is_wsl_environment",
    "parse_machinereadable",
    "probe_tcp_serial",
    "remove_existing_vm",
    "resolve_vbox_settings_path",
    "run_vboxmanage",
    "serial_endpoint_for_vbox",
    "serial_uart_mode_and_endpoint",
    "try_unregistervm_delete",
    "vbox_closemedium_disk_delete_best_effort",
    "vm_is_registered",
    "wsl_to_windows_path",
]

OPENWRT_ROUTER_VM_NAME = "OpenWrt_2026_Router"
OPENWRT_CLIENT_VM_NAME = "OpenWrt_LAN_Client"
OPENWRT_LAN_INTNET_NAME = "openwrt-lan"

SERIAL_TCP_HOST = "127.0.0.1"
SERIAL_TCP_PORT = 2323
SERIAL_UNIX_SOCKET_PATH = "/tmp/OpenWrt_LAN_Client_serial.sock"
SERIAL_PTY_LINK_PATH = "/tmp/OpenWrt_LAN_Client_serial.pty"
SERIAL_BAUD = "115200"

OPENWRT_URL = "https://downloads.openwrt.org/releases/25.12.2/targets/x86/64/openwrt-25.12.2-x86-64-generic-ext4-combined.img.gz"
OPENWRT_IMAGE_NAME = "openwrt_2026.img"
OPENWRT_VDI_NAME = "openwrt.vdi"

OSBOXES_URL = "https://sourceforge.net/projects/osboxes/files/v/vm/59-Uu--svr/24.04/64bit.7z/download"
OSBOXES_ARCHIVE_NAME = "ubuntu_osboxes_2404.7z"
OSBOXES_LOGIN_USER = "osboxes"
OSBOXES_LOGIN_PASSWORD_HINT = "osboxes.org"
CLIENT_VDI_NAME = "client_browser.vdi"


def is_wsl_environment() -> bool:
    """Return True when running inside WSL."""
    return "microsoft" in platform.release().lower() or os.path.exists(
        "/proc/sys/fs/binfmt_misc/WSLInterop"
    )


def get_linux_distro_id() -> str | None:
    """Return the lowercase /etc/os-release distro ID on native Linux hosts."""
    if is_wsl_environment() or platform.system().lower() != "linux":
        return None
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.split("=", 1)[1].strip().strip('"').lower()
    except OSError:
        return None
    return None


def wsl_to_windows_path(path: str | Path) -> str:
    """Convert a WSL-style POSIX path to a Windows path when possible."""
    path_str = str(path)
    try:
        result = subprocess.run(
            ["wslpath", "-w", path_str],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        if path_str.startswith("/mnt/"):
            _, drive, rest = path_str.split("/", 2)
            return f"{drive.upper()}:\\{rest.replace('/', '\\')}"
        return path_str


def vboxmanage_targets_windows(vboxmanage: str) -> bool:
    """True when this shell is controlling Windows VirtualBox through VBoxManage.exe."""
    return Path(vboxmanage).name.lower().endswith(".exe")


def get_system_paths(vm_name: str, image_name: str | None = None) -> dict[str, str | bool | None]:
    """Return standard host paths for VirtualBox VM creation and downloads."""
    linux_home = str(Path.home())
    win_profile = None
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

    downloads = os.path.join(linux_home, "Downloads")
    vms_root = os.path.join(linux_home, "VirtualBox VMs")
    vm_base = os.path.join(vms_root, vm_name)

    paths: dict[str, str | bool | None] = {
        "is_wsl": is_wsl_environment(),
        "linux_home": linux_home,
        "win_profile": win_profile,
        "base_path": win_profile if win_profile else linux_home,
        "downloads": downloads,
        "vms_root": vms_root,
        "vm_base": vm_base,
    }
    if image_name:
        paths["img_path"] = os.path.join(downloads, image_name)
    return paths


def find_vboxmanage(paths: dict[str, str | bool | None]) -> str | None:
    """Return the best available VBoxManage executable path."""
    env_path = os.environ.get("VBOXMANAGE")
    if env_path and os.path.exists(env_path):
        return env_path
    if paths.get("is_wsl"):
        windows_path = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
        if os.path.exists(windows_path):
            return windows_path
        return shutil.which("VBoxManage.exe") or shutil.which("VBoxManage")
    for candidate in (
        shutil.which("VBoxManage"),
        shutil.which("vboxmanage"),
        shutil.which("VBoxManage.exe"),
        "/usr/bin/VBoxManage",
        "/usr/lib/virtualbox/VBoxManage",
        "/opt/VirtualBox/VBoxManage",
    ):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def find_vboxmanage_with_windows_fallback(paths: dict[str, str | bool | None]) -> str | None:
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


def get_vboxmanage_install_hint() -> str:
    """Return a host-specific hint for installing or exposing VBoxManage."""
    if is_wsl_environment():
        return (
            "VBoxManage not found. Install VirtualBox on Windows or add it to PATH. "
            "Expected Windows install path from WSL: "
            "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
        )

    distro_id = get_linux_distro_id()
    if distro_id == "fedora":
        return (
            "VBoxManage not found. On Fedora, install VirtualBox from RPM Fusion "
            "(package: VirtualBox), rebuild/load the kernel modules if prompted, "
            "then open a new shell so /usr/bin/VBoxManage is on PATH."
        )
    if distro_id in {"ubuntu", "debian", "linuxmint", "pop"}:
        return (
            "VBoxManage not found. On Ubuntu/Debian, install VirtualBox "
            "(for example: sudo apt install virtualbox) or add VBoxManage to PATH."
        )
    return "VBoxManage not found. Install VirtualBox or add VBoxManage to PATH."


def _vboxmanage_error_hint(output: str) -> str | None:
    lower = output.lower()
    distro_id = get_linux_distro_id()
    if distro_id == "fedora" and (
        "kernel driver not installed" in lower
        or "vboxdrv" in lower
        or "vboxnetflt" in lower
    ):
        return (
            "Fedora hint: VirtualBox is installed, but its kernel modules appear "
            "unavailable. Rebuild/load them for the running kernel (for RPM Fusion "
            "installs this is usually handled by akmods after kernel-devel is present), "
            "then retry."
        )
    if "permission denied" in lower:
        return "Permission hint: run from a user allowed to manage VirtualBox VMs."
    return None


def get_half_cpus() -> int:
    total = os.cpu_count() or 2
    return max(1, total // 2)


def run_vboxmanage(vboxmanage: str, args: list[str], **kwargs) -> None:
    """Run VBoxManage with the provided arguments."""
    print(f"Executing: {vboxmanage} {' '.join(args)}")
    capture_output = kwargs.pop("capture_output", True)
    text = kwargs.pop("text", True)
    lock_retries = int(kwargs.pop("lock_retries", 12))
    lock_retry_s = float(kwargs.pop("lock_retry_s", 1.0))

    for attempt in range(lock_retries + 1):
        result = subprocess.run(
            [vboxmanage] + args,
            capture_output=capture_output,
            text=text,
            **kwargs,
        )
        if result.returncode == 0:
            return

        output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        lower = output.lower()
        locked = (
            "already locked for a session" in lower
            or "being unlocked" in lower
            or "vbox_e_invalid_object_state" in lower
            or "0x80bb0007" in lower
        )
        if locked and attempt < lock_retries:
            if attempt == 0:
                print("VirtualBox still has a machine lock; waiting and retrying...")
            time.sleep(lock_retry_s)
            continue

        hint = _vboxmanage_error_hint(output)
        if hint:
            raise RuntimeError(f"VBoxManage failed: {output}\n\n{hint}") from None
        detail = output or f"exit status {result.returncode}"
        raise RuntimeError(f"VBoxManage failed: {detail}") from None


def resolve_vbox_settings_path(vm_dir: str, vm_name: str) -> str | None:
    """Find an existing .vbox file in either flat or nested VirtualBox folder layouts."""
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


def parse_machinereadable(vboxmanage: str, name: str) -> dict[str, str]:
    """Parse ``VBoxManage showvminfo --machinereadable`` output into a dictionary."""
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
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"')
    return out


def vbox_closemedium_disk_delete_best_effort(vboxmanage: str, medium_path: str) -> None:
    """Remove a disk from VirtualBox media registry and delete the file when possible."""
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
    """Retry unregistering and deleting a VirtualBox VM while it is locked."""
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


def remove_existing_vm(
    vboxmanage: str,
    vm_name: str,
    vm_base: str,
    *,
    medium_path_for_vbox: str,
) -> None:
    """Drop any prior VM registration, registered disk, and leftover VM folder."""
    if vm_is_registered(vboxmanage, vm_name):
        state = get_vm_state(vboxmanage, vm_name)
        if state == "saved":
            print(f"Discarding saved state for {vm_name!r}...")
            subprocess.run(
                [vboxmanage, "discardstate", vm_name], capture_output=True, text=True
            )
            state = get_vm_state(vboxmanage, vm_name)
        if state in ("running", "paused", "stopping", "starting"):
            print(f"Powering off existing VM {vm_name!r} ({state})...")
            subprocess.run([vboxmanage, "controlvm", vm_name, "poweroff"], check=False)
            for _ in range(45):
                time.sleep(1)
                st = get_vm_state(vboxmanage, vm_name)
                if st in (None, "poweroff", "aborted"):
                    break
            else:
                print(
                    f"[!] VM {vm_name!r} did not reach poweroff in time; "
                    "unregister may fail - close the VM window or run ``VBoxManage controlvm ... poweroff``."
                )
        time.sleep(3)

        print(f"Unregistering and deleting VirtualBox VM {vm_name!r} (all media)...")
        if not try_unregistervm_delete(vboxmanage, vm_name):
            raise RuntimeError(
                f"Could not unregister {vm_name!r} (VirtualBox still has it locked). "
                "Close any window showing that VM, exit stray VBoxManage sessions, then re-run."
            )

    vbox_closemedium_disk_delete_best_effort(vboxmanage, medium_path_for_vbox)

    if os.path.isdir(vm_base):
        print(f"Removing leftover VM directory {vm_base!r}...")
        shutil.rmtree(vm_base, ignore_errors=True)


def vm_is_registered(vboxmanage: str, vm_name: str) -> bool:
    r = subprocess.run(
        [vboxmanage, "list", "vms"],
        capture_output=True,
        text=True,
        check=True,
    )
    return f'"{vm_name}"' in r.stdout


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


def serial_endpoint_for_vbox(vboxmanage: str) -> str:
    """Return the host-side serial endpoint VirtualBox should expose."""
    if vboxmanage_targets_windows(vboxmanage):
        return str(SERIAL_TCP_PORT)
    return SERIAL_UNIX_SOCKET_PATH


def serial_uart_mode_and_endpoint(vboxmanage: str) -> tuple[str, str]:
    """Return the ``VBoxManage --uartmode1`` mode and endpoint for the lab client."""
    if vboxmanage_targets_windows(vboxmanage):
        return "tcpserver", str(SERIAL_TCP_PORT)
    return "server", SERIAL_UNIX_SOCKET_PATH


def probe_tcp_serial(host: str, port: int, timeout_s: float = 2.0) -> tuple[bool, str]:
    """Connect to a VirtualBox TCP serial endpoint without sending bytes."""
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True, "CONNECTED"
    except OSError as exc:
        return False, str(exc)


def get_active_bridged_interface(vboxmanage: str) -> str | None:
    """Return the first active bridged adapter name, or the first available adapter."""
    try:
        result = subprocess.run(
            [vboxmanage, "list", "-l", "bridgedifs"],
            capture_output=True,
            text=True,
            check=True,
        )
        blocks = [block for block in result.stdout.split("\n\n") if block.strip()]
        first_name: str | None = None
        for block in blocks:
            attrs: dict[str, str] = {}
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
        return None
