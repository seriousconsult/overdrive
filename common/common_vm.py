#!/usr/bin/env python3
"""Shared VirtualBox and WSL helpers used by VM setup scripts."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

__all__ = [
    "is_wsl_environment",
    "get_linux_distro_id",
    "wsl_to_windows_path",
    "get_system_paths",
    "find_vboxmanage",
    "get_vboxmanage_install_hint",
    "get_half_cpus",
    "run_vboxmanage",
    "resolve_vbox_settings_path",
    "vbox_closemedium_disk_delete_best_effort",
    "try_unregistervm_delete",
    "vm_is_registered",
    "get_vm_state",
    "get_active_bridged_interface",
]


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
