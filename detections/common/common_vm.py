#!/usr/bin/env python3
"""Shared VirtualBox and WSL helpers used by VM setup scripts."""

from __future__ import annotations

import functools
import os
import platform
import shutil
import socket
import subprocess
import sys
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
    "MULLVAD_DOT_RESOLVERS",
    "MULLVAD_DOT_PORT",
    "OPENWRT_LAN_DNS",
    "OPENWRT_STUBBY_LISTEN",
    "OSBOXES_ARCHIVE_NAME",
    "OSBOXES_LOGIN_PASSWORD_HINT",
    "OSBOXES_LOGIN_USER",
    "OSBOXES_URL",
    "SERIAL_BAUD",
    "SERIAL_PTY_LINK_PATH",
    "SERIAL_TCP_HOST",
    "SERIAL_TCP_PORT",
    "SERIAL_UNIX_SOCKET_PATH",
    "ROUTER_SERIAL_PTY_LINK_PATH",
    "ROUTER_SERIAL_TCP_PORT",
    "ROUTER_SERIAL_UNIX_SOCKET_PATH",
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
    "serial_tcp_host_candidates",
    "serial_uart_mode_and_endpoint",
    "spawn_wsl_interactive_terminal",
    "spawn_serial_console_window",
    "start_vm_headless_safe",
    "ensure_vm_ready_to_start",
    "close_medium_best_effort",
    "wait_after_disk_operation",
    "wsl_windows_host_ip",
    "try_unregistervm_delete",
    "vbox_closemedium_disk_delete_best_effort",
    "vm_is_registered",
    "wsl_to_windows_path",
    "windows_temp_dir_linux",
]

OPENWRT_ROUTER_VM_NAME = "OpenWrt_2026_Router"
OPENWRT_CLIENT_VM_NAME = "OpenWrt_LAN_Client"
OPENWRT_LAN_INTNET_NAME = "openwrt-lan"

SERIAL_TCP_HOST = "127.0.0.1"
SERIAL_TCP_PORT = 2323  # OpenWrt_LAN_Client COM1
SERIAL_UNIX_SOCKET_PATH = "/tmp/OpenWrt_LAN_Client_serial.sock"
SERIAL_PTY_LINK_PATH = "/tmp/OpenWrt_LAN_Client_serial.pty"
SERIAL_BAUD = "115200"

# OpenWrt router uses a different host TCP port so both VMs can expose COM1 at once.
ROUTER_SERIAL_TCP_PORT = 2324
ROUTER_SERIAL_UNIX_SOCKET_PATH = "/tmp/OpenWrt_2026_Router_serial.sock"
ROUTER_SERIAL_PTY_LINK_PATH = "/tmp/OpenWrt_2026_Router_serial.pty"

OPENWRT_URL = "https://downloads.openwrt.org/releases/25.12.2/targets/x86/64/openwrt-25.12.2-x86-64-generic-ext4-combined.img.gz"
OPENWRT_IMAGE_NAME = "openwrt_2026.img"
OPENWRT_VDI_NAME = "openwrt.vdi"

# Mullvad public DNS-over-TLS (DoT). Plain UDP/53 is refused; use stubby on OpenWrt.
# https://mullvad.net/en/help/dns-over-https-and-dns-over-tls
MULLVAD_DOT_RESOLVERS: tuple[tuple[str, str], ...] = (
    ("194.242.2.2", "dns.mullvad.net"),  # unfiltered
    ("194.242.2.4", "base.dns.mullvad.net"),  # ads/trackers/malware block
)
MULLVAD_DOT_PORT = 853
OPENWRT_LAN_DNS = "192.168.1.1"
OPENWRT_STUBBY_LISTEN = "127.0.0.1#5453"

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


@functools.lru_cache(maxsize=1)
def _windows_cmd_available() -> bool:
    """True when ``cmd.exe`` interop works (optional Windows helper, not required for VM setup)."""
    if os.name == "nt":
        return True
    if not is_wsl_environment() or shutil.which("cmd.exe") is None:
        return False
    try:
        proc = subprocess.run(
            ["cmd.exe", "/c", "echo", "ok"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return proc.returncode == 0 and "ok" in proc.stdout
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def wsl_windows_host_ip() -> str | None:
    """Return the Windows host IP as seen from WSL2 (for Windows-local TCP services)."""
    if not is_wsl_environment():
        return None
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as resolv:
            for line in resolv:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    return parts[1]
    except OSError:
        return None
    return None


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


def windows_to_wsl_path(path: str | Path) -> str:
    """Convert a Windows path to a WSL path when possible."""
    path_str = str(path)
    try:
        proc = subprocess.run(
            ["wslpath", "-u", path_str],
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout.strip()
    except Exception:
        return path_str
    

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


def windows_temp_dir_linux() -> Path | None:
    """Return Windows %TEMP% as a WSL path when cmd.exe interop is available."""
    if not is_wsl_environment() or not _windows_cmd_available():
        return None
    try:
        proc = subprocess.run(
            ["cmd.exe", "/c", "echo", "%TEMP%"],
            capture_output=True,
            text=True,
            check=True,
        )
        win_temp = proc.stdout.strip()
        if not win_temp or win_temp == "%TEMP%":
            return None
        wsl = subprocess.run(
            ["wslpath", win_temp],
            capture_output=True,
            text=True,
            check=True,
        )
        path = Path(wsl.stdout.strip())
        path.mkdir(parents=True, exist_ok=True)
        return path
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return None


def vboxmanage_targets_windows(vboxmanage: str) -> bool:
    """True when this shell is controlling Windows VirtualBox through VBoxManage.exe."""
    return Path(vboxmanage).name.lower().endswith(".exe")




def get_system_paths(vm_name: str, image_name: str | None = None) -> dict[str, str | bool | None]:
    linux_home = str(Path.home())
    win_profile: str | None = None

    if is_wsl_environment() and _windows_cmd_available():
        try:
            proc = subprocess.run(
                ["cmd.exe", "/c", "echo", "%USERPROFILE%"],
                capture_output=True,
                text=True,
                check=True,
            )
            candidate = proc.stdout.strip()
            if candidate and candidate != "%USERPROFILE%":
                win_profile = candidate
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            win_profile = None

    # IMPORTANT: when we have a Windows profile, store downloads/VMs on Windows filesystem
    # so VBoxManage.exe can access them via C:\... (not \\wsl.localhost\...).
    if win_profile:
        linux_home = windows_to_wsl_path(win_profile)  # typically /mnt/c/Users/<name>

    downloads = os.path.join(linux_home, "Downloads")
    vms_root = os.path.join(linux_home, "VirtualBox VMs")
    vm_base = os.path.join(vms_root, vm_name)

    paths: dict[str, str | bool | None] = {
        "is_wsl": is_wsl_environment(),
        "linux_home": linux_home,
        "win_profile": win_profile,
        "base_path": linux_home,
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
    stream = kwargs.pop("stream", False)
    capture_output = kwargs.pop("capture_output", not stream)
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
            if stream:
                print()
            return

        output = ""
        if capture_output:
            output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        lower = output.lower()
        locked = (
            "already locked for a session" in lower
            or "being unlocked" in lower
            or "locking of attached media" in lower
            or "vbox_e_invalid_object_state" in lower
            or "0x80bb0007" in lower
        )
        if locked and attempt < lock_retries:
            if attempt == 0:
                print("VirtualBox still has a machine lock; waiting and retrying...")
            if attempt == 5 and (is_wsl_environment() or os.name == "nt"):
                print("Clearing stale VBoxManage.exe processes that may hold disk locks...")
                terminate_stale_vboxmanage_processes()
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


def terminate_stale_vboxmanage_processes() -> None:
    """Kill orphan Windows VBoxManage.exe processes that hold disk locks after failed runs."""
    if not _windows_cmd_available():
        return
    subprocess.run(
        ["cmd.exe", "/c", "taskkill", "/F", "/IM", "VBoxManage.exe"],
        capture_output=True,
        text=True,
        check=False,
    )
    time.sleep(1)


def close_medium_best_effort(vboxmanage: str, medium_linux: str) -> None:
    """Close a disk medium in VirtualBox if it is still open (e.g. after clonemedium)."""
    medium = (
        wsl_to_windows_path(medium_linux)
        if vboxmanage_targets_windows(vboxmanage)
        else medium_linux
    )
    subprocess.run(
        [vboxmanage, "closemedium", "disk", medium],
        capture_output=True,
        text=True,
        check=False,
    )


def wait_after_disk_operation(vboxmanage: str, *, seconds: float = 5.0) -> None:
    """Pause after VDI clone/edit so Windows VirtualBox can release media locks."""
    print(f"Waiting {seconds:.0f}s for VirtualBox to release disk locks...")
    time.sleep(seconds)


def ensure_vm_ready_to_start(vboxmanage: str, vm_name: str, *, wait_s: int = 60) -> None:
    """Power off and discard saved state so startvm can attach media."""
    state = get_vm_state(vboxmanage, vm_name)
    if state is None:
        return
    if state == "saved":
        run_vboxmanage(vboxmanage, ["discardstate", vm_name])
        state = get_vm_state(vboxmanage, vm_name)
    if state in ("running", "paused", "stopping", "starting"):
        run_vboxmanage(
            vboxmanage,
            ["controlvm", vm_name, "poweroff"],
            lock_retries=20,
            lock_retry_s=2.0,
        )
        for _ in range(wait_s):
            time.sleep(1)
            st = get_vm_state(vboxmanage, vm_name)
            if st in (None, "poweroff", "aborted"):
                break


def start_vm_headless_safe(vboxmanage: str, vm_name: str) -> None:
    """Start a VM headless after clearing stale locks from recent disk operations."""
    if get_vm_state(vboxmanage, vm_name) == "running":
        return
    terminate_stale_vboxmanage_processes()
    ensure_vm_ready_to_start(vboxmanage, vm_name)
    wait_after_disk_operation(vboxmanage)
    run_vboxmanage(
        vboxmanage,
        ["startvm", vm_name, "--type", "separate"],
        lock_retries=30,
        lock_retry_s=2.0,
    )


def serial_endpoint_for_vbox(
    vboxmanage: str,
    *,
    tcp_port: int | None = None,
    unix_path: str | None = None,
) -> str:
    """Return the host-side serial endpoint VirtualBox should expose."""
    if vboxmanage_targets_windows(vboxmanage):
        return str(tcp_port if tcp_port is not None else SERIAL_TCP_PORT)
    return unix_path or SERIAL_UNIX_SOCKET_PATH


def serial_uart_mode_and_endpoint(
    vboxmanage: str,
    *,
    tcp_port: int | None = None,
    unix_path: str | None = None,
) -> tuple[str, str]:
    """Return the ``VBoxManage --uartmode1`` mode and endpoint."""
    if vboxmanage_targets_windows(vboxmanage):
        return "tcpserver", str(tcp_port if tcp_port is not None else SERIAL_TCP_PORT)
    return "server", unix_path or SERIAL_UNIX_SOCKET_PATH


def serial_tcp_host_candidates(base_host: str | None = None) -> list[str]:
    """Hosts to try when reaching VirtualBox's Windows TCP serial server from WSL."""
    host = base_host or SERIAL_TCP_HOST
    candidates: list[str] = []
    if is_wsl_environment():
        win_host = wsl_windows_host_ip()
        if win_host:
            candidates.append(win_host)
    if host not in candidates:
        candidates.append(host)
    if is_wsl_environment() and "127.0.0.1" not in candidates:
        candidates.append("127.0.0.1")
    return candidates


def spawn_wsl_interactive_terminal(
    command: list[str],
    *,
    cwd: str | Path,
    title: str = "Serial console",
) -> bool:
    """Launch a command in a **new** Windows Terminal window (or a new console)."""
    if not _windows_cmd_available():
        return False
    cwd_str = str(Path(cwd).resolve())
    # Do NOT wrap this in `cmd /C start "title" …` — titles with spaces/parens break
    # and Windows treats the title as a program name ("cannot find '\"…\"'").
    # `wt -w new` already opens a separate window.
    launchers: list[list[str]] = [
        [
            "wt.exe",
            "-w",
            "new",
            "--title",
            title,
            "--",
            "wsl.exe",
            "--cd",
            cwd_str,
            "-e",
            *command,
        ],
        ["wsl.exe", "--cd", cwd_str, "-e", *command],  # may reuse console; last resort
    ]
    for launcher in launchers:
        try:
            # First launcher: new wt window. Avoid shell=True quoting bugs.
            creationflags = 0
            if os.name == "nt" and launcher[0].lower().startswith("wsl"):
                creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
            subprocess.Popen(
                launcher,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
            )
            return True
        except OSError:
            continue
    return False


def _windows_path_from_wsl(path: Path) -> str | None:
    """Convert ``/mnt/c/...`` to ``C:\\...`` when possible."""
    posix = path.resolve().as_posix()
    if posix.startswith("/mnt/") and len(posix) > 6 and posix[6] == "/":
        drive = posix[5].upper()
        rest = posix[7:].replace("/", "\\")
        return f"{drive}:\\{rest}"
    if os.name == "nt":
        return str(path.resolve())
    return None


def spawn_serial_console_window(
    script_path: str | Path,
    *,
    title: str,
    extra_args: list[str] | None = None,
    cwd: str | Path | None = None,
) -> bool:
    """
    Open a **new** terminal window that attaches to a VM serial console.

    The parent shell stays free. The child runs ``script --serial-here …``.
    Uses Windows Terminal ``-w new`` (no ``cmd start`` title quoting).
    """
    script = Path(script_path).resolve()
    work = Path(cwd).resolve() if cwd is not None else script.parent
    args = ["--serial-here", *(extra_args or [])]
    # Avoid parentheses in titles — they confuse cmd/start if any fallback uses it.
    safe_title = title.replace("(", "").replace(")", "").strip()

    # --- Path A: WSL host → new wt window running Linux Python ---
    if is_wsl_environment():
        py = sys.executable or "python3"
        cmd = [py, str(script), *args]
        if spawn_wsl_interactive_terminal(cmd, cwd=work, title=safe_title):
            print(f"[serial] Opened new window: {safe_title}")
            time.sleep(0.5)
            return True

    # --- Path B: Windows Python via wt / new console ---
    if os.name == "nt" or _windows_cmd_available():
        win_script = _windows_path_from_wsl(script) if is_wsl_environment() else str(script)
        win_cwd = _windows_path_from_wsl(work) if is_wsl_environment() else str(work)
        if not win_script:
            win_script = str(script)
        if not win_cwd:
            win_cwd = str(work)

        if is_wsl_environment() or os.name != "nt":
            run_cmd = ["py", "-3", win_script, *args]
        else:
            run_cmd = [sys.executable, win_script, *args]

        launchers: list[list[str]] = [
            ["wt.exe", "-w", "new", "--title", safe_title, "--", "cmd.exe", "/k", *run_cmd],
            ["wt.exe", "-w", "new", "--title", safe_title, "--", *run_cmd],
        ]
        # Last resort: fresh console (native Windows only)
        if os.name == "nt":
            launchers.append(run_cmd)

        for launcher in launchers:
            try:
                kwargs: dict = {
                    "stdout": subprocess.DEVNULL,
                    "stderr": subprocess.DEVNULL,
                }
                if os.name == "nt":
                    kwargs["cwd"] = win_cwd
                    if launcher is launchers[-1] and launcher[0] != "wt.exe":
                        kwargs["creationflags"] = getattr(
                            subprocess, "CREATE_NEW_CONSOLE", 0
                        )
                subprocess.Popen(launcher, **kwargs)
                print(f"[serial] Opened new window: {safe_title}")
                time.sleep(0.5)
                return True
            except OSError:
                continue

    print(
        f"[!] Could not open a new window for {safe_title!r}. "
        f"Run in this terminal: {script.name} --serial-here"
    )
    return False


def probe_tcp_serial(host: str, port: int, timeout_s: float = 2.0) -> tuple[bool, str]:
    """Connect to a VirtualBox TCP serial endpoint without sending bytes."""
    last_error: OSError | None = None
    for candidate in serial_tcp_host_candidates(host):
        try:
            with socket.create_connection((candidate, port), timeout=timeout_s):
                return True, f"CONNECTED ({candidate}:{port})"
        except OSError as exc:
            last_error = exc
    return False, str(last_error) if last_error else "no host candidates"


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
