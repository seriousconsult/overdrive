#!/usr/bin/env python3
"""Shared lab VM constants and WSL/serial helpers for QEMU/KVM setup scripts."""

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

from detections.common.common_local import (
    is_wsl_local as _is_wsl_local,
    wsl_windows_host_ip as _wsl_windows_host_ip,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VM_STORAGE_ROOT = REPO_ROOT / "VM"

__all__ = [
    "CLIENT_DISK_NAME",
    "OPENWRT_CLIENT_VM_NAME",
    "OPENWRT_IMAGE_NAME",
    "OPENWRT_LAN_INTNET_NAME",
    "OPENWRT_ROUTER_VM_NAME",
    "TEST_CLIENTA_VM_NAME",
    "TEST_CLIENTK_VM_NAME",
    "TEST_CLIENT_VM_NAME",
    "TEST_LAN_INTNET_NAME",
    "TEST_ROUTER_VM_NAME",
    "LEGACY_CLIENT_VM_NAME",
    "OPENWRT_URL",
    "OPENWRT_QCOW_NAME",
    "OSBOXES_ARCHIVE_NAME",
    "OSBOXES_LOGIN_PASSWORD_HINT",
    "OSBOXES_LOGIN_USER",
    "OSBOXES_URL",
    "SERIAL_BAUD",
    "SERIAL_PTY_LINK_PATH",
    "SERIAL_TCP_HOST",
    "SERIAL_TCP_PORT",
    "SERIAL_UNIX_SOCKET_PATH",
    "CLIENTK_SERIAL_PTY_LINK_PATH",
    "CLIENTK_SERIAL_TCP_PORT",
    "CLIENTK_SERIAL_UNIX_SOCKET_PATH",
    "ROUTER_SERIAL_PTY_LINK_PATH",
    "ROUTER_SERIAL_TCP_PORT",
    "ROUTER_SERIAL_UNIX_SOCKET_PATH",
    "get_half_cpus",
    "get_linux_distro_id",
    "get_system_paths",
    "probe_tcp_serial",
    "remove_lab_vms",
    "serial_tcp_host_candidates",
    "spawn_wsl_interactive_terminal",
    "spawn_serial_console_window",
    "wait_after_disk_operation",
    "ensure_kvm_accessible",
    "wsl_to_windows_path",
    "windows_temp_dir_linux",
    "windows_to_wsl_path",
]

TEST_ROUTER_VM_NAME = "Test_Router"
TEST_CLIENTA_VM_NAME = "Test_Clienta"
TEST_CLIENTK_VM_NAME = "Test_Clientk"
# Back-compat alias for older imports.
TEST_CLIENT_VM_NAME = TEST_CLIENTA_VM_NAME
TEST_LAN_INTNET_NAME = "test-lan"
# Pre-Alpine Ubuntu client (verify_lab still recognizes a registered leftover).
LEGACY_CLIENT_VM_NAME = "Test_Client_Legacy"

# Back-compat aliases used by older imports.
OPENWRT_ROUTER_VM_NAME = TEST_ROUTER_VM_NAME
OPENWRT_CLIENT_VM_NAME = LEGACY_CLIENT_VM_NAME
OPENWRT_LAN_INTNET_NAME = TEST_LAN_INTNET_NAME

SERIAL_TCP_HOST = "127.0.0.1"
SERIAL_TCP_PORT = 2323  # legacy client COM1
SERIAL_UNIX_SOCKET_PATH = "/tmp/Test_Clienta_serial.sock"
SERIAL_PTY_LINK_PATH = "/tmp/Test_Clienta_serial.pty"
SERIAL_BAUD = "115200"

# Test clientk (Kali) serial on a dedicated host TCP port.
CLIENTK_SERIAL_TCP_PORT = 2326
CLIENTK_SERIAL_UNIX_SOCKET_PATH = "/tmp/Test_Clientk_serial.sock"
CLIENTK_SERIAL_PTY_LINK_PATH = "/tmp/Test_Clientk_serial.pty"

# Test router uses a different host TCP port so both VMs can expose COM1 at once.
ROUTER_SERIAL_TCP_PORT = 2324
ROUTER_SERIAL_UNIX_SOCKET_PATH = "/tmp/Test_Router_serial.sock"
ROUTER_SERIAL_PTY_LINK_PATH = "/tmp/Test_Router_serial.pty"

OPENWRT_URL = "https://downloads.openwrt.org/releases/25.12.2/targets/x86/64/openwrt-25.12.2-x86-64-generic-ext4-combined.img.gz"
OPENWRT_IMAGE_NAME = "openwrt_2026.img"
OPENWRT_QCOW_NAME = "openwrt.qcow2"



OSBOXES_URL = "https://sourceforge.net/projects/osboxes/files/v/vm/59-Uu--svr/24.04/64bit.7z/download"
OSBOXES_ARCHIVE_NAME = "ubuntu_osboxes_2404.7z"
OSBOXES_LOGIN_USER = "osboxes"
OSBOXES_LOGIN_PASSWORD_HINT = "configured by OSBOXES_LOGIN_PASSWORD in VM/.env"
CLIENT_DISK_NAME = "client_browser.qcow2"


@functools.lru_cache(maxsize=1)

def ensure_kvm_accessible() -> bool:
    """Make ``/dev/kvm`` usable so libguestfs/qemu use KVM instead of slow TCG emulation."""
    if platform.system().lower() != "linux":
        return False

    kvm = Path("/dev/kvm")
    if not kvm.exists():
        print("[overdrive] /dev/kvm not present; libguestfs will use slow emulation.")
        return False
    if os.access(kvm, os.R_OK | os.W_OK):
        return True

    if not shutil.which("sudo"):
        print("[overdrive] /dev/kvm not accessible and sudo is missing; libguestfs may be slow.")
        return False

    print("[overdrive] Opening /dev/kvm for fast libguestfs (sudo chmod 0666 /dev/kvm)...")
    proc: subprocess.CompletedProcess[str] | None = None
    try:
        proc = subprocess.run(
            ["sudo", "-n", "chmod", "0666", str(kvm)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[overdrive] sudo -n chmod /dev/kvm failed: {exc}")
    else:
        if proc.returncode == 0 and os.access(kvm, os.R_OK | os.W_OK):
            print("[overdrive] /dev/kvm is now accessible (KVM acceleration enabled).")
            return True
        if proc.stderr:
            err = proc.stderr.strip()
            if err:
                print(f"[overdrive] sudo -n chmod /dev/kvm: {err}")

    if sys.stdin.isatty():
        try:
            proc = subprocess.run(
                ["sudo", "chmod", "0666", str(kvm)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"[overdrive] sudo chmod /dev/kvm failed: {exc}")
        else:
            if proc.returncode == 0 and os.access(kvm, os.R_OK | os.W_OK):
                print("[overdrive] /dev/kvm is now accessible (KVM acceleration enabled).")
                return True
            if proc.stderr:
                err = proc.stderr.strip()
                if err:
                    print(f"[overdrive] sudo chmod /dev/kvm: {err}")
    else:
        print(
            "[overdrive] Skipping interactive sudo for /dev/kvm (no TTY). "
            "Run once: sudo chmod 0666 /dev/kvm"
        )

    if os.access(kvm, os.R_OK | os.W_OK):
        return True
    print("[overdrive] /dev/kvm still not accessible; libguestfs will run without KVM (slow).")
    return False

def _windows_cmd_available() -> bool:
    """True when ``cmd.exe`` interop works (optional Windows helper, not required for VM setup)."""
    if os.name == "nt":
        return True
    if not _is_wsl_local() or shutil.which("cmd.exe") is None:
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

def get_linux_distro_id() -> str | None:
    """Return the lowercase /etc/os-release distro ID on native Linux hosts."""
    if _is_wsl_local() or platform.system().lower() != "linux":
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
    if not _is_wsl_local() or not _windows_cmd_available():
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

def get_system_paths(vm_name: str, image_name: str | None = None) -> dict[str, str | bool | None]:
    storage_root = Path(os.environ.get("OVERDRIVE_VM_STORAGE_DIR", str(DEFAULT_VM_STORAGE_ROOT))).expanduser()
    linux_home = str(storage_root)
    win_profile: str | None = None

    if _is_wsl_local() and _windows_cmd_available():
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

    # Keep VM build outputs repo-owned under the Overdrive VM/ tree.
    downloads = os.path.join(linux_home, "downloads")
    # QEMU/KVM lab VMs live under lab_vms/.
    vms_root = os.path.join(linux_home, "lab_vms")
    vm_base = os.path.join(vms_root, vm_name)

    paths: dict[str, str | bool | None] = {
        "is_wsl": _is_wsl_local(),
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

def get_half_cpus() -> int:
    total = os.cpu_count() or 2
    return max(1, total // 2)

def remove_lab_vms(*, dry_run: bool = False) -> None:
    """Stop and delete all known Overdrive lab QEMU VMs before a fresh rebuild."""
    from detections.common.common_qemu import remove_lab_vms_qemu

    remove_lab_vms_qemu(dry_run=dry_run)



def wait_after_disk_operation(*_args, seconds: float = 2.0, **_kwargs) -> None:
    """Brief pause after disk image mutations."""
    time.sleep(seconds)



def serial_tcp_host_candidates(base_host: str | None = None) -> list[str]:
    """Hosts to try when reaching a TCP serial endpoint from WSL."""
    host = base_host or SERIAL_TCP_HOST
    candidates: list[str] = []
    if _is_wsl_local():
        win_host = _wsl_windows_host_ip()
        if win_host:
            candidates.append(win_host)
    if host not in candidates:
        candidates.append(host)
    if _is_wsl_local() and "127.0.0.1" not in candidates:
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

    # --- Terminate any existing serial console windows / python sessions first ---
    print(f"[*] Closing any existing serial console windows for {safe_title}...")
    if os.name == "nt" or _windows_cmd_available():
        # Close WT/CMD windows matching the title
        taskkill_cmd = "taskkill.exe" if os.name != "nt" else "taskkill"
        subprocess.run([taskkill_cmd, "/F", "/FI", f"WINDOWTITLE eq {safe_title}"], capture_output=True, check=False)
        # Also kill background python processes running the target script
        script_pattern = script.name
        ps_cmd = (
            f"Get-Process -Name python* -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.CommandLine -like '*{script_pattern}*' -and $_.Id -ne {os.getpid()} }} | "
            f"Stop-Process -Force"
        )
        if os.name == "nt":
            subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, check=False)
        elif _is_wsl_local():
            subprocess.run(["powershell.exe", "-Command", ps_cmd], capture_output=True, check=False)

    if platform.system().lower() == "linux" or _is_wsl_local():
        # Terminate Linux/WSL python instances of this script
        my_pid = os.getpid()
        script_pattern = script.name
        try:
            out = subprocess.check_output(["pgrep", "-f", script_pattern]).decode().strip()
            for pid_str in out.split():
                if pid_str.isdigit():
                    pid = int(pid_str)
                    if pid != my_pid:
                        subprocess.run(["kill", "-9", str(pid)], capture_output=True, check=False)
        except Exception:
            pass
    time.sleep(1.0)

    # --- Path A: WSL host → new wt window running Linux Python ---
    if _is_wsl_local():
        py = sys.executable or "python3"
        cmd = [py, str(script), *args]
        if spawn_wsl_interactive_terminal(cmd, cwd=work, title=safe_title):
            print(f"[serial] Opened new window: {safe_title}")
            time.sleep(0.5)
            return True

    # --- Path B: Windows Python via wt / new console ---
    if os.name == "nt" or _windows_cmd_available():
        win_script = _windows_path_from_wsl(script) if _is_wsl_local() else str(script)
        win_cwd = _windows_path_from_wsl(work) if _is_wsl_local() else str(work)
        if not win_script:
            win_script = str(script)
        if not win_cwd:
            win_cwd = str(work)

        if _is_wsl_local() or os.name != "nt":
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
    """Connect to a TCP serial endpoint without sending bytes."""
    last_error: OSError | None = None
    for candidate in serial_tcp_host_candidates(host):
        try:
            with socket.create_connection((candidate, port), timeout=timeout_s):
                return True, f"CONNECTED ({candidate}:{port})"
        except OSError as exc:
            last_error = exc
    return False, str(last_error) if last_error else "no host candidates"

