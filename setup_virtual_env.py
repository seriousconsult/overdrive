#!/usr/bin/env python3
"""
Bootstrap a project-local Python virtual environment for Overdrive automation.

- Creates ./virtual_env next to this script
- Installs Python deps into the venv
- Installs OS deps via apt (Ubuntu/Debian) or dnf (Fedora/RHEL), unless skipped
- Applies file capabilities to the venv interpreter (so Scapy can use raw sockets without sudo)
- Drops into an interactive bash with venv activated, unless skipped
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import venv
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
VENV_DIR = REPO_ROOT / "virtual_env"
VENV_PYTHON = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
    "python.exe" if sys.platform == "win32" else "python"
)

PY_DEPS = [
    "requests",
    "selenium",
    "httpx[http2]",
    "scapy",
    "zeroconf",
]

APT_LOCK_TIMEOUT_SECONDS = 180
APT_LOCK_WAIT_SECONDS = 60
APT_LOCK_POLL_SECONDS = 2
APT_LOCK_REPORT_SECONDS = 15
APT_LOCK_MAX_ATTEMPTS = 5
APT_UPDATE_MAX_AGE_SECONDS = 24 * 60 * 60
APT_LOCK_PATHS = (
    "/var/lib/apt/lists/lock",
    "/var/cache/apt/archives/lock",
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
)
APT_LOCK_PROCESS_NAMES = {
    "apt",
    "apt-get",
    "apt.systemd.daily",
    "dpkg",
    "unattended-upgr",
    "unattended-upgrades",
    "packagekitd",
}


class AptLockError(subprocess.CalledProcessError):
    """Raised when apt/dpkg is still locked after polite waiting."""


APT_UPDATED = False

def get_linux_info():
    if shutil.which("dnf"):
        return {
            "mgr": "dnf",
            "pcap": "libpcap-devel",
            "7zip_sets": [["p7zip", "p7zip-plugins"], ["7zip"]],
            # guestfs tools package name can vary; we try a couple
            "guestfs_sets": [["guestfs-tools"], ["libguestfs-tools"]],
            "cap_provider_sets": [["libcap"], ["libcap-tools"]],
            "chrome_cmd": "google-chrome",
            "socat": "socat",
            "minicom": "minicom",
            "nmap": "nmap",
            "curl": "curl",
        }
    if shutil.which("apt"):
        return {
            "mgr": "apt",
            "pcap": "libpcap-dev",
            "7zip_sets": [["p7zip-full"], ["p7zip"], ["7zip"]],
            "guestfs_sets": [["libguestfs-tools"], ["guestfs-tools"]],
            "cap_provider_sets": [["libcap2-bin"], ["libcap-bin"]],
            "chrome_cmd": "google-chrome",
            "socat": "socat",
            "minicom": "minicom",
            "nmap": "nmap",
            "curl": "curl",
        }
    return None

def have_cmd(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0

def add_sudo(cmd: list[str], *, non_interactive: bool) -> list[str]:
    if is_root():
        return cmd
    if not have_cmd("sudo"):
        raise RuntimeError("sudo is required for this step, but it is not installed.")

    sudo_cmd = ["sudo"]
    if non_interactive:
        sudo_cmd.append("-n")
    return [*sudo_cmd, *cmd]

def run_cmd(
    cmd: list[str],
    *,
    use_sudo: bool = True,
    non_interactive: bool = False,
    env: dict[str, str] | None = None,
):
    # If running as root, never require sudo.
    if use_sudo:
        cmd = add_sudo(cmd, non_interactive=non_interactive)
    subprocess.run(cmd, check=True, env=env)


def apt_base_command(args: list[str]) -> list[str]:
    apt_bin = "apt-get" if have_cmd("apt-get") else "apt"
    return [
        apt_bin,
        "-o",
        f"DPkg::Lock::Timeout={APT_LOCK_TIMEOUT_SECONDS}",
        "-o",
        f"APT::Get::Lock::Timeout={APT_LOCK_TIMEOUT_SECONDS}",
        *args,
    ]


def package_name_needs_apt_index(package: str) -> bool:
    return not package.startswith("/") and not package.endswith(".deb")


def apt_lists_are_fresh() -> bool:
    lists_dir = Path("/var/lib/apt/lists")
    try:
        newest = max(
            path.stat().st_mtime
            for path in lists_dir.iterdir()
            if path.is_file() and path.name != "lock"
        )
    except (OSError, ValueError):
        return False
    return time.time() - newest <= APT_UPDATE_MAX_AGE_SECONDS


def ensure_apt_updated_for(packages: list[str], *, non_interactive: bool) -> None:
    global APT_UPDATED

    if APT_UPDATED:
        return
    if not any(package_name_needs_apt_index(package) for package in packages):
        return
    if apt_lists_are_fresh():
        print("[*] apt package lists are fresh; skipping apt-get update.")
        return

    print(f"[*] apt-get update (waits up to {APT_LOCK_WAIT_SECONDS}s for apt locks)")
    run_apt(["update"], non_interactive=non_interactive)
    APT_UPDATED = True


def active_package_processes() -> list[str]:
    found: list[str] = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return found

    for proc_dir in proc_root.iterdir():
        if not proc_dir.name.isdigit():
            continue
        try:
            comm = (proc_dir / "comm").read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            continue
        if comm not in APT_LOCK_PROCESS_NAMES:
            continue
        try:
            cmdline_raw = (proc_dir / "cmdline").read_bytes()
            cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
        except OSError:
            cmdline = comm
        found.append(f"pid={proc_dir.name} {cmdline or comm}")
    return found


def proc_cmdline(pid: int) -> str:
    proc_dir = Path("/proc") / str(pid)
    try:
        cmdline_raw = (proc_dir / "cmdline").read_bytes()
        cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
        if cmdline:
            return cmdline
    except OSError:
        pass
    try:
        return (proc_dir / "comm").read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return "(process exited)"


def passive_package_watchers() -> list[str]:
    watchers: list[str] = []
    for line in active_package_processes():
        if "unattended-upgrade-shutdown" in line:
            watchers.append(line)
    return watchers


def apt_lock_holder_pids(*, non_interactive: bool) -> set[int]:
    existing_locks = [path for path in APT_LOCK_PATHS if Path(path).exists()]
    if not existing_locks or not have_cmd("fuser"):
        return set()

    commands = [["fuser", *existing_locks]]
    if not is_root() and have_cmd("sudo"):
        try:
            commands.append(add_sudo(["fuser", *existing_locks], non_interactive=non_interactive))
        except RuntimeError:
            pass

    for cmd in commands:
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        except OSError:
            continue
        if proc.returncode != 0:
            continue
        pids = {int(match) for match in re.findall(r"\b\d+\b", proc.stdout)}
        if pids:
            return pids
    return set()


def apt_lock_holder_details(*, non_interactive: bool) -> str:
    details: list[str] = []
    holder_pids = sorted(apt_lock_holder_pids(non_interactive=non_interactive))
    if holder_pids:
        details.append(
            "apt/dpkg lock holders:\n"
            + "\n".join(f"  pid={pid} {proc_cmdline(pid)}" for pid in holder_pids)
        )

    watchers = passive_package_watchers()
    if watchers:
        details.append(
            "Package watcher processes not treated as lock holders:\n"
            + "\n".join(f"  {line}" for line in watchers)
        )

    return "\n".join(details)


def apt_likely_locked(*, non_interactive: bool) -> bool:
    if apt_lock_holder_pids(non_interactive=non_interactive):
        return True

    if have_cmd("fuser"):
        return False

    package_processes = [
        line
        for line in active_package_processes()
        if "unattended-upgrade-shutdown" not in line
    ]
    return bool(package_processes)


def wait_for_apt_locks(*, non_interactive: bool) -> None:
    deadline = time.monotonic() + APT_LOCK_WAIT_SECONDS
    last_report = 0.0
    last_pids: set[int] | None = None

    while True:
        holder_pids = apt_lock_holder_pids(non_interactive=non_interactive)
        if not holder_pids:
            return

        now = time.monotonic()
        remaining = max(0, int(deadline - now))
        if remaining <= 0:
            print("[-] apt/dpkg is still locked; not removing lock files.")
            details = apt_lock_holder_details(non_interactive=non_interactive)
            if details:
                print(details)
            raise AptLockError(100, ["apt-lock-wait"])

        if holder_pids != last_pids or now - last_report >= APT_LOCK_REPORT_SECONDS:
            print(
                "[*] apt/dpkg lock is busy; waiting without touching lock files "
                f"(up to {remaining}s left)."
            )
            details = apt_lock_holder_details(non_interactive=non_interactive)
            if details:
                print(details)
            last_report = now
            last_pids = set(holder_pids)

        time.sleep(min(APT_LOCK_POLL_SECONDS, remaining))


def run_apt(
    args: list[str],
    *,
    non_interactive: bool = False,
) -> None:
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["APT_LISTCHANGES_FRONTEND"] = "none"

    cmd = apt_base_command(args)
    if not is_root():
        cmd = add_sudo(
            ["env", "DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", *cmd],
            non_interactive=non_interactive,
        )

    for attempt in range(1, APT_LOCK_MAX_ATTEMPTS + 1):
        if attempt > 1:
            print(f"[*] Retrying apt command (attempt {attempt}/{APT_LOCK_MAX_ATTEMPTS})...")

        wait_for_apt_locks(non_interactive=non_interactive)
        proc = subprocess.run(cmd, env=env if is_root() else None)
        if proc.returncode == 0:
            return

        locked = apt_likely_locked(non_interactive=non_interactive)
        if proc.returncode != 100 or not locked or attempt == APT_LOCK_MAX_ATTEMPTS:
            if locked:
                print("[-] apt/dpkg still appears to be busy; not removing lock files.")
                details = apt_lock_holder_details(non_interactive=non_interactive)
                if details:
                    print(details)
                raise AptLockError(proc.returncode, cmd)
            raise subprocess.CalledProcessError(proc.returncode, cmd)

        wait_for_apt_locks(non_interactive=non_interactive)



def install_packages(info, packages: list[str], *, non_interactive: bool = False) -> None:
    mgr = info["mgr"]
    if mgr == "apt":
        ensure_apt_updated_for(packages, non_interactive=non_interactive)
        run_apt(["install", "-y", *packages], non_interactive=non_interactive)
    else:
        run_cmd([mgr, "install", "-y", *packages], non_interactive=non_interactive)



def install_first_available(
    info,
    package_sets: list[list[str]],
    *,
    non_interactive: bool = False,
):
    last_exc = None
    for packages in package_sets:
        try:
            install_packages(info, packages, non_interactive=non_interactive)
            return
        except AptLockError:
            raise
        except subprocess.CalledProcessError as exc:
            last_exc = exc
            print(f"[-] Failed installing: {' '.join(packages)}; trying next...")
    if last_exc:
        raise last_exc


def package_installed(info, package: str) -> bool:
    if package.startswith("/") or package.endswith(".deb"):
        return False

    mgr = info["mgr"]
    if mgr == "apt" and have_cmd("dpkg-query"):
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", package],
            text=True,
            capture_output=True,
            check=False,
        )
        return proc.returncode == 0 and "install ok installed" in proc.stdout
    if mgr == "dnf" and have_cmd("rpm"):
        proc = subprocess.run(["rpm", "-q", package], capture_output=True, check=False)
        return proc.returncode == 0
    return False

def distro_success_label():
    info = get_linux_info()
    if not info:
        return "this system (unknown package manager—install deps manually if needed)"
    return "Fedora / RHEL-family (dnf)" if info["mgr"] == "dnf" else "Debian / Ubuntu (apt)"

def install_system_deps(*, non_interactive: bool = False):
    info = get_linux_info()
    if not info:
        print("⚠️ Unknown OS: install system dependencies manually if needed.")
        return

    mgr = info["mgr"]
    print(f"Detected {mgr} package manager. Installing system deps...")

    # 1) libpcap
    if not package_installed(info, info["pcap"]):
        print(f"[*] Installing {info['pcap']}...")
        install_packages(info, [info["pcap"]], non_interactive=non_interactive)
    else:
        print(f"[*] {info['pcap']} already installed.")

    # 2) 7zip
    if not have_cmd("7z"):
        print("[*] Installing 7-Zip (first available option)...")
        install_first_available(
            info,
            info["7zip_sets"],
            non_interactive=non_interactive,
        )
    else:
        print("[*] 7-Zip already installed.")

    # 3) Chrome
    if not have_cmd(info["chrome_cmd"]):
        print("[*] Installing Google Chrome...")
        if mgr == "dnf":
            # Direct rpm install works for most Fedora/RHEL setups
            chrome_url = "https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm"
            run_cmd(
                ["dnf", "install", "-y", chrome_url],
                use_sudo=True,
                non_interactive=non_interactive,
            )
        else:
            deb_url = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
            fd, deb_path = tempfile.mkstemp(suffix=".deb")
            os.close(fd)
            try:
                print("[*] Downloading Chrome .deb...")
                urllib.request.urlretrieve(deb_url, deb_path)
                install_packages(info, [deb_path], non_interactive=non_interactive)
            finally:
                try:
                    os.unlink(deb_path)
                except OSError:
                    pass
    else:
        print("[*] Chrome already installed.")

    # 4) nmap / minicom / socat / curl
    for key in ["nmap", "minicom", "socat", "curl"]:
        cmd = info[key]
        if not have_cmd(cmd):
            print(f"[*] Installing {cmd}...")
            install_packages(info, [cmd], non_interactive=non_interactive)
        else:
            print(f"[*] {cmd} already installed.")

    # 5) guestfs tools (for virt-customize)
    if not have_cmd("virt-customize"):
        print("[*] Installing guestfs tools for virt-customize (first available option)...")
        install_first_available(
            info,
            info["guestfs_sets"],
            non_interactive=non_interactive,
        )
    else:
        print("[*] virt-customize already available.")

    # 6) capability tool provider (setcap)
    if not have_cmd("setcap"):
        print("[*] Installing libcap tooling (first available option)...")
        install_first_available(
            info,
            info["cap_provider_sets"],
            non_interactive=non_interactive,
        )
    else:
        print("[*] setcap already available.")

def apply_network_capabilities(interpreter_path: Path, *, non_interactive: bool = False):
    if sys.platform == "win32":
        print("[*] Skipping setcap (not applicable on Windows).")
        return

    if not interpreter_path.exists():
        print(f"[-] Venv interpreter not found: {interpreter_path}")
        return

    if not have_cmd("setcap"):
        print("[-] 'setcap' not found. Install libcap tooling for your distro first.")
        return

    # Optional idempotency: if getcap exists and shows our desired caps, skip.
    if have_cmd("getcap"):
        try:
            out = subprocess.check_output(["getcap", str(interpreter_path)], stderr=subprocess.STDOUT).decode("utf-8", "ignore").strip()
            if "cap_net_raw" in out and "cap_net_admin" in out:
                print("[*] Network capabilities already set on venv interpreter; skipping setcap.")
                return
        except subprocess.CalledProcessError:
            pass

    print(f"[*] Applying network capabilities to venv Python: {interpreter_path}")
    try:
        run_cmd(
            ["setcap", "cap_net_raw,cap_net_admin+eip", str(interpreter_path)],
            use_sudo=True,
            non_interactive=non_interactive,
        )
        print("[+] Success! Run Scapy with this venv Python (or after activate).")
    except subprocess.CalledProcessError:
        print("[-] Failed to apply setcap. Ensure you have sudo privileges.")
        if non_interactive:
            raise
    except FileNotFoundError:
        print("[-] setcap utility not found. Install it with your distro's libcap package.")




def ensure_venv_support(*, non_interactive: bool = False, allow_install: bool = True):
    """
    Ensures the host python has ensurepip/venv support so `venv.create(..., with_pip=True)`
    can bootstrap pip. On Ubuntu/Debian this is typically python3-venv / pythonX.Y-venv.
    """
    if sys.platform == "win32":
        return

    # If ensurepip exists, we're good
    try:
        import ensurepip  # noqa: F401
        return
    except Exception:
        pass

    info = get_linux_info()
    if not info:
        raise RuntimeError(
            "Host python lacks ensurepip; please install venv support manually "
            "(e.g., apt install python3-venv on Ubuntu/Debian)."
        )
    if not allow_install:
        raise RuntimeError(
            "Host python lacks ensurepip/venv support, and --skip-system-deps "
            "prevents installing it automatically. Install python3-venv manually "
            "or rerun without --skip-system-deps."
        )

    pyver = f"{sys.version_info.major}.{sys.version_info.minor}"
    mgr = info["mgr"]

    # Install alternatives (Ubuntu/Debian are usually version-specific; Fedora varies)
    if mgr == "apt":
        candidates = [f"python{pyver}-venv", "python3-venv"]
    else:  # dnf
        candidates = [f"python{pyver}-venv", "python3-venv"]

    print("[*] Host python missing ensurepip/venv support. Installing required package...")
    install_first_available(info, [[c] for c in candidates], non_interactive=non_interactive)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create the Overdrive virtual environment and optional system setup."
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help=(
            "Never prompt for input. Privileged commands use sudo -n and fail if "
            "passwordless sudo is unavailable. Also skips opening an activated shell."
        ),
    )
    parser.add_argument(
        "--skip-system-deps",
        action="store_true",
        help="Do not run apt/dnf or install OS packages.",
    )
    parser.add_argument(
        "--skip-capabilities",
        action="store_true",
        help="Do not run setcap on the venv Python interpreter.",
    )
    parser.add_argument(
        "--no-shell",
        action="store_true",
        help="Create the venv and exit instead of opening an activated shell.",
    )
    parser.add_argument(
        "--apt-lock-wait",
        type=int,
        default=APT_LOCK_WAIT_SECONDS,
        metavar="SECONDS",
        help=(
            "Maximum time to wait for apt/dpkg lock holders before failing "
            f"(default: {APT_LOCK_WAIT_SECONDS})."
        ),
    )
    return parser.parse_args()



def main():
    args = parse_args()
    global APT_LOCK_WAIT_SECONDS
    APT_LOCK_WAIT_SECONDS = max(0, args.apt_lock_wait)

    # 0) Ensure host python can create venvs with pip
    ensure_venv_support(
        non_interactive=args.non_interactive,
        allow_install=not args.skip_system_deps,
    )

    # 1) Always delete and recreate venv (fresh start)
    if VENV_DIR.exists():
        print(f"[!] Removing existing venv: {VENV_DIR}")
        shutil.rmtree(VENV_DIR)

    print(f"[*] Creating venv in {VENV_DIR}...")
    venv.create(str(VENV_DIR), with_pip=True)

    python_exe = str(VENV_PYTHON)
    if not Path(python_exe).exists():
        print(f"[-] Expected venv python not found at: {python_exe}")
        sys.exit(1)

    # 2) Install Python libs
    print("Installing Python packages into venv...")
    subprocess.check_call([python_exe, "-m", "pip", "install", "--no-input", *PY_DEPS])

    # 3) Install system deps (apt/dnf)
    if args.skip_system_deps:
        print("[*] Skipping system dependency installation (--skip-system-deps).")
    else:
        install_system_deps(non_interactive=args.non_interactive)

    print(f"\nSuccess! Virtual environment is ready on {distro_success_label()}.")

    # 4) Apply capabilities only when bootstrapping from system Python.
    if args.skip_capabilities:
        print("[*] Skipping network capabilities (--skip-capabilities).")
    elif sys.platform != "win32" and sys.prefix == sys.base_prefix:
        print("[*] Running from system Python; applying capabilities to venv interpreter.")
        apply_network_capabilities(
            Path(python_exe),
            non_interactive=args.non_interactive,
        )

    # 5) Enter shell with venv activated
    if args.no_shell or args.non_interactive:
        print(f"Activate it later with: source {VENV_DIR / 'bin' / 'activate'}")
        return 0

    print("Entering virtual environment... (Type 'exit' to leave)")
    activate = str(VENV_DIR / "bin" / "activate")
    subprocess.call(
        ["/bin/bash", "-i", "-c", f"source '{activate}'; exec /bin/bash -i"]
    )
    return 0


def command_text(cmd) -> str:
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(part) for part in cmd)
    return str(cmd)

def used_noninteractive_sudo(cmd) -> bool:
    return isinstance(cmd, (list, tuple)) and "sudo" in cmd and "-n" in cmd

if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(
            f"[-] Command failed with exit code {exc.returncode}: {command_text(exc.cmd)}",
            file=sys.stderr,
        )
        if used_noninteractive_sudo(exc.cmd):
            print(
                "[-] Non-interactive sudo was denied. Configure passwordless sudo, "
                "run the script interactively, or use --skip-system-deps "
                "--skip-capabilities.",
                file=sys.stderr,
            )
        sys.exit(exc.returncode)
