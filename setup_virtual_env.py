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
import shutil
import subprocess
import sys
import tempfile
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



def install_packages(info, packages: list[str], *, non_interactive: bool = False) -> None:
    mgr = info["mgr"]
    if mgr == "apt":
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"
        cmd = ["apt", "install", "-y", *packages]
        if is_root():
            subprocess.run(cmd, check=True, env=env)
        else:
            subprocess.run(
                add_sudo(
                    ["env", "DEBIAN_FRONTEND=noninteractive", *cmd],
                    non_interactive=non_interactive,
                ),
                check=True,
            )
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
        except subprocess.CalledProcessError as exc:
            last_exc = exc
            print(f"[-] Failed installing: {' '.join(packages)}; trying next...")
    if last_exc:
        raise last_exc

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

    if mgr == "apt":
        print("[*] apt update")
        run_cmd(["apt", "update"], use_sudo=True, non_interactive=non_interactive)

    # 1) libpcap
    if not have_cmd("tcpdump"):  # heuristic; libpcap provides build headers too
        print(f"[*] Installing {info['pcap']}...")
        install_packages(info, [info["pcap"]], non_interactive=non_interactive)

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
    return parser.parse_args()



def main():
    args = parse_args()

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
