#!/usr/bin/env python3
"""
Bootstrap a project-local Python virtual environment for Overdrive automation.

- Creates ./virtual_env next to this script
- Installs Python deps into the venv
- Installs OS deps via apt (Ubuntu/Debian) or dnf (Fedora/RHEL)
- Applies file capabilities to the venv interpreter (so Scapy can use raw sockets without sudo)
- Drops into an interactive bash with venv activated
"""

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

def run_cmd(cmd: list[str], *, use_sudo: bool = True):
    # If running as root, never require sudo.
    if use_sudo and os.geteuid() != 0:
        cmd = ["sudo", *cmd]
    subprocess.run(cmd, check=True)



def install_packages(info, packages: list[str]) -> None:
    mgr = info["mgr"]
    if mgr == "apt":
        env = os.environ.copy()
        env["DEBIAN_FRONTEND"] = "noninteractive"

        cmd = ["apt", "install", "-y", *packages]
        if os.geteuid() != 0:
            cmd = ["sudo", *cmd]

        subprocess.run(cmd, check=True, env=env)
    else:
        run_cmd([mgr, "install", "-y", *packages])



def install_first_available(info, package_sets: list[list[str]]):
    last_exc = None
    for packages in package_sets:
        try:
            install_packages(info, packages)
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

def install_system_deps():
    info = get_linux_info()
    if not info:
        print("⚠️ Unknown OS: install system dependencies manually if needed.")
        return

    mgr = info["mgr"]
    print(f"Detected {mgr} package manager. Installing system deps...")

    if mgr == "apt":
        print("[*] apt update")
        run_cmd(["apt", "update"], use_sudo=True)

    # 1) libpcap
    if not have_cmd("tcpdump"):  # heuristic; libpcap provides build headers too
        print(f"[*] Installing {info['pcap']}...")
        install_packages(info, [info["pcap"]])

    # 2) 7zip
    if not have_cmd("7z"):
        print("[*] Installing 7-Zip (first available option)...")
        install_first_available(info, info["7zip_sets"])
    else:
        print("[*] 7-Zip already installed.")

    # 3) Chrome
    if not have_cmd(info["chrome_cmd"]):
        print("[*] Installing Google Chrome...")
        if mgr == "dnf":
            # Direct rpm install works for most Fedora/RHEL setups
            chrome_url = "https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm"
            run_cmd(["dnf", "install", "-y", chrome_url], use_sudo=True)
        else:
            deb_url = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
            fd, deb_path = tempfile.mkstemp(suffix=".deb")
            os.close(fd)
            try:
                print("[*] Downloading Chrome .deb...")
                urllib.request.urlretrieve(deb_url, deb_path)
                run_cmd(["apt", "install", "-y", deb_path], use_sudo=True)
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
            install_packages(info, [cmd])
        else:
            print(f"[*] {cmd} already installed.")

    # 5) guestfs tools (for virt-customize)
    if not have_cmd("virt-customize"):
        print("[*] Installing guestfs tools for virt-customize (first available option)...")
        install_first_available(info, info["guestfs_sets"])
    else:
        print("[*] virt-customize already available.")

    # 6) capability tool provider (setcap)
    if not have_cmd("setcap"):
        print("[*] Installing libcap tooling (first available option)...")
        install_first_available(info, info["cap_provider_sets"])
    else:
        print("[*] setcap already available.")

def apply_network_capabilities(interpreter_path: Path):
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
            use_sudo=True
        )
        print("[+] Success! Run Scapy with this venv Python (or after activate).")
    except subprocess.CalledProcessError:
        print("[-] Failed to apply setcap. Ensure you have sudo privileges.")
    except FileNotFoundError:
        print("[-] setcap utility not found. Install it with your distro's libcap package.")




def ensure_venv_support():
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

    pyver = f"{sys.version_info.major}.{sys.version_info.minor}"
    mgr = info["mgr"]

    # Install alternatives (Ubuntu/Debian are usually version-specific; Fedora varies)
    if mgr == "apt":
        candidates = [f"python{pyver}-venv", "python3-venv"]
    else:  # dnf
        candidates = [f"python{pyver}-venv", "python3-venv"]

    print("[*] Host python missing ensurepip/venv support. Installing required package...")
    install_first_available(info, [[c] for c in candidates])



def main():
    # 0) Ensure host python can create venvs with pip
    ensure_venv_support()

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
    subprocess.check_call([python_exe, "-m", "pip", "install", *PY_DEPS])

    # 3) Install system deps (apt/dnf)
    install_system_deps()

    print(f"\nSuccess! Virtual environment is ready on {distro_success_label()}.")

    # 4) Apply capabilities only when bootstrapping from system Python.
    if sys.platform != "win32" and sys.prefix == sys.base_prefix:
        print("[*] Running from system Python; applying capabilities to venv interpreter.")
        apply_network_capabilities(Path(python_exe))

    # 5) Enter shell with venv activated
    print("Entering virtual environment... (Type 'exit' to leave)")
    activate = str(VENV_DIR / "bin" / "activate")
    subprocess.call(
        ["/bin/bash", "-i", "-c", f"source '{activate}'; exec /bin/bash -i"]
    )

    

if __name__ == "__main__":
    main()