#!/usr/bin/env python3
"""
Bootstrap a project-local Python virtual environment for Overdrive automation.

Creates ``virtual_env`` next to this script, installs Python dependencies (HTTP clients,
Scapy, Selenium, etc.), optionally installs Linux packages (libpcap, 7-Zip, Chrome),
and on Linux applies file capabilities to the **venv** interpreter so Scapy can use
raw sockets without ``sudo`` every run. Ends by launching an interactive bash with the
venv activated (Unix-like systems).
"""

import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import venv
from pathlib import Path

# Always resolve the venv relative to this script so ``python /path/to/virtual_env_setup.py``
# from another cwd still creates ``.../overdrive/virtual_env``.
REPO_ROOT = Path(__file__).resolve().parent
venv_dir = str(REPO_ROOT / "virtual_env")


def get_linux_info():
    """Detects the package manager and relevant package names."""
    if shutil.which("dnf"):
        return {
            "mgr": "dnf",
            "pcap": "libpcap-devel",
            "7zip": "p7zip p7zip-plugins",
            "chrome_cmd": "google-chrome",
            "socat": "socat",
            "minicom": "minicom",
        }
    elif shutil.which("apt"):
        return {
            "mgr": "apt",
            "pcap": "libpcap-dev",
            "7zip": "p7zip-full",
            "chrome_cmd": "google-chrome-stable",
            "socat": "socat",
            "minicom": "minicom",
        }
    return None


def _distro_success_label() -> str:
    """Human-readable OS label for the final message; avoids guessing 'Ubuntu' on unknown distros."""
    info = get_linux_info()
    if not info:
        return "this system (unknown package manager—install system deps manually if needed)"
    if info["mgr"] == "dnf":
        return "Fedora / RHEL-family (dnf)"
    if info["mgr"] == "apt":
        return "Debian / Ubuntu (apt)"
    return "this system"


def apply_network_capabilities(interpreter_path: str) -> None:
    """
    Grant raw-socket capabilities to the **virtualenv** Python binary (not sys.executable).

    When this setup script is run with system Python, sys.executable points at /usr/bin/python3;
    Scapy in the venv must run under virtual_env/bin/python, so setcap must target that file.

    Security note: cap_net_raw/cap_net_admin are stored on the interpreter inode. Anyone who can
    execute that Python binary inherits those capabilities—fine for a personal dev venv; review
    before using on shared or production hosts.
    """
    if sys.platform == "win32":
        print("[*] Skipping setcap (not applicable on Windows).")
        return

    python_path = os.path.realpath(interpreter_path)
    if not os.path.isfile(python_path):
        print(f"[-] Venv interpreter not found: {python_path}")
        return

    print(f"[*] Applying network capabilities to venv Python: {python_path}")

    try:
        # cap_net_raw: Scapy packet forging; cap_net_admin: promiscuous / iface control; +eip on the file
        cmd = ["sudo", "setcap", "cap_net_raw,cap_net_admin+eip", python_path]
        subprocess.check_call(cmd)
        print("[+] Success! Run Scapy scripts with the venv Python above (or after activate).")
    except subprocess.CalledProcessError:
        print("[-] Failed to apply setcap. Ensure you have sudo privileges.")
    except FileNotFoundError:
        print("[-] 'setcap' utility not found. Install it with: sudo apt install libcap2-bin")


def install_system_deps():
    info = get_linux_info()
    if not info:
        print("⚠️ Unknown OS: install dependencies manually.")
        return

    mgr = info["mgr"]
    print(f"Detected {mgr} package manager. Preparing installation...")

    try:
        # 1. Install libpcap
        print(f"Installing {info['pcap']}...")
        subprocess.run(["sudo", mgr, "install", "-y", info["pcap"]], check=True)


        # 2. Install 7-Zip
        if not shutil.which("7z"):
            print(f"Installing {info['7zip']}...")
            # split() handles the multiple packages for Fedora 7zip
            subprocess.run(["sudo", mgr, "install", "-y"] + info["7zip"].split(), check=True)
        else:
            print("7-Zip is already installed.")

        # 3. Install Chrome
        if not shutil.which(info["chrome_cmd"]):
            print("Installing Google Chrome...")
            if mgr == "dnf":
                try:
                    # Direct installation via the Google RPM URL - bypasses the need for config-manager
                    print("Attempting direct RPM installation...")
                    chrome_url = "https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm"
                    subprocess.run(["sudo", "dnf", "install", "-y", chrome_url], check=True)
                except subprocess.CalledProcessError:
                    print("Direct install failed. Trying repo method...")
                    # Fallback: Just try installing it normally; if workstation-repos is there, it might just work
                    subprocess.run(["sudo", "dnf", "install", "-y", "google-chrome-stable"], check=True)
            elif mgr == "apt":
                deb_url = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
                deb_fd, deb_path = tempfile.mkstemp(suffix=".deb")
                os.close(deb_fd)
                try:
                    print("Downloading Google Chrome .deb...")
                    urllib.request.urlretrieve(deb_url, deb_path)
                    subprocess.run(["sudo", "apt", "install", "-y", deb_path], check=True)
                finally:
                    try:
                        os.unlink(deb_path)
                    except OSError:
                        pass

        # 4. Install nmap
        if not shutil.which("nmap"):
            print("Installing nmap...")
            subprocess.run(["sudo", mgr, "install", "-y", "nmap"], check=True)
        else:
            print("nmap is already installed.")


        # 5. Install minicom
        if not shutil.which("minicom"):
            print("Installing minicom...")
            subprocess.run(["sudo", mgr, "install", "-y", "minicom"], check=True)
        else:
            print("minicom is already installed.")

        # 6. Install socat
        if not shutil.which("socat"):
            print("Installing socat...")
            subprocess.run(["sudo", mgr, "install", "-y", "socat"], check=True)
        else:
            print("socat is already installed.")
            
    except:
        print("Dependancies failed to install.")


# --- Main Logic ---

# 1. Create venv
if not os.path.exists(venv_dir):
    print(f"Creating venv in {venv_dir}...")
    venv.create(venv_dir, with_pip=True)

# 2. Path to Python
python_exe = (
    os.path.join(venv_dir, "bin", "python")
    if sys.platform != "win32"
    else os.path.join(venv_dir, "Scripts", "python.exe")
)

# 3. Install Python libs
print("Installing Python packages...")
subprocess.check_call(
    [python_exe, "-m", "pip", "install", "requests", "selenium", "httpx[http2]", "scapy", "zeroconf"]
)

# 4. Handle System Deps
install_system_deps()

print("\nSuccess! Your Virtual environment is ready on " + _distro_success_label() + ".")

# 5. Linux: when bootstrapping with system Python, grant capabilities to the venv interpreter
if sys.platform != "win32" and os.path.isfile(python_exe) and sys.prefix == sys.base_prefix:
    print(
        "[*] Bootstrapping with system Python; applying capabilities to the venv interpreter "
        f"({python_exe}), not sys.executable."
    )
    apply_network_capabilities(python_exe)

# 6. Go to shell (string form: recommended when shell=True)
print("Entering virtual environment... (Type 'exit' to leave)")
subprocess.call(
    f"bash --rcfile <(echo 'source {venv_dir}/bin/activate')",
    executable="/bin/bash",
    shell=True,
)
