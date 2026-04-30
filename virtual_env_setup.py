#!/usr/bin/env python3


import os
import venv
import subprocess
import sys
import shutil

venv_dir = "virtual_env"

def get_linux_info():
    """Detects the package manager and relevant package names."""
    if shutil.which("dnf"):
        return {
            "mgr": "dnf",
            "pcap": "libpcap-devel",
            "7zip": "p7zip p7zip-plugins",
            "chrome_cmd": "google-chrome"
        }
    elif shutil.which("apt"):
        return {
            "mgr": "apt",
            "pcap": "libpcap-dev",
            "7zip": "p7zip-full",
            "chrome_cmd": "google-chrome-stable"
        }
    return None

def install_system_deps():
    info = get_linux_info()
    if not info:
        print("⚠️ Unknown OS: Please install dependencies manually.")
        return

    mgr = info["mgr"]
    print(f"Detected {mgr} package manager. Preparing installation...")

    try:
        # 1. Install libpcap
        print(f"Installing {info['pcap']}...")
        subprocess.run(["sudo", mgr, "install", "-y", info['pcap']], check=True)

        # 2. Install 7-Zip
        if not shutil.which("7z"):
            print(f"Installing {info['7zip']}...")
            # split() handles the multiple packages for Fedora 7zip
            subprocess.run(["sudo", mgr, "install", "-y"] + info['7zip'].split(), check=True)
        else:
            print("7-Zip is already installed.")

        # 3. Install Chrome
        if not shutil.which(info['chrome_cmd']):
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
    except subprocess.CalledProcessError as e:
        print(f"❌ Error during system install: {e}")

# --- Main Logic ---

# 1. Create venv
if not os.path.exists(venv_dir):
    print(f"Creating venv in {venv_dir}...")
    venv.create(venv_dir, with_pip=True)

# 2. Path to Python
python_exe = os.path.join(venv_dir, "bin", "python") if sys.platform != "win32" else os.path.join(venv_dir, "Scripts", "python.exe")

# 3. Install Python libs
print("Installing Python packages...")
subprocess.check_call([python_exe, "-m", "pip", "install", "requests", "selenium", "httpx[http2]", "scapy"])

# 4. Handle System Deps
install_system_deps()

print("\nSuccess! Your Virtual environment is ready on " + ("Fedora" if shutil.which("dnf") else "Ubuntu") + ".")

# 5. Drop into shell
print("Entering virtual environment... (Type 'exit' to leave)")
subprocess.call([f"bash --rcfile <(echo 'source {venv_dir}/bin/activate')"], 
                executable='/bin/bash', shell=True)