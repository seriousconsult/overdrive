#!/usr/bin/env python3


import os
import venv
import subprocess
import sys

venv_dir = "virtual_env"


def is_chrome_installed():
    """Check if Google Chrome is installed."""
    try:
        result = subprocess.run(
            ["which", "google-chrome-stable"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def install_chrome():
    """Install Google Chrome on Debian/Ubuntu-based systems."""
    print("Google Chrome not found. Installing...")

    try:
        # Add Google Chrome repository
        subprocess.run(
            "wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | sudo apt-key add -",
            shell=True,
            check=True
        )
        subprocess.run(
            'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list',
            shell=True,
            check=True
        )
        # Update and install
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "install", "-y", "google-chrome-stable"], check=True)
        print("Google Chrome installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install Chrome: {e}")
        return False
    return True


# 1. Create the virtual environment
print(f"Creating venv in {venv_dir}...")
venv.create(venv_dir, with_pip=True)

# 2. Path to the new environment's python executable
if sys.platform == "win32":
    python_exe = os.path.join(venv_dir, "Scripts", "python.exe")
else:
    python_exe = os.path.join(venv_dir, "bin", "python")

# 3. Install packages using the venv's python
print("Installing packages...")
subprocess.check_call([python_exe, "-m", "pip", "install", 
                       "requests", "selenium", "httpx[http2]", "scapy"])

# 4. Install Chrome if not present (Linux only)
if sys.platform != "win32":
    if not is_chrome_installed():
        install_chrome()
    else:
        print("Google Chrome is already installed.")

print("\nSuccess! Virtual environment is ready.")
print(f"Activate it with: source {venv_dir}/bin/activate")

# 5. Drop the user into a sub-shell with the venv activated
print("Entering virtual environment... (Type 'exit' to leave)")
subprocess.call([f"bash --rcfile <(echo 'source {venv_dir}/bin/activate')"], 
                    executable='/bin/bash', shell=True)