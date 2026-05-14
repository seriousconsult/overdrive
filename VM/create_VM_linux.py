#!/usr/bin/env python3
'''
TODO: finish this script to automate the creation of an Linux VM in VirtualBox.
'''

import os
import subprocess
import requests
import shutil
import platform 
import getpass
import sys

# Ensure sibling common/ package is importable when running this script from VM/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from common.common_vm import get_active_bridged_interface, get_half_cpus, get_system_paths

# --- 1. Global Variables (Define these first!) ---
VM_NAME = "Network_Test"
VBOX = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
OSBOXES_URL = "https://sourceforge.net/projects/osboxes/files/v/vm/59-Uu--svr/24.04/64bit.7z/download"

# --- 2. Dynamic Detection Functions ---

# --- 3. Final Path Resolution ---
paths = get_system_paths(VM_NAME)
win_user = paths["win_user"]
base = paths["base_path"]


DOWNLOAD_DIR = f"{base}/Downloads"
ARCHIVE_PATH = os.path.join(DOWNLOAD_DIR, "ubuntu_osboxes_2404.7z")
EXTRACT_DIR = os.path.join(DOWNLOAD_DIR, "temp_extraction")
VM_BASE_WSL = f"{base}/VirtualBox VMs/{VM_NAME}"
INTERFACE = get_active_bridged_interface(VBOX)
VM_CPUS = get_half_cpus()


# Windows-style paths for VBoxManage.exe arguments
if paths["is_wsl"]:
    VDI_DEST_WIN = f"C:\\Users\\{win_user}\\VirtualBox VMs\\{VM_NAME}\\Network_Test.vdi"
    VBOX_FILE_WIN = f"C:\\Users\\{win_user}\\VirtualBox VMs\\{VM_NAME}\\{VM_NAME}.vbox"
else:
    VDI_DEST_WIN = os.path.join(VM_BASE_WSL, "Network_Test.vdi")
    VBOX_FILE_WIN = os.path.join(VM_BASE_WSL, f"{VM_NAME}.vbox")


# --- 4. Main Execution ---
def setup_osboxes_vm():
    # Now it creates /mnt/c/Users/serio/... which exists!
    os.makedirs(VM_BASE_WSL, exist_ok=True)
    target_vdi_wsl = os.path.join(VM_BASE_WSL, "Network_Test.vdi")

    if os.path.exists(target_vdi_wsl):
        print(f"VDI already exists. Skipping extraction.")
    else:
        if not os.path.exists(ARCHIVE_PATH):
            print("Downloading OSBoxes archive...")
            r = requests.get(OSBOXES_URL, stream=True, allow_redirects=True)
            with open(ARCHIVE_PATH, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
        
        print("Extracting VDI...")
        if os.path.exists(EXTRACT_DIR): shutil.rmtree(EXTRACT_DIR)
        os.makedirs(EXTRACT_DIR, exist_ok=True)
        # Ensure 7z is installed: sudo apt install p7zip-full
        subprocess.run(["7z", "x", ARCHIVE_PATH, f"-o{EXTRACT_DIR}", "-y"], check=True)
        
        found_vdi = None
        for root, _, files in os.walk(EXTRACT_DIR):
            for file in files:
                if file.lower().endswith((".vdi", ".vmdk")):
                    found_vdi = os.path.join(root, file); break
        
        if found_vdi:
            shutil.copy(found_vdi, target_vdi_wsl)
            shutil.rmtree(EXTRACT_DIR)
        else:
            print("Error: No VDI found."); return

    # Register/Create
    vms = subprocess.run([VBOX, "list", "vms"], capture_output=True, text=True).stdout
    if f'"{VM_NAME}"' not in vms:
        if os.path.exists(os.path.join(VM_BASE_WSL, f"{VM_NAME}.vbox")):
            subprocess.run([VBOX, "registervm", VBOX_FILE_WIN], check=True)
        else:
            subprocess.run([VBOX, "createvm", "--name", VM_NAME, "--ostype", "Ubuntu_64", "--register"], check=True)

    # Config
    print(f"Configuring {VM_NAME} on {INTERFACE}...")
    subprocess.run([VBOX, "modifyvm", VM_NAME, 
                    "--memory", "8192", "--cpus", str(VM_CPUS), 
                    "--nic1", "bridged", "--bridgeadapter1", INTERFACE,
                    "--graphicscontroller", "vmsvga", "--vram", "128"], check=True)

    # Storage
    subprocess.run([VBOX, "storagectl", VM_NAME, "--name", "SATA", "--add", "sata"], stderr=subprocess.DEVNULL)
    subprocess.run([VBOX, "storageattach", VM_NAME, "--storagectl", "SATA", 
                    "--port", "0", "--device", "0", "--type", "hdd", "--medium", VDI_DEST_WIN], check=True)
    

    # --- Set Host Key to Left CTRL ---
    # Key code 16777249 corresponds to the Left Control key
    print("Setting Host Escape key to Left CTRL...")
    subprocess.run([VBOX, "setextradata", VM_NAME, "GUI/Input/HostKeyCombination", "16777249"], check=True)

    print("Setup complete. Starting VM...")
    subprocess.run([VBOX, "startvm", VM_NAME, "--type", "gui"], check=True)


if __name__ == "__main__":
    setup_osboxes_vm()
