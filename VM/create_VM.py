#!/usr/bin/env python3
import os
import subprocess
import requests
import shutil

# --- 1. Dynamic Detection ---
def get_windows_user():
    try:
        result = subprocess.run(["powershell.exe", "-Command", "$env:USERNAME"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except:
        return "SeanGrimaldi"

def get_active_bridged_interface(vbox_path):
    try:
        res = subprocess.run([vbox_path, "list", "bridgedifs"], capture_output=True, text=True)
        for line in res.stdout.splitlines():
            if line.startswith("Name:"):
                return line.replace("Name:", "").strip()
    except: pass
    return "Intel(R) Wi-Fi 7 BE200 320MHz"

def get_half_cpus():
    total_cpus = os.cpu_count() or 2
    return max(1, total_cpus // 2)

# --- 2. Configuration ---
win_user = get_windows_user()
VBOX = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
INTERFACE = get_active_bridged_interface(VBOX)
VM_CPUS = get_half_cpus()

VM_NAME = "Network_Test"
OSBOXES_URL = "https://downloads.sourceforge.net/project/osboxes/v/vb/59-U-u-svr/24.10/64bit.7z"

DOWNLOAD_DIR = f"/mnt/c/Users/{win_user}/Downloads"
ARCHIVE_PATH = os.path.join(DOWNLOAD_DIR, "ubuntu_osboxes.7z")
EXTRACT_DIR = os.path.join(DOWNLOAD_DIR, "temp_extraction")
VM_BASE_WSL = f"/mnt/c/Users/{win_user}/VirtualBox VMs/{VM_NAME}"
VDI_DEST_WIN = f"C:\\Users\\{win_user}\\VirtualBox VMs\\{VM_NAME}\\Network_Test.vdi"
VBOX_FILE_WIN = f"C:\\Users\\{win_user}\\VirtualBox VMs\\{VM_NAME}\\{VM_NAME}.vbox"

def setup_osboxes_vm():
    os.makedirs(VM_BASE_WSL, exist_ok=True)
    target_vdi_wsl = os.path.join(VM_BASE_WSL, "Network_Test.vdi")

    # --- Step 1: Extraction ---
    if os.path.exists(target_vdi_wsl):
        print(f"VDI already exists at {target_vdi_wsl}. Skipping extraction.")
    else:
        if not os.path.exists(ARCHIVE_PATH):
            print("Downloading OSBoxes archive...")
            r = requests.get(OSBOXES_URL, stream=True, allow_redirects=True)
            with open(ARCHIVE_PATH, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
        
        print("Extracting VDI...")
        if os.path.exists(EXTRACT_DIR): shutil.rmtree(EXTRACT_DIR)
        os.makedirs(EXTRACT_DIR, exist_ok=True)
        subprocess.run(["7z", "x", ARCHIVE_PATH, f"-o{EXTRACT_DIR}", "-y"], check=True)
        
        found_vdi = None
        for root, _, files in os.walk(EXTRACT_DIR):
            for file in files:
                if file.lower().endswith((".vdi", ".vmdk")):
                    found_vdi = os.path.join(root, file); break
        
        if found_vdi:
            print(f"Moving {os.path.basename(found_vdi)} to VM folder...")
            shutil.copy(found_vdi, target_vdi_wsl)
            shutil.rmtree(EXTRACT_DIR)
        else:
            print("Error: No VDI found in archive."); return

    # --- Step 2: Registration ---
    vms = subprocess.run([VBOX, "list", "vms"], capture_output=True, text=True).stdout
    if f'"{VM_NAME}"' not in vms:
        if os.path.exists(os.path.join(VM_BASE_WSL, f"{VM_NAME}.vbox")):
            print("Registering existing .vbox file...")
            subprocess.run([VBOX, "registervm", VBOX_FILE_WIN], check=True)
        else:
            print("Creating new VM...")
            subprocess.run([VBOX, "createvm", "--name", VM_NAME, "--ostype", "Ubuntu_64", "--register"], check=True)

    # --- Step 3: Configuration ---
    print(f"Configuring hardware: {VM_CPUS} CPUs, 8GB RAM, Bridged on {INTERFACE}...")

    subprocess.run([VBOX, "modifyvm", VM_NAME, 
                    "--memory", "8192", "--cpus", str(VM_CPUS), 
                    "--nic1", "bridged", "--bridgeadapter1", INTERFACE,
                    "--graphicscontroller", "vmsvga", "--vram", "128"], check=True)

    # Enable host time sync
    subprocess.run([VBOX, "setextradata", VM_NAME, "VBoxInternal/Devices/VMMDev/0/Config/GetHostTimeDisabled", "0"])

    # Attach Storage
    print("Attaching storage controllers and disk...")
    subprocess.run([VBOX, "storagectl", VM_NAME, "--name", "SATA", "--add", "sata"], stderr=subprocess.DEVNULL)
    subprocess.run([VBOX, "storageattach", VM_NAME, "--storagectl", "SATA", 
                    "--port", "0", "--device", "0", "--type", "hdd", "--medium", VDI_DEST_WIN], check=True)

    # --- Step 4: Final Start ---
    print(f"Setup complete. Starting {VM_NAME}...")
    subprocess.run([VBOX, "startvm", VM_NAME, "--type", "gui"], check=True)

if __name__ == "__main__":
    setup_osboxes_vm()