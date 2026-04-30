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

win_user = get_windows_user()
VBOX = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
INTERFACE = get_active_bridged_interface(VBOX)

# --- 2. Configuration ---
VM_NAME = "Network_Test"
OSBOXES_URL = "https://downloads.sourceforge.net/project/osboxes/v/vb/59-U-u-svr/24.10/64bit.7z"

DOWNLOAD_DIR = f"/mnt/c/Users/{win_user}/Downloads"
ARCHIVE_PATH = os.path.join(DOWNLOAD_DIR, "ubuntu_osboxes.7z")
EXTRACT_DIR = os.path.join(DOWNLOAD_DIR, "temp_extraction")
VM_BASE_WSL = f"/mnt/c/Users/{win_user}/VirtualBox VMs/{VM_NAME}"
VDI_DEST_WIN = f"C:\\Users\\{win_user}\\VirtualBox VMs\\{VM_NAME}\\Network_Test.vdi"
VBOX_FILE_WIN = f"C:\\Users\\{win_user}\\VirtualBox VMs\\{VM_NAME}\\{VM_NAME}.vbox"

def setup_osboxes_vm():
    # Ensure VM directory exists
    os.makedirs(VM_BASE_WSL, exist_ok=True)
    target_vdi = os.path.join(VM_BASE_WSL, "Network_Test.vdi")

    # 1. Skip Extraction if VDI already exists
    if os.path.exists(target_vdi):
        print(f"✅ VDI already exists at {target_vdi}. Skipping extraction.")
    else:
        # Download if archive missing
        if not os.path.exists(ARCHIVE_PATH):
            print(f"📥 Downloading OSBoxes archive...")
            r = requests.get(OSBOXES_URL, stream=True, allow_redirects=True)
            with open(ARCHIVE_PATH, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192): f.write(chunk)
        
        print(f"📂 Extracting VDI...")
        os.makedirs(EXTRACT_DIR, exist_ok=True)
        subprocess.run(["7z", "x", ARCHIVE_PATH, f"-o{EXTRACT_DIR}", "-y"], check=True)
        
        # Locate VDI in temp folder
        found_vdi = None
        for root, _, files in os.walk(EXTRACT_DIR):
            for file in files:
                if file.lower().endswith((".vdi", ".vmdk")):
                    found_vdi = os.path.join(root, file); break
        
        if found_vdi:
            print(f"🚚 Moving {os.path.basename(found_vdi)}...")
            shutil.move(found_vdi, target_vdi)
            shutil.rmtree(EXTRACT_DIR)
        else:
            print("❌ Error: No VDI found in archive."); return

    # 2. Smart VM Registration (Fixes the CreateMachine error)
    vms = subprocess.run([VBOX, "list", "vms"], capture_output=True, text=True).stdout
    
    if f'"{VM_NAME}"' in vms:
        print(f"✨ VM '{VM_NAME}' is already registered.")
    else:
        # Check if the .vbox file exists on disk but isn't in VirtualBox
        if os.path.exists(os.path.join(VM_BASE_WSL, f"{VM_NAME}.vbox")):
            print(f"🔗 Registering existing settings file...")
            subprocess.run([VBOX, "registervm", VBOX_FILE_WIN], check=True)
        else:
            print(f"⚙️ Creating new VM...")
            subprocess.run([VBOX, "createvm", "--name", VM_NAME, "--ostype", "Ubuntu_64", "--register"], check=True)

    # 3. Final Configuration (safe to run multiple times)
    print(f"📡 Configuring network on {INTERFACE}...")
    subprocess.run([VBOX, "modifyvm", VM_NAME, 
                    "--memory", "8192", "--vram", "96", 
                    "--nic1", "bridged", "--bridgeadapter1", INTERFACE, 
                    "--nicpromisc1", "allow-all", "--graphicscontroller", "vmsvga"], check=True)

    # Attach Disk
    subprocess.run([VBOX, "storagectl", VM_NAME, "--name", "SATA", "--add", "sata"], stderr=subprocess.DEVNULL)
    subprocess.run([VBOX, "storageattach", VM_NAME, "--storagectl", "SATA", 
                    "--port", "0", "--device", "0", "--type", "hdd", "--medium", VDI_DEST_WIN], check=True)

    print(f"🚀 Success! {VM_NAME} is ready.")

if __name__ == "__main__":
    setup_osboxes_vm()