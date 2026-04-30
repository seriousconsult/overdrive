#!/usr/bin/env python3

import subprocess
import requests
import shutil
import os
import getpass

#!/usr/bin/env python3
import os
import subprocess
import requests
import shutil

# --- 1. Truly Dynamic Windows User Detection ---
def get_windows_user():
    try:
        # Ask Windows directly via PowerShell
        result = subprocess.run(
            ["powershell.exe", "-Command", "$env:USERNAME"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except Exception:
        # Fallback to the most common folder if PowerShell fails
        # This lists C:\Users and picks the first one that isn't 'Public' or 'Default'
        users = [d for d in os.listdir('/mnt/c/Users') if d not in ['Public', 'Default', 'desktop.ini']]
        return users[0] if users else "serio"

win_user = get_windows_user()
print(f"Detected Windows User: {win_user}")

# --- 2. Configuration ---
VM_NAME = "Network_Test_OSBoxes"

#OSBOXES_URL = "https://sourceforge.net/projects/osboxes/files/v/vb/59-U-u-svr/24.10/64bit.7z/download"
OSBOXES_URL = "https://downloads.sourceforge.net/project/osboxes/v/vb/59-U-u-svr/24.10/64bit.7z"
# In the download block, add 'allow_redirects=True'
response = requests.get(OSBOXES_URL, stream=True, timeout=30, allow_redirects=True)


VBOX = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
DOWNLOAD_DIR = f"/mnt/c/Users/{win_user}/Downloads"
ARCHIVE_PATH = os.path.join(DOWNLOAD_DIR, "ubuntu_osboxes.7z")
EXTRACT_DIR = os.path.join(DOWNLOAD_DIR, "temp_extraction")

VM_BASE_WSL = f"/mnt/c/Users/{win_user}/VirtualBox VMs/{VM_NAME}"
VDI_DEST_WIN = f"C:\\Users\\{win_user}\\VirtualBox VMs\\{VM_NAME}\\Network_Test.vdi"
INTERFACE = 'Killer(TM) Wi-Fi 7 BE1750w 320MHz Wireless Network Adapter (BE200D2W)'



def setup_osboxes_vm():
    # Ensure the download directory exists! (Fixes the FileNotFoundError)
    if not os.path.exists(DOWNLOAD_DIR):
        print(f"Creating directory: {DOWNLOAD_DIR}")
        os.makedirs(DOWNLOAD_DIR, exist_ok=True)

    # 1. Download the Archive
    if not os.path.exists(ARCHIVE_PATH):
        print(f"Downloading OSBoxes image from {OSBOXES_URL}...")
        try:
            response = requests.get(OSBOXES_URL, stream=True, timeout=30)
            response.raise_for_status() # Check for HTTP errors
            with open(ARCHIVE_PATH, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        except Exception as e:
            print(f"❌ Download failed: {e}")
            return
    else:
        print("Archive already exists, skipping download.")

    # 2. Extract using '7z'
    print(f"Extracting VDI (recursively)...")
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    
    # Use 'x' instead of 'e' to handle internal folders, and -y to overwrite
    # This will extract the '64bit' folder into your EXTRACT_DIR
    subprocess.run(["7z", "x", ARCHIVE_PATH, f"-o{EXTRACT_DIR}", "-y"], check=True)

    # 3. Create VM via VBoxManage
    print(f"Creating VirtualBox VM: {VM_NAME}...")
    # Check if VM already exists to avoid errors
    check_vm = subprocess.run([VBOX, "list", "vms"], capture_output=True, text=True)
    if f'"{VM_NAME}"' not in check_vm.stdout:
        subprocess.run([VBOX, "createvm", "--name", VM_NAME, "--ostype", "Ubuntu_64", "--register"], check=True)
    else:
        print(f"VM '{VM_NAME}' already registered. Skipping creation.")

    # 4. Configure Specs
    subprocess.run([VBOX, "modifyvm", VM_NAME, 
                    "--memory", "8192", 
                    "--vram", "96", 
                    "--nic1", "bridged", 
                    "--bridgeadapter1", INTERFACE, 
                    "--nicpromisc1", "allow-all", 
                    "--graphicscontroller", "vmsvga"], check=True)

    # 5. Move Disk and Attach
    os.makedirs(VM_BASE_WSL, exist_ok=True)
    
    # Walk through the EXTRACT_DIR to find the VDI anywhere inside
    found_vdi = None
    for root, dirs, files in os.walk(EXTRACT_DIR):
        for file in files:
            if file.lower().endswith(".vdi"):
                found_vdi = os.path.join(root, file)
                break
        if found_vdi: break

    if not found_vdi:
        print("❌ Error: No VDI found anywhere in the extracted archive.")
        return

    target_vdi = os.path.join(VM_BASE_WSL, "Network_Test.vdi")
    
    print(f"🚚 Moving {os.path.basename(found_vdi)} to VM folder...")
    shutil.move(found_vdi, target_vdi)

    # 6. Storage Controller & Attachment
    # Add SATA if not present (ignoring error if it already exists)
    subprocess.run([VBOX, "storagectl", VM_NAME, "--name", "SATA", "--add", "sata"], stderr=subprocess.DEVNULL)
    
    subprocess.run([VBOX, "storageattach", VM_NAME, "--storagectl", "SATA", 
                    "--port", "0", "--device", "0", "--type", "hdd", "--medium", VDI_DEST_WIN], check=True)

    # Cleanup
    shutil.rmtree(EXTRACT_DIR)
    print(f"✅ VM {VM_NAME} is ready to boot!")

if __name__ == "__main__":
    setup_osboxes_vm()