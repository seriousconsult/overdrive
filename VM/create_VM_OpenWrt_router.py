#!/usr/bin/env python3
import os
import subprocess
import platform 
import getpass
import time
'''
TODO: finish this script to automate the creation of an OpenWrt VM in VirtualBox, 
with dynamic path detection for both WSL and Linux environments. 
The script should handle downloading the OpenWrt image, converting it to VDI format,
 creating/registering the VM, configuring it with appropriate settings.
'''

# --- 1. Global Variables ---
VM_NAME = "OpenWrt_2026_Router"
VBOX = "/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
OPENWRT_URL = "https://downloads.openwrt.org/releases/25.12.2/targets/x86/64/openwrt-25.12.2-x86-64-generic-ext4-combined.img.gz"

# --- 2. Dynamic Detection Functions ---
def get_system_paths():
    is_wsl = "microsoft-standard" in platform.release().lower()
    if is_wsl:
        proc = subprocess.run(["cmd.exe", "/c", "echo %USERPROFILE%"], capture_output=True, text=True)
        win_profile = proc.stdout.strip()
        wsl_user_path = win_profile.replace('C:', '/mnt/c').replace('\\', '/')
        return {
            "base_path": wsl_user_path,
            "is_wsl": True,
            "win_user": win_profile.split('\\')[-1],
            "win_profile": win_profile
        }
    else:
        return {
            "base_path": os.path.expanduser("~"),
            "is_wsl": False,
            "win_user": getpass.getuser(),
            "win_profile": os.path.expanduser("~")
        }

def get_active_bridged_interface(vbox_path):
    try:
        res = subprocess.run([vbox_path, "list", "-l", "bridgedifs"], capture_output=True, text=True, check=True)
        adapters = res.stdout.strip().split('\n\n')
        for block in adapters:
            details = {line.split(":", 1)[0].strip(): line.split(":", 1)[1].strip() for line in block.splitlines() if ":" in line}
            if details.get("Status") == "Up":
                return details.get("Name")
    except: pass
    return "Ethernet"

# --- 3. Path Resolution ---
paths = get_system_paths()
win_user = paths["win_user"]
win_profile = paths["win_profile"]
base = paths["base_path"]

# WSL Paths for Python/Linux commands
IMG_PATH_WSL = f"{base}/Downloads/openwrt_2026.img"
VM_BASE_WSL = f"{base}/VirtualBox VMs/{VM_NAME}"
INTERFACE = get_active_bridged_interface(VBOX)

# Windows Paths for VBoxManage.exe
IMG_PATH_WIN = f"{win_profile}\\Downloads\\openwrt_2026.img"
VDI_DEST_WIN = f"{win_profile}\\VirtualBox VMs\\{VM_NAME}\\openwrt.vdi"
VBOX_FILE_WIN = f"{win_profile}\\VirtualBox VMs\\{VM_NAME}\\{VM_NAME}.vbox"

# --- 4. Main Execution ---
def setup_openwrt_vm():
    os.makedirs(VM_BASE_WSL, exist_ok=True)
    target_vdi_wsl = os.path.join(VM_BASE_WSL, "openwrt.vdi")

    if os.path.exists(target_vdi_wsl):
        print(f"VDI already exists. Skipping download.")
    else:
        print(f"Downloading and unzipping OpenWrt 25.12.2...")
        # Use zcat for Linux stream, output to the WSL-visible path
        cmd = f"curl -L {OPENWRT_URL} | zcat > '{IMG_PATH_WSL}'"
        subprocess.run(cmd, shell=True, check=True)
        
        # Give Windows a second to acknowledge the new file
        time.sleep(2)

        print(f"Converting Image to VDI...")
        print(f"Source: {IMG_PATH_WIN}")
        print(f"Dest: {VDI_DEST_WIN}")
        
        # Use Windows-style paths for the conversion
        subprocess.run([VBOX, "convertfromraw", IMG_PATH_WIN, VDI_DEST_WIN, "--format", "VDI"], check=True)
        
        if os.path.exists(IMG_PATH_WSL):
            os.remove(IMG_PATH_WSL)

    # Register/Create VM
    vms = subprocess.run([VBOX, "list", "vms"], capture_output=True, text=True).stdout
    if f'"{VM_NAME}"' not in vms:
        if os.path.exists(os.path.join(VM_BASE_WSL, f"{VM_NAME}.vbox")):
            subprocess.run([VBOX, "registervm", VBOX_FILE_WIN], check=True)
        else:
            subprocess.run([VBOX, "createvm", "--name", VM_NAME, "--ostype", "Linux_64", "--register"], check=True)

    # Configuration
    print(f"Configuring {VM_NAME}...")
    subprocess.run([VBOX, "modifyvm", VM_NAME, 
                    "--memory", "512", "--cpus", "1", 
                    "--nic1", "bridged", "--bridgeadapter1", INTERFACE,
                    "--graphicscontroller", "vmsvga"], check=True)

    # Storage Setup
    subprocess.run([VBOX, "storagectl", VM_NAME, "--name", "IDE", "--remove"], stderr=subprocess.DEVNULL)
    subprocess.run([VBOX, "storagectl", VM_NAME, "--name", "IDE", "--add", "ide"], check=True)
    subprocess.run([VBOX, "storageattach", VM_NAME, "--storagectl", "IDE", 
                    "--port", "0", "--device", "0", "--type", "hdd", "--medium", VDI_DEST_WIN], check=True)

    print(f"\nSUCCESS. Starting VM...")
    subprocess.run([VBOX, "startvm", VM_NAME, "--type", "gui"], check=True)

if __name__ == "__main__":
    setup_openwrt_vm()