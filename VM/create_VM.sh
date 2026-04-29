#!/bin/bash

# create a VM with a bridged adapter in promiscuous mode
# cd /mnt/c/Users/serio/'VirtualBox VMs'

# --- 1. Find VirtualBox (The Fix) ---
# We point directly to the default Windows install path
VBOX="/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"

# --- 2. Configuration ---
VM_NAME="Network_Test"
ISO_PATH="/mnt/c/Users/serio/Downloads/ubuntu-26.04-live-server-amd64.iso"
VDI_PATH="C:\Users\serio\VirtualBox VMs\Network_Test\Network_Test.vdi"
INTERFACE='Killer(TM) Wi-Fi 7 BE1750w 320MHz Wireless Network Adapter (BE200D2W)'

echo "Attempting to create the VM..."

# Create the VM
"$VBOX" createvm --name "$VM_NAME" --ostype "Ubuntu_64" --register

# Configure Specs
"$VBOX" modifyvm "$VM_NAME" \
    --memory 8192 \
    --vram 96 \
    --nic1 bridged \
    --bridgeadapter1 "$INTERFACE" \
    --nicpromisc1 allow-all

# Storage Setup
"$VBOX" storagectl "$VM_NAME" --name "SATA" --add sata
"$VBOX" storagectl "$VM_NAME" --name "IDE" --add ide

# Create Hard Drive
"$VBOX" createmedium disk --filename "$VDI_PATH" --size 25000

# Attach Drive
"$VBOX" storageattach "$VM_NAME" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$VDI_PATH"

# Attach ISO (Using wslpath so the Windows .exe understands the path)
if [ -f "$ISO_PATH" ]; then
    WIN_ISO=$(wslpath -w "$ISO_PATH")
    "$VBOX" storageattach "$VM_NAME" --storagectl "IDE" --port 0 --device 0 --type dvddrive --medium "$WIN_ISO"
    echo "✅ ISO is locked and loaded."
else
    echo "❌ ISO not found at $ISO_PATH"
fi

echo "✨ If no errors appeared above, your VM is ready in the GUI!"