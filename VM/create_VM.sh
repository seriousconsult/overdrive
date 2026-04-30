#!/bin/bash

# create a VM with a bridged adapter in promiscuous mode
# cd /mnt/c/Users/serio/'VirtualBox VMs'
#!/bin/bash

# --- 1. Find VirtualBox ---
VBOX="/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"

# --- 2. Configuration ---
VM_NAME="Network_Test_OSBoxes"
# Path to where you extracted the OSBoxes VDI file (WSL Path)
OSBOXES_SRC="/mnt/c/Users/serio/Downloads/Ubuntu_25.04_VB_64bit.vdi"

# Destination for the VM disk (Windows format for VBoxManage)
VDI_DEST="C:\Users\serio\VirtualBox VMs\Network_Test_OSBoxes\Network_Test.vdi"

INTERFACE='Killer(TM) Wi-Fi 7 BE1750w 320MHz Wireless Network Adapter (BE200D2W)'

echo "Setting up VM..."

# Create the VM
"$VBOX" createvm --name "$VM_NAME" --ostype "Ubuntu_64" --register

# Configure Specs
"$VBOX" modifyvm "$VM_NAME" \
    --memory 8192 \
    --vram 96 \
    --nic1 bridged \
    --bridgeadapter1 "$INTERFACE" \
    --nicpromisc1 allow-all \
    --graphicscontroller vmsvga

# Storage Setup
"$VBOX" storagectl "$VM_NAME" --name "SATA" --add sata

# --- 3. Handle the OSBoxes Disk ---
# copy the OSBoxes file to the VM folder
#  Username - osboxes Password - osboxes.org
if [ -f "$OSBOXES_SRC" ]; then
    # Create the directory first (via WSL)
    mkdir -p "/mnt/c/Users/serio/VirtualBox VMs/$VM_NAME"
    
    echo "Copying OSBoxes VDI to VM directory..."
    cp "$OSBOXES_SRC" "/mnt/c/Users/serio/VirtualBox VMs/$VM_NAME/Network_Test.vdi"
    
    # Attach the existing drive
    "$VBOX" storageattach "$VM_NAME" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$VDI_DEST"
    echo "✅ OSBoxes disk attached."
else
    echo "❌ OSBoxes source file not found at $OSBOXES_SRC"
    exit 1
fi

echo "✨ Done! You can now start the VM in the VirtualBox GUI."
echo "📝 Note: Default OSBoxes credentials are usually osboxes / osboxes.org"