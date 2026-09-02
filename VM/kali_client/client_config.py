"""Constants for the Kali test client VM builder."""

from __future__ import annotations

from pathlib import Path

from detections.common.common_vm import (
    CLIENTK_SERIAL_TCP_PORT,
    TEST_CLIENTK_VM_NAME,
    TEST_LAN_INTNET_NAME,
)

__all__ = [
    "CLIENT_GUEST_HOSTNAME",
    "CLIENT_MEMORY_MIB",
    "CLIENT_ROOT_DEVICE",
    "CLIENT_VDI_NAME",
    "CLIENT_VDI_SIZE_MIB",
    "CLIENT_VM_CPUS",
    "CREATE_SCRIPT_NAME",
    "KALI_CLIENT_DIR",
    "KALI_IMAGE_NAME",
    "KALI_SERIAL_TCP_PORT",
    "KALI_TAR_NAME",
    "KALI_URL",
    "LAN_INTNET_NAME",
    "REPO_ROOT",
    "VM_NAME",
]

KALI_CLIENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = str(KALI_CLIENT_DIR.parents[1])
CREATE_SCRIPT_NAME = "create_VM_client_kali.py"

LAN_INTNET_NAME = TEST_LAN_INTNET_NAME
VM_NAME = TEST_CLIENTK_VM_NAME
CLIENT_VDI_NAME = "client_browser_kali.vdi"
CLIENT_VM_CPUS = 2
CLIENT_GUEST_HOSTNAME = "clientk"
CLIENT_VDI_SIZE_MIB = 16384
CLIENT_MEMORY_MIB = 4096
CLIENT_ROOT_DEVICE = "/dev/sda1"

KALI_SERIAL_TCP_PORT = CLIENTK_SERIAL_TCP_PORT

KALI_TAR_NAME = "kali-linux-2026.2-cloud-genericcloud-amd64.tar.xz"
KALI_IMAGE_NAME = "kali-linux-2026.2-cloud-genericcloud-amd64.qcow2"
KALI_URL = "https://kali.download/cloud-images/current/kali-linux-2026.2-cloud-genericcloud-amd64.tar.xz"
