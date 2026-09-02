"""Constants for the test client VM builder."""

from __future__ import annotations

from pathlib import Path

from detections.common.common_vm import TEST_CLIENTA_VM_NAME, TEST_LAN_INTNET_NAME

__all__ = [
    "ALPINE_CLIENT_DIR",
    "ALPINE_IMAGE_NAME",
    "ALPINE_SERIAL_TCP_PORT",
    "ALPINE_URL",
    "CLIENT_GUEST_HOSTNAME",
    "CLIENT_MEMORY_MIB",
    "CLIENT_ROOT_DEVICE",
    "CLIENT_VDI_NAME",
    "CLIENT_VDI_SIZE_MIB",
    "CLIENT_VM_CPUS",
    "CREATE_SCRIPT_NAME",
    "LAN_INTNET_NAME",
    "REPO_ROOT",
    "VM_NAME",
]

ALPINE_CLIENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = str(ALPINE_CLIENT_DIR.parents[1])
CREATE_SCRIPT_NAME = "create_VM_client_browser_pipe_alpine.py"

LAN_INTNET_NAME = TEST_LAN_INTNET_NAME
VM_NAME = TEST_CLIENTA_VM_NAME
CLIENT_VDI_NAME = "client_browser_alpine.vdi"
CLIENT_VM_CPUS = 1
CLIENT_GUEST_HOSTNAME = "clienta"
# Chromium + detection Python libs need more than the tiny cloud image default.
CLIENT_VDI_SIZE_MIB = 8192
CLIENT_MEMORY_MIB = 2048
CLIENT_ROOT_DEVICE = "/dev/sda"

ALPINE_SERIAL_TCP_PORT = 2325

ALPINE_URL = "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.10-x86_64-bios-tiny-r0.qcow2"
ALPINE_IMAGE_NAME = "nocloud_alpine-3.20.10-x86_64-bios-tiny-r0.qcow2"
