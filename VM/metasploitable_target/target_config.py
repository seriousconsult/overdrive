"""Constants for the Metasploitable 2 intentional target VM."""

from __future__ import annotations

from pathlib import Path

from detections.common.common_vm import (
    TARGET_SERIAL_TCP_PORT,
    TEST_LAN_INTNET_NAME,
    TEST_TARGET_VM_NAME,
)

__all__ = [
    "CLIENT_MEMORY_MIB",
    "CLIENT_VM_CPUS",
    "CREATE_SCRIPT_NAME",
    "LAN_INTNET_NAME",
    "METASPLOITABLE_DIR",
    "METASPLOITABLE_LOGIN_HINT",
    "METASPLOITABLE_URL",
    "METASPLOITABLE_VMDK_NAME",
    "METASPLOITABLE_ZIP_NAME",
    "REPO_ROOT",
    "TARGET_QCOW_NAME",
    "TARGET_SERIAL_TCP_PORT",
    "VM_NAME",
]

METASPLOITABLE_DIR = Path(__file__).resolve().parent
REPO_ROOT = str(METASPLOITABLE_DIR.parents[1])
CREATE_SCRIPT_NAME = "create_VM_target_metasploitable.py"

LAN_INTNET_NAME = TEST_LAN_INTNET_NAME
VM_NAME = TEST_TARGET_VM_NAME
TARGET_QCOW_NAME = "metasploitable2.qcow2"
CLIENT_VM_CPUS = 1
CLIENT_MEMORY_MIB = 512

# Official Metasploitable 2 (Rapid7 / SourceForge). Intentionally vulnerable — lab LAN only.
METASPLOITABLE_ZIP_NAME = "metasploitable-linux-2.0.0.zip"
METASPLOITABLE_VMDK_NAME = "Metasploitable.vmdk"
METASPLOITABLE_URL = (
    "https://downloads.sourceforge.net/project/metasploitable/Metasploitable2/"
    "metasploitable-linux-2.0.0.zip"
)
METASPLOITABLE_LOGIN_HINT = "msfadmin / msfadmin (stock Metasploitable 2 — not hardened)"
