"""Legacy stub kept for older imports; Kali now uses the prebuilt QEMU image."""

from __future__ import annotations

__all__ = ["client_package_install_script"]


def client_package_install_script() -> str:
    return """#!/bin/bash
# The Kali QEMU image already carries the default Kali toolset.
echo "[overdrive] package bootstrap skipped for prebuilt Kali QEMU image"
exit 0
"""
