"""Legacy stub — all OS package installs are handled by ``install.py``."""

from __future__ import annotations

__all__ = ["client_package_install_script"]


def client_package_install_script() -> str:
    return """#!/bin/bash
# OS packages are installed by /root/install.py during guest prime.
echo "[overdrive] package bootstrap deferred to install.py"
exit 0
"""
