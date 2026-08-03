"""Shared helpers for ``local/*.py`` scripts (WSL detection, Windows paths, small file/MAC utils)."""

from __future__ import annotations

import os
import platform
import re
import subprocess
from typing import Final

__all__ = [
    "ensure_repo_on_path",
    "get_repo_root",
    "is_wsl_local",
    "windows_userprofile_as_wsl_path",
    "read_text_file",
    "path_exists",
    "mac_to_oui",
    "normalize_mac_colon",
    "mac_oui_colon_prefix",
]


def get_repo_root() -> str:
    """Repository root containing the ``detections`` package."""
    return str(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def ensure_repo_on_path() -> None:
    """Insert repo root on ``sys.path`` so ``from detections.common.common_local import …`` works when a script is run as a file."""
    import sys

    root = get_repo_root()
    if root not in sys.path:
        sys.path.insert(0, root)


def is_wsl_local() -> bool:
    """
    True when this process appears to run under WSL (Linux userland on Windows).

    Combines env hints, ``WSLInterop``, and ``/proc/version`` checks used across ``local/`` scripts.
    """
    if platform.system() != "Linux":
        return False
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return True
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def windows_userprofile_as_wsl_path() -> str | None:
    """
    Resolve ``%USERPROFILE%`` via ``cmd.exe`` and return a WSL path like ``/mnt/c/Users/Name``.

    Used for ``.wslconfig`` and other Windows-side paths from a WSL shell.
    """
    try:
        win_path = subprocess.check_output(
            ["cmd.exe", "/c", "echo", "%USERPROFILE%"],
            stderr=subprocess.DEVNULL,
        ).decode().strip()
        if win_path and ":" in win_path:
            drive, _, rest = win_path.partition(":")
            drive = drive.lower()
            path = rest.replace("\\", "/")
            return f"/mnt/{drive}{path}"
    except (subprocess.CalledProcessError, OSError, UnicodeDecodeError):
        pass
    return None


def read_text_file(path: str, *, encoding: str = "utf-8") -> str:
    """Read a text file; return empty string on missing or read errors."""
    try:
        with open(path, encoding=encoding, errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def path_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except OSError:
        return False


_MAC_COLON_RE: Final = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)


def normalize_mac_colon(s: str) -> str | None:
    """Normalize ``aa-bb-cc-dd-ee-ff`` or mixed case to lowercase colon form; invalid → None."""
    s = s.strip().lower().replace("-", ":")
    if _MAC_COLON_RE.fullmatch(s):
        return s
    return None


def mac_to_oui(mac: str) -> str:
    """First three octets of a MAC as six lowercase hex digits (no separators)."""
    if not mac:
        return ""
    mac = mac.lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 3:
        return ""
    return (parts[0] + parts[1] + parts[2]).lower()


def mac_oui_colon_prefix(mac: str) -> str:
    """First three octets as ``aa:bb:cc`` for OUI dict keys (same rules as former ``my_router._mac_oui_key``)."""
    m = re.sub(r"[:-]", ":", mac.strip().lower())
    parts = [p for p in m.split(":") if p]
    if len(parts) < 3:
        return ""
    return ":".join(parts[:3])
