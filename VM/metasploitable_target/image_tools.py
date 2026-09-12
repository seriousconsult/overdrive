"""Download Metasploitable 2 and convert the VMDK to qcow2."""

from __future__ import annotations

import os
import urllib.request
import zipfile
from pathlib import Path

from detections.common.common_qemu import convert_disk_to_qcow2, require_qemu_tools
from VM.metasploitable_target.target_config import (
    METASPLOITABLE_URL,
    METASPLOITABLE_VMDK_NAME,
    METASPLOITABLE_ZIP_NAME,
)

__all__ = [
    "download_metasploitable_zip",
    "ensure_metasploitable_qcow2",
    "extract_metasploitable_vmdk",
]


def download_metasploitable_zip(url: str, dest_zip: str) -> None:
    Path(dest_zip).parent.mkdir(parents=True, exist_ok=True)
    if os.path.isfile(dest_zip) and os.path.getsize(dest_zip) > 100_000_000:
        print(f"[overdrive] Metasploitable zip already present: {dest_zip}")
        return
    print(f"[overdrive] Downloading Metasploitable 2 (~800MB) from SourceForge...")
    print(f"  URL: {url}")
    print(f"  Dest: {dest_zip}")
    tmp = dest_zip + ".partial"
    try:
        urllib.request.urlretrieve(url, tmp)
        os.replace(tmp, dest_zip)
    except Exception:
        if os.path.isfile(tmp):
            os.remove(tmp)
        raise
    print(f"[overdrive] Download complete: {dest_zip}")


def extract_metasploitable_vmdk(zip_path: str, extract_dir: str) -> str:
    """Extract the VMDK set from the zip; return path to the descriptor VMDK."""
    extract_root = Path(extract_dir)
    extract_root.mkdir(parents=True, exist_ok=True)
    # Reuse extracted tree if the descriptor already exists.
    existing = list(extract_root.rglob(METASPLOITABLE_VMDK_NAME))
    if existing:
        print(f"[overdrive] Using existing VMDK: {existing[0]}")
        return str(existing[0])

    print(f"[overdrive] Extracting {zip_path} ...")
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_root)

    matches = list(extract_root.rglob(METASPLOITABLE_VMDK_NAME))
    if not matches:
        raise RuntimeError(
            f"Could not find {METASPLOITABLE_VMDK_NAME} after extracting {zip_path}"
        )
    print(f"[overdrive] Extracted VMDK: {matches[0]}")
    return str(matches[0])


def ensure_metasploitable_qcow2(
    *,
    download_dir: str,
    qcow_path: str,
    url: str = METASPLOITABLE_URL,
) -> None:
    """Download + extract + convert Metasploitable 2 into ``qcow_path`` if needed."""
    require_qemu_tools()
    if os.path.isfile(qcow_path) and os.path.getsize(qcow_path) > 100_000_000:
        print(f"[overdrive] Target qcow2 already present: {qcow_path}")
        return

    zip_path = os.path.join(download_dir, METASPLOITABLE_ZIP_NAME)
    extract_dir = os.path.join(download_dir, "metasploitable2")
    download_metasploitable_zip(url, zip_path)
    vmdk = extract_metasploitable_vmdk(zip_path, extract_dir)
    Path(qcow_path).parent.mkdir(parents=True, exist_ok=True)
    convert_disk_to_qcow2(vmdk, qcow_path)
