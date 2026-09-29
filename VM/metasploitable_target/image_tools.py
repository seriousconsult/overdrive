"""Download Metasploitable 2 and convert the VMDK to qcow2."""

from __future__ import annotations

import os
import subprocess
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

    zip_path = os.path.join(download_dir, METASPLOITABLE_ZIP_NAME)
    extract_dir = os.path.join(download_dir, "metasploitable2")
    download_metasploitable_zip(url, zip_path)
    vmdk = extract_metasploitable_vmdk(zip_path, extract_dir)
    marker = Path(qcow_path).with_name(f"{Path(qcow_path).name}.verified")
    source_signature = _source_signature(vmdk)
    if os.path.isfile(qcow_path) and os.path.getsize(qcow_path) > 100_000_000:
        if _marker_matches_source(marker, source_signature) and _qcow_basic_check(qcow_path):
            _write_verified_marker(marker, source_signature)
            print(f"[overdrive] Target qcow2 already present: {qcow_path}")
            return
        print("[overdrive] Verifying existing target qcow2 against Metasploitable VMDK...")
        if _qcow_matches_vmdk(vmdk, qcow_path):
            _write_verified_marker(marker, source_signature)
            print(f"[overdrive] Target qcow2 already present: {qcow_path}")
            return
        print(f"[overdrive] Existing target qcow2 is incomplete or stale; rebuilding: {qcow_path}")
        try:
            os.remove(qcow_path)
        except FileNotFoundError:
            pass

    Path(qcow_path).parent.mkdir(parents=True, exist_ok=True)
    convert_disk_to_qcow2(vmdk, qcow_path)
    _write_verified_marker(marker, source_signature)


def _source_signature(vmdk_path: str) -> str:
    path = Path(vmdk_path)
    stat = path.stat()
    return f"{path.name}:{stat.st_size}:{stat.st_mtime_ns}"


def _marker_matches_source(marker: Path, source_signature: str) -> bool:
    try:
        marker_text = marker.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return False
    if marker_text == "ok":
        return True
    return marker_text == f"source={source_signature}"


def _write_verified_marker(marker: Path, source_signature: str) -> None:
    marker.write_text(f"source={source_signature}\n", encoding="utf-8")


def _qcow_basic_check(qcow_path: str) -> bool:
    _, qemu_img = require_qemu_tools()
    result = subprocess.run(
        [qemu_img, "check", qcow_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return True
    detail = ((result.stderr or "") + (result.stdout or "")).strip()
    if detail:
        print(f"[overdrive] qemu-img check: {detail}")
    return False


def _qcow_matches_vmdk(vmdk_path: str, qcow_path: str) -> bool:
    _, qemu_img = require_qemu_tools()
    result = subprocess.run(
        [qemu_img, "compare", "-f", "vmdk", "-F", "qcow2", vmdk_path, qcow_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        detail = ((result.stderr or "") + (result.stdout or "")).strip()
        if detail:
            print(f"[overdrive] qemu-img compare: {detail}")
        return False
    detail = ((result.stderr or "") + (result.stdout or "")).strip()
    raise RuntimeError(f"Could not verify target qcow2 with qemu-img compare: {detail}")
