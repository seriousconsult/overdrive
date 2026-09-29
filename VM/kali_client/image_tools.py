"""Download Kali QEMU images and grow the client disk with libguestfs."""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

from detections.common.common_local import is_wsl_local
from detections.common.common_qemu import expand_qcow2_size
from detections.common.common_vm import (
    ensure_kvm_accessible,
)
from VM.kali_client.client_config import CLIENT_ROOT_DEVICE, CLIENT_DISK_SIZE_MIB

__all__ = [
    "download_kali_image",
    "ensure_kali_disk_image",
    "ensure_kali_qcow2",
    "expand_client_disk",
    "libguestfs_env",
    "require_disk_prime_tools",
]

_DEBUG_LOG_PATH = Path(__file__).resolve().parents[2] / "debug-52b023.log"


def _agent_debug_log(*, hypothesis_id: str, location: str, message: str, data: dict) -> None:
    # #region agent log
    try:
        payload = {
            "sessionId": "52b023",
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data,
            "timestamp": int(time.time() * 1000),
        }
        with _DEBUG_LOG_PATH.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(payload) + "\n")
    except OSError:
        pass
    # #endregion


def _find_existing_fixed_appliance_dir() -> str | None:
    """Return a directory containing kernel/initrd/root/README.fixed if found."""
    candidates = [
        "/usr/lib64/guestfs/appliance",
        "/usr/lib/guestfs/appliance",
        "/usr/local/lib/guestfs/appliance",
    ]
    for c in candidates:
        d = Path(c)
        if (d / "README.fixed").is_file() and all((d / x).is_file() for x in ["kernel", "initrd", "root"]):
            return str(d)

    cache_roots = [
        Path.home() / ".cache" / "libguestfs" / "appliance",
        Path.home() / ".cache" / "guestfs" / "appliance",
    ]
    for cr in cache_roots:
        if not cr.exists():
            continue
        for d in cr.glob("**/"):
            if not d.is_dir():
                continue
            if (d / "README.fixed").is_file() and all((d / x).is_file() for x in ["kernel", "initrd", "root"]):
                return str(d)

    return None


def _download_latest_fixed_appliance(cache_dir: Path) -> str:
    """Download and extract the latest fixed appliance tarball into cache_dir."""
    cache_dir.mkdir(parents=True, exist_ok=True)

    index_url = "https://download.libguestfs.org/binaries/appliance/"
    index_html = urllib.request.urlopen(index_url, timeout=60).read().decode("utf-8", errors="replace")

    versions = re.findall(r"(appliance-\d+(?:\.\d+)+)\.tar\.xz", index_html)
    if not versions:
        raise RuntimeError("Could not parse libguestfs appliance versions from index.")

    def verkey(s: str) -> tuple[int, ...]:
        s = s.replace("appliance-", "")
        return tuple(int(x) for x in s.split("."))

    latest = max(versions, key=verkey)
    tar_name = f"{latest}.tar.xz"
    tar_url = f"{index_url}{tar_name}"
    tar_path = cache_dir / tar_name

    extract_root = cache_dir / latest
    if not (extract_root / "README.fixed").is_file():
        if not tar_path.exists():
            print(f"[libguestfs] Downloading fixed appliance: {tar_name} ...")
            urllib.request.urlretrieve(tar_url, tar_path)

        print(f"[libguestfs] Extracting fixed appliance into cache: {extract_root} ...")
        if extract_root.exists():
            shutil.rmtree(extract_root)
        extract_root.mkdir(parents=True, exist_ok=True)

        with tarfile.open(tar_path, mode="r:xz") as tf:
            tf.extractall(path=extract_root)

    for d in [extract_root] + list(extract_root.glob("**/")):
        if not d.is_dir():
            continue
        if (d / "README.fixed").is_file() and all((d / x).is_file() for x in ["kernel", "initrd", "root"]):
            return str(d)

    raise RuntimeError("Downloaded appliance but could not find README.fixed + kernel/initrd/root in extracted content.")


def _pick_supermin_kernel_env() -> dict[str, str] | None:
    boot_kernels = sorted(glob.glob("/boot/vmlinuz*"))
    if boot_kernels:
        kernel = max(boot_kernels, key=lambda p: os.path.getmtime(p))
        m = re.sub(r"^/boot/vmlinuz-?", "", os.path.basename(kernel))
        mod_dir = f"/lib/modules/{m}"
        env = {"SUPERMIN_KERNEL": kernel}
        if Path(mod_dir).is_dir():
            env["SUPERMIN_MODULES"] = mod_dir
        return env
    return None


def download_kali_image(url: str, dest_path: str) -> None:
    dest = Path(dest_path)
    if dest.exists():
        print(f"Kali base archive already exists at {dest}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading Kali base image archive to {dest}...")
    with urllib.request.urlopen(url) as response:
        if response.status != 200:
            raise RuntimeError(f"Download failed with HTTP {response.status}")
        with open(dest, "wb") as out_file:
            shutil.copyfileobj(response, out_file)
    print("Download complete.")


_DISK_IMAGE_SUFFIXES = (".qcow2", ".raw", ".img", ".vmdk")


def _disk_suffix_priority(name: str) -> int:
    suffix = Path(name).suffix.lower()
    try:
        return _DISK_IMAGE_SUFFIXES.index(suffix)
    except ValueError:
        return len(_DISK_IMAGE_SUFFIXES)


def _is_disk_image_name(name: str) -> bool:
    return Path(name).suffix.lower() in _DISK_IMAGE_SUFFIXES


def _kali_disk_member_name(members: list[tarfile.TarInfo]) -> str | None:
    """Return the disk member inside a Kali tar archive (.qcow2 preferred)."""
    candidates = [m.name for m in members if m.isfile() and _is_disk_image_name(m.name)]
    if not candidates:
        return None
    candidates.sort(key=lambda n: (_disk_suffix_priority(n), Path(n).name.lower()))
    return candidates[0]


def _dest_for_kali_member(dest_qcow2: str, member_name: str) -> Path:
    dest = Path(dest_qcow2)
    suffix = Path(member_name).suffix.lower()
    if suffix and suffix != dest.suffix.lower():
        return dest.with_suffix(suffix)
    return dest


def _existing_cached_disk(dest_qcow2: str) -> Path | None:
    dest_q = Path(dest_qcow2)
    for suffix in _DISK_IMAGE_SUFFIXES:
        candidate = dest_q.with_suffix(suffix)
        if candidate.exists():
            return candidate
    return None


def _find_extracted_disk(root: Path) -> Path | None:
    candidates = [p for p in root.rglob("*") if p.is_file() and _is_disk_image_name(p.name)]
    if not candidates:
        return None

    def sort_key(path: Path) -> tuple[int, int, int, str]:
        name = path.name.lower()
        name_bonus = 0 if ("kali" in name or "qemu" in name) else 1
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        return (_disk_suffix_priority(path.name), name_bonus, -size, name)

    candidates.sort(key=sort_key)
    return candidates[0]


def _cache_extracted_disk(source: Path, dest_qcow2: str) -> Path:
    dest = _dest_for_kali_member(dest_qcow2, source.name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() == dest.resolve():
        return dest
    if dest.exists():
        dest.unlink()
    shutil.move(str(source), str(dest))
    return dest


def _extract_kali_tar_disk(archive: Path, dest_qcow2: str) -> Path:
    with tarfile.open(archive, mode="r:*") as tf:
        members = tf.getmembers()
        member_names = [m.name for m in members if m.isfile()]
        member_name = _kali_disk_member_name(members)
        _agent_debug_log(
            hypothesis_id="H1",
            location="image_tools.py:_extract_kali_tar_disk",
            message="tar members inspected",
            data={
                "archive_path": str(archive),
                "archive_size": archive.stat().st_size,
                "file_members": member_names,
                "selected_member": member_name,
            },
        )
        if not member_name:
            raise RuntimeError(
                f"No disk image member found inside {archive}. "
                f"Archive file members: {member_names or '(none)'}"
            )
        dest = _dest_for_kali_member(dest_qcow2, member_name)
        extracted = tf.extractfile(member_name)
        if extracted is None:
            raise RuntimeError(f"Could not read disk member {member_name!r} from {archive}")
        with open(dest, "wb") as out_file:
            shutil.copyfileobj(extracted, out_file)
        return dest


def _extract_kali_7z_disk(archive: Path, dest_qcow2: str) -> Path:
    seven_zip = shutil.which("7z")
    if not seven_zip:
        raise RuntimeError(
            "7z is required to extract Kali's prebuilt QEMU archive.\n"
            "Run python3 install.py on the host, or install p7zip-full/7zip."
        )

    extract_root = archive.with_suffix("")
    disk = _find_extracted_disk(extract_root) if extract_root.exists() else None
    if disk is None:
        if extract_root.exists():
            shutil.rmtree(extract_root)
        extract_root.mkdir(parents=True, exist_ok=True)
        command = [seven_zip, "x", "-y", f"-o{extract_root}", str(archive)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            detail = ((result.stderr or "") + (result.stdout or "")).strip()
            raise RuntimeError(f"7z extraction failed for {archive} (exit {result.returncode}).\n{detail[-4000:]}")
        disk = _find_extracted_disk(extract_root)

    if disk is None:
        raise RuntimeError(f"No disk image (.qcow2/.raw/.img/.vmdk) found after extracting {archive}.")
    return _cache_extracted_disk(disk, dest_qcow2)


def ensure_kali_disk_image(archive_path: str, dest_qcow2: str) -> str:
    """Extract/cache the disk from Kali's base archive if needed."""
    existing = _existing_cached_disk(dest_qcow2)
    if existing is not None:
        _agent_debug_log(
            hypothesis_id="H1",
            location="image_tools.py:ensure_kali_disk_image",
            message="disk already present",
            data={"path": str(existing), "format": existing.suffix.lstrip(".")},
        )
        print(f"Kali base disk image already exists at {existing}")
        return str(existing)

    archive = Path(archive_path)
    if not archive.is_file():
        raise RuntimeError(f"Kali archive not found: {archive_path}")

    print(f"Extracting Kali disk image from {archive}...")
    Path(dest_qcow2).parent.mkdir(parents=True, exist_ok=True)
    if archive.name.endswith(".7z"):
        dest = _extract_kali_7z_disk(archive, dest_qcow2)
    else:
        dest = _extract_kali_tar_disk(archive, dest_qcow2)
    _agent_debug_log(
        hypothesis_id="H1",
        location="image_tools.py:ensure_kali_disk_image",
        message="disk extracted",
        data={"archive": str(archive), "dest": str(dest), "dest_size": dest.stat().st_size},
    )
    print(f"Extracted Kali disk image to {dest}")
    return str(dest)


def ensure_kali_qcow2(archive_path: str, dest_qcow2: str) -> str:
    """Back-compat alias; Kali source archives may contain qcow2 or raw disks."""
    return ensure_kali_disk_image(archive_path, dest_qcow2)


def require_disk_prime_tools(*, skip_prime: bool) -> str:
    if skip_prime:
        raise RuntimeError("Disk priming is required for client network and serial features.")
    vc = shutil.which("virt-customize")
    if not vc:
        raise RuntimeError(
            "virt-customize is required to prime the Kali disk image.\n"
            "Install it in WSL with:\n"
            "  sudo apt install -y libguestfs-tools"
        )
    return vc


def libguestfs_env() -> dict[str, str]:
    ensure_kvm_accessible()
    virt_env = os.environ.copy()
    if is_wsl_local():
        virt_env.setdefault("LIBGUESTFS_BACKEND", "direct")
    virt_env.setdefault("TMPDIR", "/tmp")

    supermin_env = _pick_supermin_kernel_env()
    if supermin_env:
        virt_env.update(supermin_env)
        print(f"[libguestfs] Using supermin kernel override: SUPERMIN_KERNEL={supermin_env.get('SUPERMIN_KERNEL')}")
    else:
        fixed_dir = _find_existing_fixed_appliance_dir()
        if fixed_dir:
            virt_env["LIBGUESTFS_PATH"] = fixed_dir
        else:
            cache_dir = Path.home() / ".cache" / "libguestfs" / "appliance"
            fixed_dir = _download_latest_fixed_appliance(cache_dir)
            virt_env["LIBGUESTFS_PATH"] = fixed_dir
            print(f"[libguestfs] Downloaded & using fixed appliance: LIBGUESTFS_PATH={fixed_dir}")

    return virt_env


def _disk_virtual_size_bytes(disk_path: str) -> int | None:
    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        return None
    try:
        result = subprocess.run(
            [qemu_img, "info", "-U", "--output=json", disk_path],
            capture_output=True,
            text=True,
            check=True,
        )
        info = json.loads(result.stdout)
        size = info.get("virtual-size")
        return int(size) if size is not None else None
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError, TypeError, ValueError):
        return None


def expand_client_disk(disk_linux: str, *, target_mib: int = CLIENT_DISK_SIZE_MIB) -> None:
    """Grow the Kali root disk (qcow2) and filesystem before installing packages."""
    expand_qcow2_size(disk_linux, target_mib)

    guestfish = shutil.which("guestfish")
    if not guestfish:
        raise RuntimeError(
            "guestfish is required to expand the test clientk filesystem.\n"
            "Install it in WSL with:\n"
            "  sudo apt install -y libguestfs-tools"
        )

    print(f"Expanding test clientk filesystem on {CLIENT_ROOT_DEVICE}...")
    grow_cmd = [guestfish, "-a", disk_linux, "run", ":", "resize2fs", CLIENT_ROOT_DEVICE]
    result = subprocess.run(grow_cmd, capture_output=True, text=True, env=libguestfs_env())
    if result.returncode != 0:
        detail = ((result.stderr or "") + (result.stdout or "")).strip()
        raise RuntimeError(
            f"guestfish resize2fs failed on {CLIENT_ROOT_DEVICE} (exit {result.returncode}).\n{detail}"
        )
