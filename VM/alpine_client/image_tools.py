"""Download Alpine images and grow the client VDI with libguestfs."""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib.request
from pathlib import Path

from detections.common.common_local import is_wsl_local
from detections.common.common_vm import (
    close_medium_best_effort,
    ensure_kvm_accessible,
    run_vboxmanage,
    vboxmanage_targets_windows,
    wait_after_disk_operation,
    wsl_to_windows_path,
)
from VM.alpine_client.client_config import CLIENT_ROOT_DEVICE, CLIENT_VDI_SIZE_MIB

__all__ = [
    "download_alpine_image",
    "expand_client_vdi_for_packages",
    "libguestfs_env",
    "require_vdi_prime_tools",
]


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


def download_alpine_image(url: str, dest_path: str) -> None:
    dest = Path(dest_path)
    if dest.exists():
        print(f"Alpine base image already exists at {dest}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading Alpine base image to {dest}...")
    with urllib.request.urlopen(url) as response:
        if response.status != 200:
            raise RuntimeError(f"Download failed with HTTP {response.status}")
        with open(dest, "wb") as out_file:
            shutil.copyfileobj(response, out_file)
    print("Download complete.")


def require_vdi_prime_tools(*, skip_prime: bool) -> str:
    if skip_prime:
        raise RuntimeError("VDI priming is required for client network and serial features.")
    vc = shutil.which("virt-customize")
    if not vc:
        raise RuntimeError(
            "virt-customize is required to prime the Alpine VDI.\n"
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
            print(f"[libguestfs] Using existing fixed appliance: LIBGUESTFS_PATH={fixed_dir}")
        else:
            cache_dir = Path.home() / ".cache" / "libguestfs" / "appliance"
            fixed_dir = _download_latest_fixed_appliance(cache_dir)
            virt_env["LIBGUESTFS_PATH"] = fixed_dir
            print(f"[libguestfs] Downloaded & using fixed appliance: LIBGUESTFS_PATH={fixed_dir}")

    return virt_env


def _vdi_virtual_size_bytes(vdi_linux: str) -> int | None:
    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        return None
    try:
        result = subprocess.run(
            [qemu_img, "info", "-U", "--output=json", vdi_linux],
            capture_output=True,
            text=True,
            check=True,
        )
        info = json.loads(result.stdout)
        size = info.get("virtual-size")
        return int(size) if size is not None else None
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError, TypeError, ValueError):
        return None


def expand_client_vdi_for_packages(vboxmanage: str, vdi_linux: str, *, target_mib: int = CLIENT_VDI_SIZE_MIB) -> None:
    """Grow the tiny whole-disk Alpine ext4 VDI before installing packages."""
    target_bytes = target_mib * 1024 * 1024
    current_bytes = _vdi_virtual_size_bytes(vdi_linux)
    if current_bytes is None:
        print(f"Could not determine VDI virtual size; requesting resize to {target_mib} MiB.")
    elif current_bytes >= target_bytes:
        print(f"Test client VDI virtual size is already at least {target_mib} MiB.")
    else:
        current_mib = current_bytes // (1024 * 1024)
        print(f"Growing test client VDI from {current_mib} MiB to {target_mib} MiB...")

    if current_bytes is None or current_bytes < target_bytes:
        vdi_for_vbox = wsl_to_windows_path(vdi_linux) if vboxmanage_targets_windows(vboxmanage) else vdi_linux
        run_vboxmanage(vboxmanage, ["modifymedium", "disk", vdi_for_vbox, "--resize", str(target_mib)])
        close_medium_best_effort(vboxmanage, vdi_linux)
        wait_after_disk_operation(vboxmanage, seconds=2.0)

    guestfish = shutil.which("guestfish")
    if not guestfish:
        raise RuntimeError(
            "guestfish is required to expand the test client filesystem.\n"
            "Install it in WSL with:\n"
            "  sudo apt install -y libguestfs-tools"
        )

    print(f"Expanding test client filesystem on {CLIENT_ROOT_DEVICE}...")
    subprocess.run(
        [guestfish, "-a", vdi_linux, "run", ":", "resize2fs", CLIENT_ROOT_DEVICE],
        check=True,
        env=libguestfs_env(),
    )
