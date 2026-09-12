#!/usr/bin/env python3
r"""
Create an Alpine Linux VM with QEMU/KVM for use **behind** the test router from
``create_VM_OpenWrt_router.py``.

Networking (lab):
  * **NIC1** — Linux bridge ``test-lan`` (tap + virtio-net; same name as the router’s LAN leg).
    The guest gets DHCP from OpenWrt’s LAN; default gateway is the OpenWrt LAN IP.

This VM is **not** bridged to your Windows/WSL LAN. To browse from the host
through OpenWrt, use a second setup—this script targets the standard “client on
router LAN” topology.

Serial console endpoint:
  The VM has COM1 wired to the guest's ``ttyS0`` login console at 115200 baud. This is useful when
  DHCP, graphics, SSH, or the browser environment is broken.

  Boot is unattended: Disk priming rewrites extlinux to ``DEFAULT <label>`` + ``TOTALTIMEOUT``
  (serial noise cancels plain ``TIMEOUT``, which otherwise waits forever for Enter).
  After start, the script also sends a few CR nudges on the serial port.
  QEMU exposes COM1 as TCP server ``127.0.0.1:2325``.
  To attach to an already-running VM:
    ./create_VM_client_browser_pipe_alpine.py --serial-only
  Disconnect with Ctrl-].


Username: root
Password: configured by ALPINE_CLIENT_ROOT_PASSWORD in VM/.env

Tracking identifiers (hostname, DHCP client identity, machine-id, egress
User-Agent) are scrubbed at disk prime / harden time. NIC MACs are regenerated
on every VM launch (stable OUI, unique NIC suffix). Rebuild the client after
changing scrub/harden settings. LAN silence is intentional and still looks
lab-like to discovery probes.

Detection Python libs (Scapy, httpx, zeroconf, …), WireGuard tools, and network
diagnostics (nmap, dig, tcpdump, Chromium, Xvfb) are NOT installed by the base
package script (bootstrap does install ``iptables`` so ``client-firewall`` can
harden without them). Priming copies ``install.py`` temporarily, runs it inside the guest
so deps land in ``/root/virtual_env`` (plus remaining OS packages via that
script's apk path), then deletes ``install.py`` from the guest image.
"""

from __future__ import annotations

import argparse
import contextlib
from dataclasses import dataclass
import glob
import json
import os
import platform
import re
import shutil
import select
import socket
import subprocess
import sys
import threading
import time
import tarfile
import urllib.request
from pathlib import Path

# Ensure the repo package path is importable when running this script directly.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = str(Path(SCRIPT_DIR).resolve().parents[1])
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from detections.common.common_local import is_wsl_local
from detections.common.common_qemu import (
    CLIENTA_QCOW_NAME,
    TAP_CLIENTA,
    build_client_qemu_argv,
    convert_disk_to_qcow2,
    fresh_lab_identity,
    is_qemu_vm_running,
    qemu_log_path,
    qemu_pid_path,
    remove_existing_lab_vm,
    require_qemu_tools,
    start_qemu_daemon,
    stop_qemu_vm,
)
from detections.common.common_vm import (
    ensure_kvm_accessible,
    get_system_paths,
    SERIAL_BAUD,
    SERIAL_TCP_HOST,
    serial_tcp_host_candidates,
    spawn_serial_console_window,
)
from VM.alpine_client.image_tools import expand_client_disk
from VM.alpine_client.serial_console import (
    configure_serial_endpoint,
    connect_serial_console,
    connect_tcp_serial_console,
    nudge_alpine_boot_menu,
)
from VM.alpine_client.alpine_client_hardening import (
    CLIENT_FIREWALL_INIT_ALPINE,
    CLIENT_FIREWALL_SCRIPT,
    CLIENT_HARDENING_SCRIPT,
)
from VM.alpine_client.client_config import (
    ALPINE_IMAGE_NAME,
    ALPINE_SERIAL_TCP_PORT,
    ALPINE_URL,
    CLIENT_GUEST_HOSTNAME,
    CLIENT_MEMORY_MIB,
    CLIENT_ROOT_DEVICE,
    CLIENT_QCOW_NAME,
    CLIENT_DISK_SIZE_MIB,
    CLIENT_VM_CPUS,
    LAN_INTNET_NAME,
    VM_NAME,
)
from VM.alpine_client.package_assets import client_package_install_script
from VM.alpine_client.pipeline import (
    AlpineClientBuildOptions,
    BuildStep,
    run_alpine_client_pipeline,
    validate_client_pipeline_order,
)
from VM.alpine_client.guest_prime import (
    ClientPrimeAssets,
    copy_client_payloads_and_service_assets,
    configure_client_guest_services_and_boot,
    harden_and_clean_client_guest_image,
    install_client_detection_libraries,
    prepare_client_prime_assets,
    prime_client_identity_and_base_packages,
)
from VM.vm_config import (
    OPENWRT_LAN_DNS,
    alpine_client_root_password,
)


CLIENT_PIPELINE_ORDER = (
    "cleanup.existing-vm",
    "workspace.prepare",
    "image.download-base",
    "disk.convert-qcow2",
    "disk.expand",
    "guest-assets.prepare",
    "guest.base-packages",
    "guest.payloads",
    "guest.detection-libs",
    "guest.services-boot",
    "guest.hardening",
    "qemu.prepare",
    "qemu.start",
)


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

    # Common cache locations
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
    """
    Download and extract the latest fixed appliance tarball into cache_dir.
    Then return the directory containing README.fixed + kernel/initrd/root.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)

    index_url = "https://download.libguestfs.org/binaries/appliance/"
    index_html = urllib.request.urlopen(index_url, timeout=60).read().decode("utf-8", errors="replace")

    # Find appliance-<ver>.tar.xz entries
    versions = re.findall(r"(appliance-\d+(?:\.\d+)+)\.tar\.xz", index_html)
    if not versions:
        raise RuntimeError("Could not parse libguestfs appliance versions from index.")

    # Choose latest by version tuple
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

    # Search extracted tree for README.fixed
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


def _libguestfs_env() -> dict[str, str]:
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



def setup_client_vm(
    *,
    start_vm: bool = True,
    connect_serial: bool = True,
    skip_disk_prime: bool = False,
    start_type: str = "gui",
) -> None:
    options = AlpineClientBuildOptions(
        start_vm=start_vm,
        connect_serial=connect_serial,
        skip_disk_prime=skip_disk_prime,
        start_type=start_type,
    )
    ensure_kvm_accessible()
    qemu, _qemu_img = require_qemu_tools()
    paths = get_system_paths(VM_NAME, ALPINE_IMAGE_NAME)

    vm_base = str(paths["vm_base"])
    vms_root = str(paths["vms_root"])
    download_dir = str(paths["downloads"])
    img_path = str(paths["img_path"])
    qcow_path = os.path.join(vm_base, CLIENT_QCOW_NAME)
    serial_endpoint = str(ALPINE_SERIAL_TCP_PORT)
    prime_assets: ClientPrimeAssets | None = None

    def require_prime_assets() -> ClientPrimeAssets:
        if prime_assets is None:
            raise RuntimeError("Alpine guest prime assets were not prepared before image customization.")
        return prime_assets

    def remove_previous_vm() -> None:
        print(f"Fresh rebuild: removing existing {VM_NAME!r} disk and QEMU process first.")
        remove_existing_lab_vm(VM_NAME, vm_base, tap=TAP_CLIENTA)
        for legacy_name in ("Test_Client", "OpenWrt_LAN_Client_Alpine", "OpenWrt_LAN_Client"):
            legacy_base = os.path.join(vms_root, legacy_name)
            if legacy_name == VM_NAME:
                continue
            if os.path.isdir(legacy_base) or is_qemu_vm_running(legacy_name, vm_base=legacy_base):
                print(f"Also removing legacy client VM {legacy_name!r}...")
                remove_existing_lab_vm(legacy_name, legacy_base, tap=None)

    def ensure_workspace() -> None:
        os.makedirs(vm_base, exist_ok=True)
        os.makedirs(vms_root, exist_ok=True)
        os.makedirs(download_dir, exist_ok=True)

    def download_base_image() -> None:
        from VM.alpine_client.image_tools import download_alpine_image
        download_alpine_image(ALPINE_URL, img_path)

    def convert_base_image() -> None:
        if os.path.exists(qcow_path):
            print(f"Removing stale test clienta qcow2 before conversion: {qcow_path}")
            os.remove(qcow_path)
        print("Converting Alpine base image into qcow2 format...")
        convert_disk_to_qcow2(img_path, qcow_path)

    def expand_disk() -> None:
        expand_client_disk(qcow_path, target_mib=CLIENT_DISK_SIZE_MIB)

    def prepare_guest_prime_assets() -> None:
        nonlocal prime_assets
        prime_assets = prepare_client_prime_assets(Path(download_dir))

    def install_guest_identity_and_base_packages() -> None:
        prime_client_identity_and_base_packages(
            qcow_path,
            require_prime_assets(),
            skip_prime=options.skip_disk_prime,
        )

    def copy_guest_payloads_and_service_assets() -> None:
        copy_client_payloads_and_service_assets(
            qcow_path,
            require_prime_assets(),
            skip_prime=options.skip_disk_prime,
        )

    def install_guest_detection_libraries() -> None:
        install_client_detection_libraries(
            qcow_path,
            require_prime_assets(),
            skip_prime=options.skip_disk_prime,
        )

    def configure_guest_services_and_boot() -> None:
        configure_client_guest_services_and_boot(
            qcow_path,
            skip_prime=options.skip_disk_prime,
        )

    def harden_guest_image() -> None:
        harden_and_clean_client_guest_image(
            qcow_path,
            require_prime_assets(),
            skip_prime=options.skip_disk_prime,
        )

    def prepare_qemu_runtime() -> None:
        configure_serial_endpoint(serial_endpoint)
        print(f"  LAN: bridge {LAN_INTNET_NAME!r} via tap {TAP_CLIENTA!r}")

    def start_and_connect() -> None:
        print(f"Starting {VM_NAME} ({options.start_type})...")
        if is_qemu_vm_running(VM_NAME, vm_base=vm_base):
            stop_qemu_vm(VM_NAME, vm_base=vm_base)
        identity = fresh_lab_identity(VM_NAME)
        argv = build_client_qemu_argv(
            qemu=qemu,
            vm_name=VM_NAME,
            qcow_path=qcow_path,
            memory_mib=CLIENT_MEMORY_MIB,
            cpus=CLIENT_VM_CPUS,
            tap_name=TAP_CLIENTA,
            mac_colon=identity["nic1_colon"],
            hardware_uuid=identity["hardware_uuid"],
            serial_port=ALPINE_SERIAL_TCP_PORT,
            start_type=options.start_type,
            pid_path=qemu_pid_path(vm_base),
        )
        start_qemu_daemon(argv, log_path=qemu_log_path(vm_base))
        time.sleep(2)
        try:
            nudge_alpine_boot_menu()
        except Exception as exc:
            print(f"[!] Boot nudge failed: {exc}")

        if options.connect_serial:
            time.sleep(1)
            extra_args = ["--force-interactive-serial", "--serial-port", str(ALPINE_SERIAL_TCP_PORT)]
            spawned = spawn_serial_console_window(
                Path(__file__).resolve(),
                title=f"Test clienta serial ({ALPINE_SERIAL_TCP_PORT})",
                extra_args=extra_args,
                cwd=Path(SCRIPT_DIR),
            )
            if not spawned:
                connect_serial_console(serial_endpoint, force_interactive=True)

    steps = [
        BuildStep("cleanup.existing-vm", "remove previous VM and disk", remove_previous_vm),
        BuildStep("workspace.prepare", "prepare workspace", ensure_workspace),
        BuildStep("image.download-base", "download Alpine base image", download_base_image),
        BuildStep("disk.convert-qcow2", "convert image to qcow2", convert_base_image),
        BuildStep("disk.expand", "expand client disk", expand_disk),
        BuildStep("guest-assets.prepare", "prepare guest customization assets", prepare_guest_prime_assets),
        BuildStep(
            "guest.base-packages",
            "set guest identity and install base packages",
            install_guest_identity_and_base_packages,
            description="Image customization: hostname, root password, and bootstrap apk packages only.",
        ),
        BuildStep(
            "guest.payloads",
            "copy repo payloads and service assets",
            copy_guest_payloads_and_service_assets,
            description="Image customization: stages /root/detections, /root/local_host, service scripts, browser assets, and temporary /root/install.py.",
        ),
        BuildStep(
            "guest.detection-libs",
            "install Alpine detection/browser packages",
            install_guest_detection_libraries,
            description=(
                "Runs install.py inside the guest image (Chromium, network tools, Python deps). "
                "Usually 5-15 minutes. The progress line may look idle while virt-customize runs."
            ),
        ),
        BuildStep(
            "guest.services-boot",
            "configure guest services and unattended boot",
            configure_guest_services_and_boot,
            description="Image customization: enables network/timezone services and serial unattended boot.",
        ),
        BuildStep(
            "guest.hardening",
            "apply final guest hardening and cleanup",
            harden_guest_image,
            description="Image customization: removes SSH/cloud-init artifacts and build-only files after dependencies are installed.",
        ),
        BuildStep(
            "qemu.prepare",
            "configure QEMU network and serial",
            prepare_qemu_runtime,
            description="QEMU phase begins only after the guest image is fully customized and hardened.",
        ),
        BuildStep("qemu.start", "start VM and attach serial", start_and_connect, enabled=options.start_vm),
    ]

    validate_client_pipeline_order(steps, CLIENT_PIPELINE_ORDER)
    run_alpine_client_pipeline(steps)



if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Create / configure Alpine Linux router-lab client VM.")
    ap.add_argument("--no-start", action="store_true", help="Configure the VM but do not start it.")
    ap.add_argument("--serial-only", action="store_true", help="Open serial console for already running test clienta.")
    ap.add_argument("--serial-here", action="store_true", help="Attach to serial directly in this console window.")
    ap.add_argument("--force-interactive-serial", action="store_true", help="Forces interactive socket bridge on startup.")
    ap.add_argument("--serial-port", type=int, default=ALPINE_SERIAL_TCP_PORT, help="TCP port for serial console.")
    ap.add_argument(
        "--start-type",
        choices=("gui", "headless", "separate"),
        default="gui",
        help="QEMU display mode when starting the VM (gui=GTK, else headless). Default: gui.",
    )
    ns = ap.parse_args()

    if ns.serial_here or ns.serial_only:
        serial_endpoint = str(ns.serial_port)
        if ns.serial_only and not ns.serial_here:
            extra_args = ["--force-interactive-serial"] if ns.force_interactive_serial else []
            extra_args.extend(["--serial-port", str(ns.serial_port)])
            spawned = spawn_serial_console_window(
                Path(__file__).resolve(),
                title=f"Test clienta serial ({ns.serial_port})",
                extra_args=extra_args,
                cwd=Path(SCRIPT_DIR),
            )
            if spawned:
                raise SystemExit(0)
        connect_serial_console(serial_endpoint, force_interactive=ns.force_interactive_serial or ns.serial_here)
        raise SystemExit(0)

    setup_client_vm(
        start_vm=not ns.no_start,
        connect_serial=not ns.no_start,
        start_type=ns.start_type,
    )
