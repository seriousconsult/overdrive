#!/usr/bin/env python3
r"""
Create a Kali Linux VM with QEMU/KVM for use **behind** the test router from
``create_VM_OpenWrt_router.py``.

Networking (lab):
  * **NIC1** — Linux bridge ``test-lan`` (tap + virtio-net) (same name as the router’s LAN leg).
    The guest gets DHCP from OpenWrt’s LAN; default gateway is the OpenWrt LAN IP.

This VM is **not** bridged to your Windows/WSL LAN (LAN-only on the lab bridge). To browse from the host
through OpenWrt, use a second setup—this script targets the standard “client on
router LAN” topology.

Serial console endpoint:
  The VM has COM1 wired to the guest's ``ttyS0`` login console at 115200 baud. This is useful when
  DHCP, graphics, SSH, or the browser environment is broken.

  Boot is unattended: Disk priming adds ``console=ttyS0,115200n8`` to grub and enables
  ``serial-getty@ttyS0``. After start, the script also sends a few CR nudges on the serial port.

  * QEMU exposes COM1 as TCP server ``127.0.0.1:2326``.
        ./create_VM_client_kali.py --serial-only

Username: root
Password: configured by KALI_CLIENT_ROOT_PASSWORD in VM/.env

Tracking identifiers (hostname, DHCP client identity, machine-id, egress
User-Agent) are scrubbed at disk prime / harden time. NIC MACs are regenerated
on every VM launch (stable OUI, unique NIC suffix). Rebuild the client after
changing scrub/harden settings.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = str(Path(SCRIPT_DIR).resolve().parents[1])
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from detections.common.common_qemu import (
    CLIENTK_QCOW_NAME,
    TAP_CLIENTK,
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
    spawn_serial_console_window,
)
from VM.kali_client.client_config import (
    CLIENT_QCOW_NAME,
    CLIENT_DISK_SIZE_MIB,
    CLIENT_MEMORY_MIB,
    CLIENT_VM_CPUS,
    KALI_IMAGE_NAME,
    KALI_SERIAL_TCP_PORT,
    KALI_TAR_NAME,
    KALI_URL,
    LAN_INTNET_NAME,
    VM_NAME,
)
from VM.kali_client.guest_prime import (
    ClientPrimeAssets,
    configure_client_guest_services_and_boot,
    copy_client_payloads_and_service_assets,
    harden_and_clean_client_guest_image,
    install_client_detection_libraries,
    prepare_client_prime_assets,
    prime_client_identity_and_base_packages,
)
from VM.kali_client.image_tools import (
    download_kali_image,
    ensure_kali_qcow2,
    expand_client_disk,
)
from VM.kali_client.pipeline import (
    BuildStep,
    KaliClientBuildOptions,
    run_kali_client_pipeline,
    validate_client_pipeline_order,
)
from VM.kali_client.serial_console import (
    configure_serial_endpoint,
    connect_serial_console,
    nudge_kali_boot_menu,
)

CLIENT_PIPELINE_ORDER = (
    "cleanup.existing-vm",
    "workspace.prepare",
    "image.download-base",
    "image.extract-qcow2",
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


def setup_client_vm(
    *,
    start_vm: bool = True,
    connect_serial: bool = True,
    skip_disk_prime: bool = False,
    start_type: str = "gui",
) -> None:
    options = KaliClientBuildOptions(
        start_vm=start_vm,
        connect_serial=connect_serial,
        skip_disk_prime=skip_disk_prime,
        start_type=start_type,
    )
    ensure_kvm_accessible()
    qemu, _qemu_img = require_qemu_tools()
    paths = get_system_paths(VM_NAME, KALI_TAR_NAME)

    vm_base = str(paths["vm_base"])
    vms_root = str(paths["vms_root"])
    download_dir = str(paths["downloads"])
    tar_path = str(paths["img_path"])
    qcow2_download = os.path.join(download_dir, KALI_IMAGE_NAME)
    disk_image_path = qcow2_download
    qcow_path = os.path.join(vm_base, CLIENT_QCOW_NAME)
    serial_endpoint = str(KALI_SERIAL_TCP_PORT)
    prime_assets: ClientPrimeAssets | None = None

    def require_prime_assets() -> ClientPrimeAssets:
        if prime_assets is None:
            raise RuntimeError("Kali guest prime assets were not prepared before image customization.")
        return prime_assets

    def remove_previous_vm() -> None:
        print(f"Fresh rebuild: removing existing {VM_NAME!r} disk and QEMU process first.")
        remove_existing_lab_vm(VM_NAME, vm_base, tap=TAP_CLIENTK)

    def ensure_workspace() -> None:
        os.makedirs(vm_base, exist_ok=True)
        os.makedirs(vms_root, exist_ok=True)
        os.makedirs(download_dir, exist_ok=True)

    def download_base_image() -> None:
        download_kali_image(KALI_URL, tar_path)

    def extract_base_qcow2() -> None:
        nonlocal disk_image_path
        disk_image_path = ensure_kali_qcow2(tar_path, qcow2_download)

    def convert_base_image() -> None:
        if os.path.exists(qcow_path):
            print(f"Removing stale test clientk qcow2 before conversion: {qcow_path}")
            os.remove(qcow_path)
        print("Converting Kali disk image into qcow2 format...")
        if disk_image_path.endswith(".qcow2") and os.path.abspath(disk_image_path) != os.path.abspath(qcow_path):
            convert_disk_to_qcow2(disk_image_path, qcow_path)
        elif disk_image_path.endswith(".qcow2"):
            shutil.copy2(disk_image_path, qcow_path)
        else:
            convert_disk_to_qcow2(disk_image_path, qcow_path)
        if not os.path.exists(qcow_path):
            raise RuntimeError(f"qcow2 conversion finished but target was not created: {qcow_path}")

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
        print(f"  LAN: bridge {LAN_INTNET_NAME!r} via tap {TAP_CLIENTK!r}")

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
            tap_name=TAP_CLIENTK,
            mac_colon=identity["nic1_colon"],
            hardware_uuid=identity["hardware_uuid"],
            serial_port=KALI_SERIAL_TCP_PORT,
            start_type=options.start_type,
            pid_path=qemu_pid_path(vm_base),
        )
        start_qemu_daemon(argv, log_path=qemu_log_path(vm_base))
        time.sleep(2)
        try:
            nudge_kali_boot_menu()
        except Exception as exc:
            print(f"[!] Boot nudge failed: {exc}")

        if options.connect_serial:
            time.sleep(1)
            extra_args = ["--force-interactive-serial", "--serial-port", str(KALI_SERIAL_TCP_PORT)]
            spawned = spawn_serial_console_window(
                Path(__file__).resolve(),
                title=f"Test clientk serial ({KALI_SERIAL_TCP_PORT})",
                extra_args=extra_args,
                cwd=Path(SCRIPT_DIR),
            )
            if not spawned:
                connect_serial_console(serial_endpoint, force_interactive=True)

    steps = [
        BuildStep("cleanup.existing-vm", "remove previous VM and disk", remove_previous_vm),
        BuildStep("workspace.prepare", "prepare workspace", ensure_workspace),
        BuildStep("image.download-base", "download Kali cloud image archive", download_base_image),
        BuildStep("image.extract-qcow2", "extract Kali disk image from archive", extract_base_qcow2),
        BuildStep("disk.convert-qcow2", "convert image to qcow2", convert_base_image),
        BuildStep("disk.expand", "expand clientk disk", expand_disk),
        BuildStep(
            "guest-assets.prepare",
            "prepare guest customization assets",
            prepare_guest_prime_assets,
        ),
        BuildStep(
            "guest.base-packages",
            "set guest identity and install base packages",
            install_guest_identity_and_base_packages,
            description="Image customization: hostname, root password, and bootstrap apt packages only.",
        ),
        BuildStep(
            "guest.payloads",
            "copy repo payloads and service assets",
            copy_guest_payloads_and_service_assets,
            description="Image customization: stages /root/detections, /root/local_host, systemd units, browser assets, and temporary /root/install.py.",
        ),
        BuildStep(
            "guest.detection-libs",
            "install Kali tools + detection libraries",
            install_guest_detection_libraries,
            description=(
                "Runs install.py inside the guest image: kali-linux-default "
                "(wireshark, metasploit, top10, …), Chromium, and Python deps. "
                "Usually 20-60 minutes; timeout 2 hours. The progress line may look idle "
                "while virt-customize runs."
            ),
        ),
        BuildStep(
            "guest.services-boot",
            "configure guest services and unattended boot",
            configure_guest_services_and_boot,
            description="Image customization: enables systemd units, grub serial console, and disables cloud-init/NetworkManager.",
        ),
        BuildStep(
            "guest.hardening",
            "apply final guest hardening and cleanup",
            harden_guest_image,
            description="Image customization: purges SSH/cloud-init artifacts and build-only files after dependencies are installed.",
        ),
        BuildStep(
            "qemu.prepare",
            "configure QEMU network and serial",
            prepare_qemu_runtime,
            description="QEMU phase begins only after the guest image is fully customized and hardened.",
        ),
        BuildStep(
            "qemu.start",
            "start VM and attach serial",
            start_and_connect,
            enabled=options.start_vm,
        ),
    ]

    validate_client_pipeline_order(steps, CLIENT_PIPELINE_ORDER)
    run_kali_client_pipeline(steps)



# Back-compat alias used by older imports and docs.
setup_clientk_vm = setup_client_vm


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Create / configure Kali Linux router-lab client VM.")
    ap.add_argument("--no-start", action="store_true", help="Configure the VM but do not start it.")
    ap.add_argument("--serial-only", action="store_true", help="Open serial console for already running test clientk.")
    ap.add_argument("--serial-here", action="store_true", help="Attach to serial directly in this console window.")
    ap.add_argument("--force-interactive-serial", action="store_true", help="Forces interactive socket bridge on startup.")
    ap.add_argument("--serial-port", type=int, default=KALI_SERIAL_TCP_PORT, help="TCP port for serial console.")
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
                title=f"Test clientk serial ({ns.serial_port})",
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
