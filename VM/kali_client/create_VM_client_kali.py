#!/usr/bin/env python3
r"""
Create a Kali Linux VM in VirtualBox for use **behind** the test router from
``create_VM_OpenWrt_router.py``.

Networking (lab):
  * **NIC1** — VirtualBox **internal network** ``test-lan`` (same name as the router’s LAN leg).
    The guest gets DHCP from OpenWrt’s LAN; default gateway is the OpenWrt LAN IP.

This VM is **not** bridged to your Windows/WSL LAN. To browse from the host
through OpenWrt, use a second setup—this script targets the standard “client on
router LAN” topology.

Serial console endpoint:
  The VM has COM1 wired to the guest's ``ttyS0`` login console at 115200 baud. This is useful when
  DHCP, graphics, SSH, or the browser environment is broken.

  Boot is unattended: VDI priming adds ``console=ttyS0,115200n8`` to grub and enables
  ``serial-getty@ttyS0``. After start, the script also sends a few CR nudges on the serial port.

  * Windows host / Windows VirtualBox:
      VirtualBox exposes COM1 as TCP server ``127.0.0.1:2326``.

  * WSL shell controlling Windows VirtualBox through ``VBoxManage.exe``:
        ./create_VM_client_kali.py --serial-only

Username: root
Password: configured by KALI_CLIENT_ROOT_PASSWORD in VM/.env

Tracking identifiers (hostname, DHCP client identity, machine-id, egress
User-Agent) are scrubbed at VDI prime / harden time. NIC MACs are regenerated
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

from detections.common.common_vm import (
    assign_fresh_lab_macs,
    close_medium_best_effort,
    find_vboxmanage,
    get_system_paths,
    remove_existing_vm,
    run_vboxmanage,
    serial_endpoint_for_vbox,
    spawn_serial_console_window,
    vm_is_registered,
    wait_after_disk_operation,
    wsl_to_windows_path,
)
from VM.kali_client.client_config import (
    CLIENT_VDI_NAME,
    CLIENT_VDI_SIZE_MIB,
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
    expand_client_vdi_for_packages,
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
    "disk.convert-vdi",
    "disk.expand",
    "guest-assets.prepare",
    "guest.base-packages",
    "guest.payloads",
    "guest.detection-libs",
    "guest.services-boot",
    "guest.hardening",
    "vbox.register",
    "vbox.hardware",
    "vbox.storage",
    "vbox.start",
)


def setup_client_vm(
    *,
    start_vm: bool = True,
    connect_serial: bool = True,
    skip_vdi_prime: bool = False,
    start_type: str = "gui",
) -> None:
    options = KaliClientBuildOptions(
        start_vm=start_vm,
        connect_serial=connect_serial,
        skip_vdi_prime=skip_vdi_prime,
        start_type=start_type,
    )
    paths = get_system_paths(VM_NAME, KALI_TAR_NAME)
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError("VBoxManage not found.")

    vm_base = paths["vm_base"]
    vms_root = paths["vms_root"]
    download_dir = paths["downloads"]
    tar_path = paths["img_path"]
    qcow2_path = os.path.join(download_dir, KALI_IMAGE_NAME)
    disk_image_path = qcow2_path
    vdi_wsl = os.path.join(vm_base, CLIENT_VDI_NAME)

    vdi_for_vbox = wsl_to_windows_path(vdi_wsl) if paths["is_wsl"] else vdi_wsl
    vms_root_for_vbox = wsl_to_windows_path(vms_root) if paths["is_wsl"] else vms_root

    serial_endpoint = serial_endpoint_for_vbox(vboxmanage, tcp_port=KALI_SERIAL_TCP_PORT)
    prime_assets: ClientPrimeAssets | None = None

    def require_prime_assets() -> ClientPrimeAssets:
        if prime_assets is None:
            raise RuntimeError("Kali guest prime assets were not prepared before image customization.")
        return prime_assets

    def remove_previous_vm() -> None:
        print(f"Fresh rebuild: removing existing {VM_NAME!r} registration and disk first.")
        remove_existing_vm(
            vboxmanage,
            VM_NAME,
            vm_base,
            medium_path_for_vbox=wsl_to_windows_path(vdi_wsl) if paths["is_wsl"] else vdi_wsl,
        )

    def ensure_workspace() -> None:
        os.makedirs(vm_base, exist_ok=True)
        os.makedirs(vms_root, exist_ok=True)
        os.makedirs(download_dir, exist_ok=True)

    def download_base_image() -> None:
        download_kali_image(KALI_URL, tar_path)

    def extract_base_qcow2() -> None:
        nonlocal disk_image_path
        disk_image_path = ensure_kali_qcow2(tar_path, qcow2_path)

    def remove_stale_client_vdi() -> None:
        close_medium_best_effort(vboxmanage, vdi_wsl)
        if os.path.exists(vdi_wsl):
            print(f"Removing stale test clientk VDI before conversion: {vdi_wsl}")
            try:
                os.remove(vdi_wsl)
            except OSError as exc:
                print(f"[!] Could not remove VDI ({exc}); attempting VBox closemedium --delete...")
                subprocess.run(
                    [vboxmanage, "closemedium", "disk", vdi_for_vbox, "--delete"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if os.path.exists(vdi_wsl):
                    raise RuntimeError(
                        "Could not remove stale test clientk VDI before conversion.\n"
                        f"Path: {vdi_wsl}\n"
                        f"Windows path: {vdi_for_vbox}\n"
                        f"Error: {exc}"
                    ) from exc

    def convert_base_image() -> None:
        remove_stale_client_vdi()
        disk_for_vbox = wsl_to_windows_path(disk_image_path) if paths["is_wsl"] else disk_image_path
        print("Converting Kali disk image into VDI format...")
        qemu_img = shutil.which("qemu-img")
        if qemu_img:
            try:
                subprocess.run(
                    [qemu_img, "convert", "-p", "-O", "vdi", disk_image_path, vdi_wsl],
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                raise RuntimeError(
                    "qemu-img could not convert the Kali base image to VDI.\n"
                    f"Source: {disk_image_path}\n"
                    f"Target: {vdi_wsl}"
                ) from exc
        else:
            try:
                run_vboxmanage(
                    vboxmanage,
                    ["clonemedium", "disk", disk_for_vbox, vdi_for_vbox, "--format", "VDI"],
                )
            except RuntimeError as exc:
                detail = str(exc)
                if "VERR_ACCESS_DENIED" in detail or "access denied" in detail.lower():
                    raise RuntimeError(
                        "VirtualBox could not create the test clientk VDI (access denied).\n"
                        f"Target: {vdi_wsl}\n"
                        f"Windows target: {vdi_for_vbox}\n"
                        "Close VirtualBox Manager, power off the client VM, remove/detach the stale "
                        "client_browser_kali.vdi from Media Manager, then rerun."
                    ) from exc
                raise
        if not os.path.exists(vdi_wsl):
            raise RuntimeError(f"VDI conversion finished but target was not created: {vdi_wsl}")
        close_medium_best_effort(vboxmanage, vdi_wsl)
        wait_after_disk_operation(vboxmanage, seconds=2.0)

    def expand_disk() -> None:
        expand_client_vdi_for_packages(vboxmanage, vdi_wsl, target_mib=CLIENT_VDI_SIZE_MIB)

    def prepare_guest_prime_assets() -> None:
        nonlocal prime_assets
        prime_assets = prepare_client_prime_assets(Path(download_dir))

    def install_guest_identity_and_base_packages() -> None:
        prime_client_identity_and_base_packages(
            vdi_wsl,
            require_prime_assets(),
            skip_prime=options.skip_vdi_prime,
        )

    def copy_guest_payloads_and_service_assets() -> None:
        copy_client_payloads_and_service_assets(
            vdi_wsl,
            require_prime_assets(),
            skip_prime=options.skip_vdi_prime,
        )

    def install_guest_detection_libraries() -> None:
        install_client_detection_libraries(
            vdi_wsl,
            require_prime_assets(),
            skip_prime=options.skip_vdi_prime,
        )

    def configure_guest_services_and_boot() -> None:
        configure_client_guest_services_and_boot(
            vdi_wsl,
            skip_prime=options.skip_vdi_prime,
        )

    def harden_guest_image() -> None:
        harden_and_clean_client_guest_image(
            vdi_wsl,
            require_prime_assets(),
            skip_prime=options.skip_vdi_prime,
        )

    def create_vm_registration() -> None:
        run_vboxmanage(
            vboxmanage,
            [
                "createvm",
                "--name",
                VM_NAME,
                "--ostype",
                "Other_64",
                "--basefolder",
                vms_root_for_vbox,
                "--register",
            ],
        )

    def configure_vm_hardware() -> None:
        run_vboxmanage(
            vboxmanage,
            [
                "modifyvm",
                VM_NAME,
                "--memory",
                str(CLIENT_MEMORY_MIB),
                "--ioapic",
                "on",
                "--cpus",
                str(CLIENT_VM_CPUS),
                "--nic1",
                "intnet",
                "--intnet1",
                LAN_INTNET_NAME,
            ],
        )
        configure_serial_endpoint(vboxmanage, serial_endpoint)

    def attach_storage() -> None:
        run_vboxmanage(
            vboxmanage,
            ["storagectl", VM_NAME, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci"],
        )
        run_vboxmanage(
            vboxmanage,
            [
                "storageattach",
                VM_NAME,
                "--storagectl",
                "SATA",
                "--port",
                "0",
                "--device",
                "0",
                "--type",
                "hdd",
                "--medium",
                vdi_for_vbox,
            ],
        )

    def start_and_connect() -> None:
        print(f"Starting {VM_NAME} ({options.start_type})...")
        assign_fresh_lab_macs(vboxmanage, VM_NAME)
        run_vboxmanage(vboxmanage, ["startvm", VM_NAME, "--type", options.start_type])

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
                connect_serial_console(vboxmanage, serial_endpoint, force_interactive=True)

    steps = [
        BuildStep("cleanup.existing-vm", "remove previous VM and disk", remove_previous_vm),
        BuildStep("workspace.prepare", "prepare workspace", ensure_workspace),
        BuildStep("image.download-base", "download Kali cloud image archive", download_base_image),
        BuildStep("image.extract-qcow2", "extract Kali disk image from archive", extract_base_qcow2),
        BuildStep("disk.convert-vdi", "convert image to VDI", convert_base_image),
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
            "run build-time install.py for detection/browser libraries",
            install_guest_detection_libraries,
            description="Image customization: runs /root/install.py, installs Chromium/tools/Python deps, then removes install.py before first boot.",
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
            "vbox.register",
            "create VirtualBox VM registration",
            create_vm_registration,
            description="VirtualBox phase begins only after the guest image is fully customized and hardened.",
        ),
        BuildStep("vbox.hardware", "configure VM hardware and serial", configure_vm_hardware),
        BuildStep("vbox.storage", "attach VDI storage", attach_storage),
        BuildStep(
            "vbox.start",
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
        help="VirtualBox frontend used when starting the VM. Default: gui.",
    )
    ns = ap.parse_args()

    if ns.serial_here or ns.serial_only:
        paths = get_system_paths(VM_NAME)
        vboxmanage = find_vboxmanage(paths)
        if not vboxmanage:
            raise RuntimeError("VBoxManage not found.")
        serial_endpoint = serial_endpoint_for_vbox(vboxmanage, tcp_port=ns.serial_port)
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
        connect_serial_console(vboxmanage, serial_endpoint, force_interactive=ns.force_interactive_serial or ns.serial_here)
        raise SystemExit(0)

    setup_client_vm(
        start_vm=not ns.no_start,
        connect_serial=not ns.no_start,
        start_type=ns.start_type,
    )
