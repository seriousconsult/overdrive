#!/usr/bin/env python3
r"""
Create the intentional Metasploitable 2 target VM on the lab LAN (``test-lan``).

This guest is **not hardened** — stock Metasploitable 2 vulnerabilities remain.
Default login: ``msfadmin`` / ``msfadmin``.

Networking:
  * NIC1 — tap ``tap-target`` on bridge ``test-lan`` (same LAN as Alpine/Kali).
  * Uses ``e1000`` (old Ubuntu 8.04 kernel lacks reliable virtio-net).

Serial: QEMU TCP ``127.0.0.1:2327``.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_qemu import (
    TAP_TARGET,
    build_client_qemu_argv,
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
from VM.metasploitable_target.image_tools import ensure_metasploitable_qcow2
from VM.metasploitable_target.serial_console import (
    configure_serial_endpoint,
    connect_serial_console,
    serial_console_instructions,
)
from VM.metasploitable_target.target_config import (
    CLIENT_MEMORY_MIB,
    CLIENT_VM_CPUS,
    METASPLOITABLE_LOGIN_HINT,
    METASPLOITABLE_URL,
    TARGET_QCOW_NAME,
    TARGET_SERIAL_TCP_PORT,
    VM_NAME,
)
from VM.pipeline_common import BuildStep, run_pipeline

CLIENT_PIPELINE_ORDER = (
    "cleanup.existing-vm",
    "workspace.prepare",
    "image.ensure-qcow2",
    "guest.enable-serial",
    "qemu.prepare",
    "qemu.start",
)

# Serial console only — does not harden, remove services, or change passwords.
_ENABLE_SERIAL_COMMAND = r"""
set -e
# GRUB legacy (Metasploitable 2 / Ubuntu 8.04)
if [ -f /boot/grub/menu.lst ]; then
  # The stock image uses root=/dev/mapper/metasploitable-root, not /dev/sda1.
  # Update the active kernel stanzas and the kopt template used by update-grub.
  sed -i '/^[[:space:]]*kernel[[:space:]]*\/vmlinuz/ { /console=ttyS0/! s/$/ console=tty0 console=ttyS0,115200n8/; }' /boot/grub/menu.lst
  sed -i '/^# kopt=/ { /console=ttyS0/! s/$/ console=tty0 console=ttyS0,115200n8/; }' /boot/grub/menu.lst
fi
# Upstart getty on ttyS0
mkdir -p /etc/event.d
cat > /etc/event.d/ttyS0 <<'EOF'
# Match the stock tty1 Upstart trigger in Ubuntu 8.04.
start on stopped rc2
start on stopped rc3
start on stopped rc4
start on stopped rc5
stop on runlevel 0
stop on runlevel 1
stop on runlevel 6
respawn
exec /sbin/getty 115200 ttyS0
EOF
"""


def _enable_serial_with_nbd(qcow_path: str) -> None:
    """Edit the stopped guest when libguestfs cannot boot on this host."""
    if not shutil.which("qemu-nbd") or not shutil.which("sudo"):
        raise RuntimeError("qemu-nbd and passwordless sudo are needed for serial setup")

    def run(*args: str) -> None:
        result = subprocess.run(
            ["sudo", "-n", *args], capture_output=True, text=True, check=False
        )
        if result.returncode:
            detail = ((result.stderr or "") + (result.stdout or "")).strip()
            raise RuntimeError(f"{' '.join(args)} failed: {detail}")

    run("modprobe", "nbd", "max_part=8")
    nbd = next(
        (
            f"/dev/nbd{i}"
            for i in range(16)
            if Path(f"/dev/nbd{i}").exists()
            and not Path(f"/sys/block/nbd{i}/pid").exists()
        ),
        None,
    )
    if nbd is None:
        raise RuntimeError("No free NBD device for target serial setup")

    with tempfile.TemporaryDirectory(prefix="overdrive-target-") as mount_dir:
        with ExitStack() as cleanup:
            run("qemu-nbd", "--connect", nbd, "--format=qcow2", qcow_path)
            cleanup.callback(run, "qemu-nbd", "--disconnect", nbd)
            run("vgchange", "-ay", "metasploitable")
            cleanup.callback(run, "vgchange", "-an", "metasploitable")
            run("mount", "/dev/metasploitable/root", mount_dir)
            cleanup.callback(run, "umount", mount_dir)
            run("mount", f"{nbd}p1", f"{mount_dir}/boot")
            cleanup.callback(run, "umount", f"{mount_dir}/boot")
            run("chroot", mount_dir, "/bin/sh", "-c", _ENABLE_SERIAL_COMMAND)


def _enable_serial_console(qcow_path: str) -> None:
    """Best-effort serial getty so tmux can attach. Not hardening."""
    vc = shutil.which("virt-customize")
    marker = Path(qcow_path).with_suffix(".serial-enabled")
    if marker.is_file():
        print("[overdrive] Serial console already enabled on target image.")
        return
    print(
        "[overdrive] Enabling ttyS0 getty on Metasploitable (serial attach only — "
        "image stays unhardened)..."
    )
    if vc:
        env = os.environ.copy()
        env.setdefault("LIBGUESTFS_BACKEND", "direct")
        result = subprocess.run(
            [vc, "-a", qcow_path, "--run-command", _ENABLE_SERIAL_COMMAND],
            capture_output=True,
            text=True,
            env=env,
        )
        if result.returncode != 0:
            print("[overdrive] virt-customize unavailable for this image; using NBD.")
            _enable_serial_with_nbd(qcow_path)
    else:
        _enable_serial_with_nbd(qcow_path)
    marker.write_text("ok\n", encoding="utf-8")
    print("[overdrive] Serial console enabled for target.")


def setup_target_vm(
    *,
    start_vm: bool = True,
    connect_serial: bool = True,
    start_type: str = "gui",
    rebuild_disk: bool = False,
) -> None:
    ensure_kvm_accessible()
    qemu, _ = require_qemu_tools()
    paths = get_system_paths(VM_NAME, image_name=TARGET_QCOW_NAME)
    vm_base = str(paths["vm_base"])
    download_dir = str(paths["downloads"])
    qcow_path = os.path.join(vm_base, TARGET_QCOW_NAME)
    preserved_disk_names = {
        TARGET_QCOW_NAME,
        f"{TARGET_QCOW_NAME}.verified",
        str(Path(TARGET_QCOW_NAME).with_suffix(".serial-enabled")),
    }

    def remove_previous_vm() -> None:
        preserve_names = None if rebuild_disk else preserved_disk_names
        remove_existing_lab_vm(VM_NAME, vm_base, tap=TAP_TARGET, preserve_names=preserve_names)

    def ensure_workspace() -> None:
        os.makedirs(vm_base, exist_ok=True)
        os.makedirs(download_dir, exist_ok=True)

    def ensure_image() -> None:
        print(
            "[overdrive] Preparing Metasploitable 2 disk (intentionally vulnerable; "
            "no hardening applied)..."
        )
        ensure_metasploitable_qcow2(
            download_dir=download_dir,
            qcow_path=qcow_path,
            url=METASPLOITABLE_URL,
        )

    def enable_serial() -> None:
        _enable_serial_console(qcow_path)

    def prepare_qemu_runtime() -> None:
        configure_serial_endpoint(str(TARGET_SERIAL_TCP_PORT))
        print(f"[overdrive] Target login: {METASPLOITABLE_LOGIN_HINT}")
        print(f"[overdrive] LAN: bridge test-lan via tap {TAP_TARGET!r}")

    def start_and_connect() -> None:
        if is_qemu_vm_running(VM_NAME, vm_base=vm_base):
            stop_qemu_vm(VM_NAME, vm_base=vm_base)
        print(f"Starting {VM_NAME} ({start_type})...")
        identity = fresh_lab_identity(VM_NAME)
        argv = build_client_qemu_argv(
            qemu=qemu,
            vm_name=VM_NAME,
            qcow_path=qcow_path,
            memory_mib=CLIENT_MEMORY_MIB,
            cpus=CLIENT_VM_CPUS,
            tap_name=TAP_TARGET,
            mac_colon=identity["nic1_colon"],
            hardware_uuid=identity["hardware_uuid"],
            serial_port=TARGET_SERIAL_TCP_PORT,
            start_type=start_type,
            pid_path=qemu_pid_path(vm_base),
            nic_model="e1000",
        )
        start_qemu_daemon(argv, log_path=qemu_log_path(vm_base))
        print(serial_console_instructions(str(TARGET_SERIAL_TCP_PORT)))
        if connect_serial:
            if sys.stdout.isatty() and not os.environ.get("OVERDRIVE_RUN_VMS_TMUX"):
                spawn_serial_console_window(
                    script_path=str(Path(__file__).resolve()),
                    title=f"{VM_NAME} serial {TARGET_SERIAL_TCP_PORT}",
                    extra_args=["--force-interactive-serial"],
                )
            else:
                print(
                    f"[overdrive] Serial available at 127.0.0.1:{TARGET_SERIAL_TCP_PORT} "
                    "(tmux pane or --serial-here)."
                )

    steps = [
        BuildStep(
            "cleanup.existing-vm",
            "remove previous target runtime",
            remove_previous_vm,
        ),
        BuildStep("workspace.prepare", "prepare workspace", ensure_workspace),
        BuildStep(
            "image.ensure-qcow2",
            "download/convert Metasploitable 2 image",
            ensure_image,
            description=(
                "Downloads metasploitable-linux-2.0.0.zip, extracts the VMDK, converts to qcow2. "
                "No guest hardening — stock vulnerable image."
            ),
        ),
        BuildStep(
            "guest.enable-serial",
            "enable ttyS0 getty for lab serial attach",
            enable_serial,
            description="Serial console only; does not harden or change Metasploitable services/passwords.",
        ),
        BuildStep("qemu.prepare", "configure QEMU network and serial", prepare_qemu_runtime),
        BuildStep(
            "qemu.start",
            "start target VM",
            start_and_connect,
            enabled=start_vm,
        ),
    ]
    actual = tuple(s.id for s in steps)
    if actual != CLIENT_PIPELINE_ORDER:
        raise RuntimeError(f"target pipeline order mismatch: {actual}")
    run_pipeline(steps, vm_label="target (Metasploitable 2)")


def serial_only_attach(*, here: bool, force_interactive: bool, serial_port: int) -> None:
    endpoint = str(serial_port)
    if here:
        connect_serial_console(endpoint, force_interactive=force_interactive)
        return
    spawn_serial_console_window(
        script_path=str(Path(__file__).resolve()),
        title=f"{VM_NAME} serial {endpoint}",
        extra_args=["--force-interactive-serial", "--serial-port", endpoint],
    )


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Create / start Metasploitable 2 target VM on the lab LAN (not hardened)."
    )
    ap.add_argument("--no-start", action="store_true", help="Prepare disk only; do not start QEMU.")
    ap.add_argument(
        "--rebuild-disk",
        action="store_true",
        help="Force rebuilding the target disk instead of reusing a verified qcow2.",
    )
    ap.add_argument("--serial-only", action="store_true", help="Attach serial for a running target.")
    ap.add_argument("--serial-here", action="store_true", help="Attach serial in this terminal.")
    ap.add_argument("--force-interactive-serial", action="store_true")
    ap.add_argument("--serial-port", type=int, default=TARGET_SERIAL_TCP_PORT)
    ap.add_argument(
        "--start-type",
        choices=("gui", "headless", "separate"),
        default="gui",
        help="QEMU display mode (gui=GTK, else headless).",
    )
    ns = ap.parse_args()
    if ns.serial_here or ns.serial_only:
        serial_only_attach(
            here=ns.serial_here,
            force_interactive=ns.force_interactive_serial or ns.serial_here,
            serial_port=ns.serial_port,
        )
        return
    setup_target_vm(
        start_vm=not ns.no_start,
        connect_serial=not ns.no_start,
        start_type=ns.start_type,
        rebuild_disk=ns.rebuild_disk,
    )


if __name__ == "__main__":
    main()
