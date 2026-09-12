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
  if ! grep -q 'console=ttyS0' /boot/grub/menu.lst; then
    sed -i 's|\(root=/dev/sda1\)|\1 console=tty0 console=ttyS0,115200n8|' /boot/grub/menu.lst || true
  fi
fi
# Upstart getty on ttyS0
mkdir -p /etc/event.d
if [ ! -f /etc/event.d/ttyS0 ]; then
  cat > /etc/event.d/ttyS0 <<'EOF'
start on runlevel 2
start on runlevel 3
stop on runlevel 0
stop on runlevel 1
stop on runlevel 4
stop on runlevel 5
stop on runlevel 6
respawn
exec /sbin/getty 115200 ttyS0
EOF
fi
"""


def _enable_serial_console(qcow_path: str) -> None:
    """Best-effort serial getty so tmux can attach. Not hardening."""
    vc = shutil.which("virt-customize")
    if not vc:
        print("[overdrive] virt-customize not found; skipping serial enable (GUI login still works).")
        return
    marker = Path(qcow_path).with_suffix(".serial-enabled")
    if marker.is_file():
        print("[overdrive] Serial console already enabled on target image.")
        return
    print(
        "[overdrive] Enabling ttyS0 getty on Metasploitable (serial attach only — "
        "image stays unhardened)..."
    )
    env = os.environ.copy()
    env.setdefault("LIBGUESTFS_BACKEND", "direct")
    result = subprocess.run(
        [vc, "-a", qcow_path, "--run-command", _ENABLE_SERIAL_COMMAND],
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        detail = ((result.stderr or "") + (result.stdout or "")).strip()[-1500:]
        print(
            "[!] Could not enable serial console inside Metasploitable image "
            f"(continuing; use GTK or fix later):\n{detail}"
        )
        return
    marker.write_text("ok\n", encoding="utf-8")
    print("[overdrive] Serial console enabled for target.")


def setup_target_vm(
    *,
    start_vm: bool = True,
    connect_serial: bool = True,
    start_type: str = "gui",
) -> None:
    ensure_kvm_accessible()
    qemu, _ = require_qemu_tools()
    paths = get_system_paths(VM_NAME, image_name=TARGET_QCOW_NAME)
    vm_base = str(paths["vm_base"])
    download_dir = str(paths["download_dir"])
    qcow_path = os.path.join(vm_base, TARGET_QCOW_NAME)

    def remove_previous_vm() -> None:
        remove_existing_lab_vm(VM_NAME, vm_base, tap=TAP_TARGET)

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
        BuildStep("cleanup.existing-vm", "remove previous target VM and disk", remove_previous_vm),
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
    )


if __name__ == "__main__":
    main()
