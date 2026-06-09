#!/usr/bin/env python3
"""Offline guest ttyS0 serial setup and inspection for lab client VDIs (WSL-safe)."""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from detections.common.common_vm import (
    CLIENT_VDI_NAME,
    OPENWRT_CLIENT_VM_NAME,
    SERIAL_BAUD,
    SERIAL_TCP_HOST,
    SERIAL_TCP_PORT,
    get_vm_state,
    run_vboxmanage,
    serial_tcp_host_candidates,
    close_medium_best_effort,
    terminate_stale_vboxmanage_processes,
    vboxmanage_targets_windows,
    wait_after_disk_operation,
    wsl_to_windows_path,
)
from detections.common.common_vm import start_vm_headless_safe as _start_vm_headless_safe

GRUB_CONSOLE_SNIPPET = f"console=ttyS0,{SERIAL_BAUD}n8"
GETTY_WANTS = "/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service"
GETTY_TEMPLATE_PATHS = (
    "/usr/lib/systemd/system/serial-getty@.service",
    "/lib/systemd/system/serial-getty@.service",
)


@dataclass
class GuestSerialStatus:
    """Offline or inferred guest serial console readiness."""

    getty_symlink_ok: bool
    grub_default_ok: bool
    grub_cfg_ok: bool
    getty_detail: str
    grub_default_detail: str
    grub_cfg_detail: str

    @property
    def ready(self) -> bool:
        return self.getty_symlink_ok and (self.grub_default_ok or self.grub_cfg_ok)

    def summary(self) -> str:
        parts = [
            f"serial-getty@ttyS0: {'OK' if self.getty_symlink_ok else 'MISSING'} ({self.getty_detail})",
            f"/etc/default/grub: {'OK' if self.grub_default_ok else 'MISSING'} ({self.grub_default_detail})",
            f"/boot/grub/grub.cfg: {'OK' if self.grub_cfg_ok else 'MISSING'} ({self.grub_cfg_detail})",
        ]
        return "; ".join(parts)


def vdi_path_for_vbox(vdi_linux: str, vboxmanage: str) -> str:
    """Return a path VBoxManage accepts for the given Linux-side VDI."""
    if vboxmanage_targets_windows(vboxmanage):
        return wsl_to_windows_path(vdi_linux)
    return vdi_linux


def _temp_edit_dir(work_root: Path) -> Path:
    """Writable temp dir on Linux-native storage (not /mnt/c)."""
    tmp = Path(tempfile.gettempdir())
    if not str(tmp).startswith("/mnt/"):
        try:
            tmp.mkdir(parents=True, exist_ok=True)
            if os.access(tmp, os.W_OK):
                return tmp
        except OSError:
            pass
    return work_root


def _temp_part_image(work_root: Path, prefix: str) -> str:
    """Temp file for the extracted ext4 root partition (~2 GB on disk)."""
    temp_dir = _temp_edit_dir(work_root)
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".part", dir=str(temp_dir))
    os.close(fd)
    Path(path).unlink(missing_ok=True)
    return path


def _qemu_img_bin() -> str:
    path = shutil.which("qemu-img")
    if not path:
        raise RuntimeError(
            "qemu-img is required for offline VDI edit (sudo apt install qemu-utils)."
        )
    return path


def _vdi_qemu_format(vdi_linux: str) -> str:
    """Return the qemu-img format name for a VirtualBox client VDI."""
    result = _run([_qemu_img_bin(), "info", vdi_linux])
    text = (result.stdout or "") + (result.stderr or "")
    for line in text.splitlines():
        if line.startswith("file format:"):
            return line.split(":", 1)[1].strip()
    return "vmdk"


@dataclass
class _VdiEditImages:
    vdi_linux: str
    part_raw: str
    part_offset_bytes: int
    qemu_format: str


# OSBoxes Ubuntu 24.04 client VDI: ext4 root at 2 MiB, 2 GiB (fixed layout).
_OSBOXES_EXT4_START_SECTOR = 4096
_OSBOXES_EXT4_PART_SECTORS = 4194304


def _run(cmd: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _qemu_img_dd(
    *,
    src: str,
    src_fmt: str | None,
    dst: str,
    dst_fmt: str | None,
    skip_sectors: int,
    count_sectors: int,
    seek_sectors: int = 0,
) -> None:
    cmd = [_qemu_img_bin(), "dd"]
    if src_fmt:
        cmd.extend(["-f", src_fmt])
    cmd.extend(["-O", dst_fmt or "raw", "bs=512", f"skip={skip_sectors}", f"count={count_sectors}", f"if={src}", f"of={dst}"])
    if seek_sectors:
        cmd.append(f"seek={seek_sectors}")
    result = _run(cmd, timeout=600)
    if result.returncode != 0:
        detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        raise RuntimeError(f"qemu-img dd failed: {detail}")


def _open_vdi_for_edit(vdi_linux: str, vboxmanage: str, work_root: Path, prefix: str) -> _VdiEditImages:
    """Extract only the ~2 GB ext4 root partition from the client VDI (never the full virtual disk)."""
    _ = vboxmanage
    qemu_format = _vdi_qemu_format(vdi_linux)
    part_raw = _temp_part_image(work_root, prefix)
    print(
        "Extracting OSBoxes root partition only (~2 GB) from client VDI "
        "for offline ttyS0 setup..."
    )
    _qemu_img_dd(
        src=vdi_linux,
        src_fmt=qemu_format,
        dst=part_raw,
        dst_fmt="raw",
        skip_sectors=_OSBOXES_EXT4_START_SECTOR,
        count_sectors=_OSBOXES_EXT4_PART_SECTORS,
    )
    on_disk_mb = Path(part_raw).stat().st_size / (1024 * 1024)
    print(f"[+] Root partition copy ready ({on_disk_mb:.0f} MB).")
    return _VdiEditImages(
        vdi_linux=vdi_linux,
        part_raw=part_raw,
        part_offset_bytes=_OSBOXES_EXT4_START_SECTOR * 512,
        qemu_format=qemu_format,
    )


def _commit_vdi_edit(ctx: _VdiEditImages, vboxmanage: str, vdi_linux: str) -> None:
    _ = vboxmanage
    if vdi_linux != ctx.vdi_linux:
        raise ValueError("VDI path mismatch during serial priming write-back.")
    part_sectors = Path(ctx.part_raw).stat().st_size // 512
    print("Writing edited root partition back into client VDI...")
    _qemu_img_dd(
        src=ctx.part_raw,
        src_fmt="raw",
        dst=ctx.vdi_linux,
        dst_fmt=ctx.qemu_format,
        skip_sectors=0,
        count_sectors=part_sectors,
        seek_sectors=ctx.part_offset_bytes // 512,
    )
    print("[+] Client VDI updated.")


def _cleanup_vdi_edit(ctx: _VdiEditImages, vboxmanage: str) -> None:
    close_medium_best_effort(vboxmanage, ctx.part_raw)
    Path(ctx.part_raw).unlink(missing_ok=True)


def ensure_client_vm_running(vboxmanage: str) -> None:
    """Start the client VM headless when it is powered off."""
    if get_vm_state(vboxmanage, OPENWRT_CLIENT_VM_NAME) == "running":
        return
    print(f"[i] Starting {OPENWRT_CLIENT_VM_NAME} headless...")
    _start_vm_headless_safe(vboxmanage, OPENWRT_CLIENT_VM_NAME)
    refresh_live_serial_tcp(vboxmanage, OPENWRT_CLIENT_VM_NAME)


def vdi_fingerprint(vdi_linux: str) -> str:
    """Stable fingerprint for a VDI file (size + mtime)."""
    stat = Path(vdi_linux).stat()
    return f"{stat.st_size}:{stat.st_mtime_ns}"


def serial_prime_marker_path(work_root: Path, vdi_linux: str) -> Path:
    return work_root / f"{Path(vdi_linux).stem}.serial_ttyS0.ok"


def serial_priming_recorded(vdi_linux: str, work_root: Path) -> bool:
    """Return True when this VDI was already primed for ttyS0 and not modified since."""
    marker = serial_prime_marker_path(work_root, vdi_linux)
    if not marker.is_file():
        return False
    return marker.read_text(encoding="utf-8").strip() == vdi_fingerprint(vdi_linux)


def record_serial_priming(vdi_linux: str, work_root: Path) -> None:
    serial_prime_marker_path(work_root, vdi_linux).write_text(
        vdi_fingerprint(vdi_linux), encoding="utf-8"
    )


def _vdi_size_label(vdi_linux: str) -> str:
    size_gb = Path(vdi_linux).stat().st_size / (1024**3)
    return f"{size_gb:.1f} GB"


def _debugfs_cmd(disk_image_linux: str, offset: int, *extra: str) -> list[str]:
    debugfs = shutil.which("debugfs")
    if not debugfs:
        raise RuntimeError("debugfs is required (sudo apt install e2fsprogs).")
    cmd = [debugfs]
    if offset:
        cmd.extend(["-o", f"offset={offset}"])
    cmd.extend(extra)
    cmd.append(disk_image_linux)
    return cmd


def _debugfs_stat(disk_image_linux: str, offset: int, path: str) -> tuple[bool, str]:
    debugfs = shutil.which("debugfs")
    if not debugfs:
        return False, "debugfs not found"
    result = _run(_debugfs_cmd(disk_image_linux, offset, "-R", f"stat {path}"), timeout=30)
    text = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    if result.returncode != 0 or "No such file" in text:
        return False, text or f"missing {path}"
    return True, text


def _debugfs_cat(disk_image_linux: str, offset: int, path: str) -> tuple[bool, str]:
    debugfs = shutil.which("debugfs")
    if not debugfs:
        return False, "debugfs not found"
    result = _run(_debugfs_cmd(disk_image_linux, offset, "-R", f"cat {path}"), timeout=30)
    text = (result.stdout or "").strip()
    if result.returncode != 0 or "No such file" in text or "Filesystem not opened" in text:
        return False, text or (result.stderr or "").strip() or f"missing {path}"
    return True, text


def inspect_guest_serial_in_image(disk_image_linux: str, offset: int) -> GuestSerialStatus:
    """Read guest serial-getty and GRUB settings from an offline root filesystem."""
    getty_ok = False
    getty_detail = "not found"
    ok, text = _debugfs_stat(disk_image_linux, offset, GETTY_WANTS)
    if ok and "serial-getty" in text:
        getty_ok = True
        getty_detail = GETTY_WANTS
    else:
        for template in GETTY_TEMPLATE_PATHS:
            if _debugfs_cat(disk_image_linux, offset, template)[0]:
                getty_detail = f"template {template} exists but {GETTY_WANTS} missing"
                break

    grub_default_ok = False
    grub_default_detail = "missing"
    ok, grub_default = _debugfs_cat(disk_image_linux, offset, "/etc/default/grub")
    if ok:
        if GRUB_CONSOLE_SNIPPET in grub_default.replace(" ", ""):
            grub_default_ok = True
            grub_default_detail = "console=ttyS0 present"
        elif "ttyS0" in grub_default:
            grub_default_ok = True
            grub_default_detail = "ttyS0 referenced"
        else:
            grub_default_detail = "no console=ttyS0 in GRUB_CMDLINE_LINUX"

    grub_cfg_ok = False
    grub_cfg_detail = "missing"
    ok, grub_cfg = _debugfs_cat(disk_image_linux, offset, "/boot/grub/grub.cfg")
    if ok:
        if GRUB_CONSOLE_SNIPPET.replace(",", ", ") in grub_cfg or GRUB_CONSOLE_SNIPPET in grub_cfg:
            grub_cfg_ok = True
            grub_cfg_detail = "console=ttyS0 on linux lines"
        elif "ttyS0" in grub_cfg:
            grub_cfg_ok = True
            grub_cfg_detail = "ttyS0 referenced"
        else:
            grub_cfg_detail = "no console=ttyS0 in linux lines"

    return GuestSerialStatus(
        getty_symlink_ok=getty_ok,
        grub_default_ok=grub_default_ok,
        grub_cfg_ok=grub_cfg_ok,
        getty_detail=getty_detail,
        grub_default_detail=grub_default_detail,
        grub_cfg_detail=grub_cfg_detail,
    )


def _patch_grub_default(content: str) -> str:
    line_re = re.compile(r"^GRUB_CMDLINE_LINUX=(.*)$", re.MULTILINE)
    desired = f'GRUB_CMDLINE_LINUX="console=tty0 {GRUB_CONSOLE_SNIPPET}"'
    if line_re.search(content):
        return line_re.sub(desired, content, count=1)
    return content.rstrip() + "\n" + desired + "\n"


def _patch_grub_cfg(content: str) -> str:
    def add_console(match: re.Match[str]) -> str:
        line = match.group(0)
        if "ttyS0" in line:
            return line
        return line.rstrip() + f" {GRUB_CONSOLE_SNIPPET}"

    return re.sub(r"^\s*linux\s+/boot/.*$", add_console, content, flags=re.MULTILINE)


def apply_guest_serial_to_image(disk_image_linux: str, offset: int) -> GuestSerialStatus:
    """Enable serial-getty@ttyS0 and GRUB console=ttyS0 in an offline root filesystem."""
    debugfs = shutil.which("debugfs")
    if not debugfs:
        raise RuntimeError("debugfs is required (sudo apt install e2fsprogs).")

    template = next(
        (p for p in GETTY_TEMPLATE_PATHS if _debugfs_cat(disk_image_linux, offset, p)[0]),
        None,
    )
    if not template:
        raise RuntimeError("serial-getty@.service template not found in guest image.")

    script_lines = [
        "mkdir /etc/systemd/system/getty.target.wants",
        f"ln {template} {GETTY_WANTS}",
    ]
    with tempfile.TemporaryDirectory(prefix="guest_serial_") as tmpdir:
        tmp = Path(tmpdir)
        ok, grub_default = _debugfs_cat(disk_image_linux, offset, "/etc/default/grub")
        if ok:
            patched = _patch_grub_default(grub_default)
            grub_default_host = tmp / "grub_default"
            grub_default_host.write_text(patched, encoding="utf-8")
            script_lines.append(f"write {grub_default_host} /etc/default/grub")

        ok, grub_cfg = _debugfs_cat(disk_image_linux, offset, "/boot/grub/grub.cfg")
        if ok:
            patched_cfg = _patch_grub_cfg(grub_cfg)
            grub_cfg_host = tmp / "grub_cfg"
            grub_cfg_host.write_text(patched_cfg, encoding="utf-8")
            script_lines.append(f"write {grub_cfg_host} /boot/grub/grub.cfg")

        script = "\n".join(script_lines) + "\n"
        script_path = tmp / "apply.serial.debugfs"
        script_path.write_text(script, encoding="utf-8")
        cmd = _debugfs_cmd(disk_image_linux, offset, "-w", "-f", str(script_path))
        result = _run(cmd, timeout=120)
        if result.returncode != 0:
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            raise RuntimeError(f"debugfs serial setup failed: {detail}")

    return inspect_guest_serial_in_image(disk_image_linux, offset)


def inspect_guest_serial_in_vdi(
    vdi_linux: str,
    vboxmanage: str,
    work_root: Path,
    *,
    skip_if_marked: bool = True,
) -> GuestSerialStatus:
    """Extract the root partition temporarily and inspect guest serial configuration."""
    if skip_if_marked and serial_priming_recorded(vdi_linux, work_root):
        return GuestSerialStatus(
            getty_symlink_ok=True,
            grub_default_ok=True,
            grub_cfg_ok=True,
            getty_detail="marker file (previously primed)",
            grub_default_detail="marker file (previously primed)",
            grub_cfg_detail="marker file (previously primed)",
        )
    ctx = _open_vdi_for_edit(vdi_linux, vboxmanage, work_root, "guest_serial_inspect_")
    try:
        return inspect_guest_serial_in_image(ctx.part_raw, 0)
    finally:
        _cleanup_vdi_edit(ctx, vboxmanage)


def prime_guest_serial_via_vbox_raw(
    vdi_linux: str,
    vboxmanage: str,
    work_root: Path,
    *,
    force: bool = False,
) -> GuestSerialStatus:
    """
    Enable guest ttyS0 login without libguestfs (WSL-safe).

    Edits only the ~2 GB ext4 root partition via debugfs; never copies the full VDI.
    """
    if not force and serial_priming_recorded(vdi_linux, work_root):
        print(f"[+] Guest ttyS0 already primed for {vdi_linux} (skipping disk clone).")
        return GuestSerialStatus(
            getty_symlink_ok=True,
            grub_default_ok=True,
            grub_cfg_ok=True,
            getty_detail="marker file",
            grub_default_detail="marker file",
            grub_cfg_detail="marker file",
        )

    print(f"Priming guest ttyS0 in root partition (debugfs, no full-disk copy): {vdi_linux}")
    ctx = _open_vdi_for_edit(vdi_linux, vboxmanage, work_root, "guest_serial_prime_")
    try:
        status = inspect_guest_serial_in_image(ctx.part_raw, 0)
        if status.ready and not force:
            print(f"[+] Guest serial already configured in image: {status.summary()}")
            record_serial_priming(vdi_linux, work_root)
            return status
        status = apply_guest_serial_to_image(ctx.part_raw, 0)
        if not status.ready:
            raise RuntimeError(f"Serial priming incomplete after debugfs edit: {status.summary()}")
        print(f"[+] Guest serial offline priming OK: {status.summary()}")
        _commit_vdi_edit(ctx, vboxmanage, vdi_linux)
        record_serial_priming(vdi_linux, work_root)
        return status
    finally:
        _cleanup_vdi_edit(ctx, vboxmanage)
        terminate_stale_vboxmanage_processes()
        wait_after_disk_operation(vboxmanage, seconds=3)


def probe_tcp_serial_guest(
    host: str | None = None,
    port: int = SERIAL_TCP_PORT,
    *,
    connect_timeout_s: float = 3.0,
    guest_data_timeout_s: float = 5.0,
    send_wake: bool = True,
) -> tuple[bool, bool, str]:
    """
    Connect to VirtualBox TCP serial and detect guest output.

    Returns (tcp_connected, guest_sent_bytes, detail).
    """
    if host:
        hosts = [host]
    else:
        hosts = serial_tcp_host_candidates(SERIAL_TCP_HOST)
    last_error = ""
    for candidate in hosts:
        try:
            with socket.create_connection((candidate, port), timeout=connect_timeout_s) as sock:
                sock.settimeout(guest_data_timeout_s)
                if send_wake:
                    sock.sendall(b"\r\n")
                deadline = time.monotonic() + guest_data_timeout_s
                chunks: list[bytes] = []
                while time.monotonic() < deadline:
                    try:
                        data = sock.recv(4096)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    chunks.append(data)
                payload = b"".join(chunks)
                if payload:
                    preview = payload[:120].decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
                    return True, True, f"{candidate}:{port} guest sent {len(payload)} bytes (preview: {preview!r})"
                return (
                    True,
                    False,
                    f"{candidate}:{port} TCP OK but guest sent 0 bytes (ttyS0 login/GRUB console likely missing)",
                )
        except OSError as exc:
            last_error = str(exc)
    return False, False, last_error or "could not connect to serial TCP on any host candidate"


def refresh_live_serial_tcp(vboxmanage: str, vm_name: str = OPENWRT_CLIENT_VM_NAME) -> None:
    """Refresh COM1 TCP backend on a running VM."""
    run_vboxmanage(vboxmanage, ["controlvm", vm_name, "changeuartmode1", "disconnected"])
    run_vboxmanage(
        vboxmanage,
        ["controlvm", vm_name, "changeuartmode1", "tcpserver", str(SERIAL_TCP_PORT)],
    )


def power_off_vm(vboxmanage: str, vm_name: str, *, wait_s: int = 45) -> bool:
    """Power off a VM and wait until it stops."""
    state = get_vm_state(vboxmanage, vm_name)
    if state in (None, "poweroff", "aborted"):
        return True
    if state not in ("running", "paused", "stopping", "starting"):
        return True
    try:
        run_vboxmanage(vboxmanage, ["controlvm", vm_name, "poweroff"])
    except RuntimeError as exc:
        print(f"[i] poweroff request: {exc}")
    for _ in range(wait_s):
        time.sleep(1)
        st = get_vm_state(vboxmanage, vm_name)
        if st in (None, "poweroff", "aborted"):
            return True
    print(f"[!] {vm_name} did not reach poweroff within {wait_s}s (state={get_vm_state(vboxmanage, vm_name)!r}).")
    return False


def start_vm_headless(vboxmanage: str, vm_name: str) -> None:
    _start_vm_headless_safe(vboxmanage, vm_name)


def ensure_guest_serial_configured(
    vboxmanage: str,
    vdi_linux: str,
    work_root: Path,
    *,
    boot_wait_s: float = 12.0,
) -> bool:
    """
    Ensure guest ttyS0 emits serial output: offline-prime VDI if needed, then boot.

    Powers the client VM off briefly when the disk is not yet primed and live TCP is silent.
    """
    if not os.path.isfile(vdi_linux):
        print(f"[!] Client VDI not found for serial priming: {vdi_linux}")
        ensure_client_vm_running(vboxmanage)
        return False

    try:
        if serial_priming_recorded(vdi_linux, work_root):
            return True
        _, has_bytes, _ = probe_tcp_serial_guest(guest_data_timeout_s=3.0)
        if has_bytes:
            record_serial_priming(vdi_linux, work_root)
            return True

        print("[fix] No guest serial output; priming ttyS0 offline (client VM will power off briefly)...")
        terminate_stale_vboxmanage_processes()
        if not power_off_vm(vboxmanage, OPENWRT_CLIENT_VM_NAME):
            print("[!] Could not power off client VM; skipping offline VDI edit.")
            return False
        prime_guest_serial_via_vbox_raw(vdi_linux, vboxmanage, work_root, force=True)
        ensure_client_vm_running(vboxmanage)
        time.sleep(boot_wait_s)
        _, has_bytes, detail = probe_tcp_serial_guest(guest_data_timeout_s=10.0)
        if has_bytes:
            print(f"[+] Guest serial output after priming: {detail}")
            return True
        print(f"[!] Still no guest serial output after priming: {detail}")
        return False
    finally:
        if get_vm_state(vboxmanage, OPENWRT_CLIENT_VM_NAME) != "running":
            ensure_client_vm_running(vboxmanage)


def default_client_vdi_linux() -> str:
    home = Path.home()
    return str(home / "VirtualBox VMs" / OPENWRT_CLIENT_VM_NAME / CLIENT_VDI_NAME)
