"""QEMU/KVM lab helpers for Overdrive VMs (router + clients).

Script-managed ``qemu-system-x86_64`` with Linux bridge ``test-lan``,
per-VM taps, qcow2 disks under ``VM/lab_vms/``, and TCP serial endpoints.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from detections.common.common_local import is_wsl_local
from detections.common.common_vm import (
    CLIENTK_SERIAL_TCP_PORT,
    DEFAULT_VM_STORAGE_ROOT,
    ROUTER_SERIAL_TCP_PORT,
    SERIAL_TCP_HOST,
    TARGET_SERIAL_TCP_PORT,
    TEST_CLIENTA_VM_NAME,
    TEST_CLIENTK_VM_NAME,
    TEST_LAN_INTNET_NAME,
    TEST_ROUTER_VM_NAME,
    TEST_TARGET_VM_NAME,
    LEGACY_CLIENT_VM_NAME,
    ensure_kvm_accessible,
)

# Alpine / Test_Clienta serial (kept here to avoid a circular import with alpine client_config).
CLIENTA_SERIAL_TCP_PORT = 2325

__all__ = [
    "CLIENTA_QCOW_NAME",
    "CLIENTK_QCOW_NAME",
    "LAB_BRIDGE_NAME",
    "LAB_VMS_DIRNAME",
    "OPENWRT_QCOW_NAME",
    "TARGET_QCOW_NAME",
    "TAP_CLIENTA",
    "TAP_CLIENTK",
    "TAP_ROUTER_LAN",
    "TAP_TARGET",
    "build_client_qemu_argv",
    "build_router_qemu_argv",
    "convert_disk_to_qcow2",
    "ensure_lab_bridge",
    "ensure_tap_on_bridge",
    "expand_qcow2_size",
    "find_qemu_img",
    "find_qemu_system",
    "fresh_lab_identity",
    "is_qemu_vm_running",
    "lab_storage_paths",
    "lab_vms_root",
    "qemu_display_args",
    "qemu_log_path",
    "qemu_pid_path",
    "qemu_serial_tcp_args",
    "remove_existing_lab_vm",
    "remove_lab_vms_qemu",
    "require_qemu_tools",
    "start_qemu_daemon",
    "stop_qemu_vm",
    "tap_name_for_vm",
    "delete_tap",
    "default_serial_port_for_vm",
]

LAB_VMS_DIRNAME = "lab_vms"
LAB_BRIDGE_NAME = TEST_LAN_INTNET_NAME
# (intentionally no hard-coded prior hypervisor path names)


OPENWRT_QCOW_NAME = "openwrt.qcow2"
CLIENTA_QCOW_NAME = "client_browser_alpine.qcow2"
CLIENTK_QCOW_NAME = "client_browser_kali.qcow2"
TARGET_QCOW_NAME = "metasploitable2.qcow2"

TAP_ROUTER_LAN = "tap-router-lan"
TAP_CLIENTA = "tap-clienta"
TAP_CLIENTK = "tap-clientk"
TAP_TARGET = "tap-target"

_IP = "/usr/sbin/ip"
_IP_FALLBACK = "ip"


def lab_vms_root(storage_root: str | Path | None = None) -> str:
    root = Path(storage_root or os.environ.get("OVERDRIVE_VM_STORAGE_DIR", str(DEFAULT_VM_STORAGE_ROOT))).expanduser()
    return str(root / LAB_VMS_DIRNAME)


def lab_storage_paths(vm_name: str, image_name: str | None = None) -> dict[str, str | bool | None]:
    """Return downloads + lab_vms paths (QEMU layout)."""
    storage_root = Path(os.environ.get("OVERDRIVE_VM_STORAGE_DIR", str(DEFAULT_VM_STORAGE_ROOT))).expanduser()
    linux_home = str(storage_root)
    downloads = os.path.join(linux_home, "downloads")
    vms_root = lab_vms_root(storage_root)
    vm_base = os.path.join(vms_root, vm_name)
    paths: dict[str, str | bool | None] = {
        "is_wsl": is_wsl_local(),
        "linux_home": linux_home,
        "base_path": linux_home,
        "downloads": downloads,
        "vms_root": vms_root,
        "vm_base": vm_base,
    }
    if image_name:
        paths["img_path"] = os.path.join(downloads, image_name)
    return paths


def find_qemu_system() -> str | None:
    env = os.environ.get("QEMU_SYSTEM")
    if env and os.path.exists(env):
        return env
    return shutil.which("qemu-system-x86_64")


def find_qemu_img() -> str | None:
    env = os.environ.get("QEMU_IMG")
    if env and os.path.exists(env):
        return env
    return shutil.which("qemu-img")


def require_qemu_tools() -> tuple[str, str]:
    qemu = find_qemu_system()
    qemu_img = find_qemu_img()
    missing: list[str] = []
    if not qemu:
        missing.append("qemu-system-x86_64")
    if not qemu_img:
        missing.append("qemu-img")
    if missing:
        raise RuntimeError(
            "Missing QEMU tools: "
            + ", ".join(missing)
            + ".\nInstall on Debian/Ubuntu/WSL: sudo apt install -y qemu-system-x86 qemu-utils"
        )
    ensure_kvm_accessible()
    return qemu, qemu_img  # type: ignore[return-value]


def _ip_bin() -> str:
    if os.path.exists(_IP):
        return _IP
    found = shutil.which(_IP_FALLBACK)
    if not found:
        raise RuntimeError("ip (iproute2) not found; required for lab bridge/tap setup.")
    return found


def _run_ip(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run ``ip``; escalate with sudo when not root."""
    ip = _ip_bin()
    cmd = [ip, *args]
    if os.geteuid() != 0:
        if not shutil.which("sudo"):
            raise RuntimeError(f"Need root to run: {' '.join(cmd)}")
        cmd = ["sudo", "-n", *cmd]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Timed out running: {' '.join(cmd)}") from exc
    if check and proc.returncode != 0:
        # Retry with interactive sudo if non-interactive failed and we have a TTY.
        if os.geteuid() != 0 and sys.stdin.isatty() and cmd[0] == "sudo" and cmd[1] == "-n":
            cmd_i = ["sudo", ip, *args]
            proc = subprocess.run(cmd_i, capture_output=True, text=True, check=False, timeout=60)
            if proc.returncode == 0:
                return proc
        detail = ((proc.stderr or "") + (proc.stdout or "")).strip()
        raise RuntimeError(f"ip {' '.join(args)} failed (exit {proc.returncode}): {detail}")
    return proc


def _iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def ensure_lab_bridge(bridge: str = LAB_BRIDGE_NAME) -> None:
    """Create and bring up the lab LAN bridge if missing."""
    if not _iface_exists(bridge):
        print(f"[overdrive] Creating lab bridge {bridge!r}...")
        _run_ip(["link", "add", "name", bridge, "type", "bridge"])
    _run_ip(["link", "set", "dev", bridge, "up"])


def ensure_tap_on_bridge(tap_name: str, bridge: str = LAB_BRIDGE_NAME) -> None:
    """Create a tap device owned by the current user and enslave it to the lab bridge."""
    ensure_lab_bridge(bridge)
    if not _iface_exists(tap_name):
        user = os.environ.get("USER") or str(os.geteuid())
        print(f"[overdrive] Creating tap {tap_name!r} (user={user}) on bridge {bridge!r}...")
        _run_ip(["tuntap", "add", "dev", tap_name, "mode", "tap", "user", user])
    # Re-enslave / bring up every time (safe if already correct).
    _run_ip(["link", "set", "dev", tap_name, "master", bridge], check=False)
    # master may fail if already set; force up either way
    _run_ip(["link", "set", "dev", tap_name, "up"])
    if not _iface_exists(tap_name):
        raise RuntimeError(f"Tap {tap_name!r} was not created.")


def delete_tap(tap_name: str) -> None:
    if not _iface_exists(tap_name):
        return
    print(f"[overdrive] Removing tap {tap_name!r}...")
    _run_ip(["link", "delete", "dev", tap_name], check=False)


def tap_name_for_vm(vm_name: str) -> str | None:
    return {
        TEST_ROUTER_VM_NAME: TAP_ROUTER_LAN,
        TEST_CLIENTA_VM_NAME: TAP_CLIENTA,
        TEST_CLIENTK_VM_NAME: TAP_CLIENTK,
        TEST_TARGET_VM_NAME: TAP_TARGET,
        "Test_Client": TAP_CLIENTA,
    }.get(vm_name)


def qemu_pid_path(vm_base: str | Path) -> Path:
    return Path(vm_base) / "qemu.pid"


def qemu_log_path(vm_base: str | Path) -> Path:
    return Path(vm_base) / "qemu.log"


def is_qemu_vm_running(vm_name: str, *, vm_base: str | Path | None = None) -> bool:
    base = Path(vm_base) if vm_base else Path(lab_vms_root()) / vm_name
    pid_file = qemu_pid_path(base)
    if not pid_file.is_file():
        return _pgrep_qemu_name(vm_name) is not None
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return _pgrep_qemu_name(vm_name) is not None
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _pgrep_qemu_name(vm_name: str) -> int | None:
    try:
        proc = subprocess.run(
            ["pgrep", "-f", f"qemu-system-x86_64.*-name {vm_name}"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        return int(proc.stdout.strip().splitlines()[0])
    except ValueError:
        return None


def stop_qemu_vm(vm_name: str, *, vm_base: str | Path | None = None, timeout_s: float = 20.0) -> None:
    base = Path(vm_base) if vm_base else Path(lab_vms_root()) / vm_name
    pid_file = qemu_pid_path(base)
    pid: int | None = None
    if pid_file.is_file():
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            pid = None
    if pid is None:
        pid = _pgrep_qemu_name(vm_name)
    if pid is None:
        return
    print(f"Stopping QEMU VM {vm_name!r} (pid {pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        with contextlib_suppress():
            pid_file.unlink(missing_ok=True)
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.25)
    else:
        print(f"[!] QEMU {vm_name!r} did not exit; sending SIGKILL...")
        with contextlib_suppress():
            os.kill(pid, signal.SIGKILL)
    with contextlib_suppress():
        pid_file.unlink(missing_ok=True)


class contextlib_suppress:
    """Tiny local suppress for unlink/kill without importing contextlib in hot paths."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


def remove_existing_lab_vm(vm_name: str, vm_base: str, *, tap: str | None = None) -> None:
    """Stop QEMU, drop tap, and remove the VM directory."""
    if is_qemu_vm_running(vm_name, vm_base=vm_base) or qemu_pid_path(vm_base).is_file():
        stop_qemu_vm(vm_name, vm_base=vm_base)
    tap_to_drop = tap if tap is not None else tap_name_for_vm(vm_name)
    if tap_to_drop:
        delete_tap(tap_to_drop)
    if os.path.isdir(vm_base):
        print(f"Removing leftover VM directory {vm_base!r}...")
        shutil.rmtree(vm_base, ignore_errors=True)


def remove_lab_vms_qemu(*, dry_run: bool = False) -> None:
    """Stop and delete all known Overdrive lab QEMU VMs (and prior on-disk layouts)."""
    vms_root = lab_vms_root()
    storage_root = Path(os.environ.get("OVERDRIVE_VM_STORAGE_DIR", str(DEFAULT_VM_STORAGE_ROOT))).expanduser()

    specs: list[tuple[str, str | None]] = [
        (TEST_CLIENTA_VM_NAME, TAP_CLIENTA),
        ("Test_Client", TAP_CLIENTA),
        (TEST_CLIENTK_VM_NAME, TAP_CLIENTK),
        (TEST_TARGET_VM_NAME, TAP_TARGET),
        (LEGACY_CLIENT_VM_NAME, None),
        ("OpenWrt_LAN_Client_Alpine", None),
        ("OpenWrt_LAN_Client", None),
        (TEST_ROUTER_VM_NAME, TAP_ROUTER_LAN),
        ("OpenWrt_2026_Router", TAP_ROUTER_LAN),
    ]

    found_any = False
    for vm_name, tap in specs:
        vm_base = os.path.join(vms_root, vm_name)
        has_lab = os.path.isdir(vm_base) or is_qemu_vm_running(vm_name, vm_base=vm_base)
        if not has_lab:
            continue
        found_any = True
        if dry_run:
            print(f"  [dry-run] Would remove {vm_name!r} (lab_vms)")
            continue
        print(f"Removing lab VM {vm_name!r}...")
        remove_existing_lab_vm(vm_name, vm_base, tap=tap)

    # Drop any leftover prior hypervisor layout dirs (legacy disk/settings trees).
    keep_names = {
        "downloads",
        "lab_vms",
        "alpine_client",
        "kali_client",
        "metasploitable_target",
        "openwrt_router",
        ".cache",
        ".env",
    }
    if storage_root.is_dir():
        for child in storage_root.iterdir():
            if not child.is_dir() or child.name in keep_names:
                continue
            looks_prior = any(child.glob("**/*.vbox")) or any(child.glob("**/*.vdi"))  # noqa: historical suffixes
            if not looks_prior:
                continue
            found_any = True
            if dry_run:
                print(f"  [dry-run] Would remove leftover VM tree {child}")
                continue
            print(f"Removing leftover VM directory {child}...")
            shutil.rmtree(child, ignore_errors=True)

    if not found_any:
        print("[*] No existing lab VMs to remove.")
    elif not dry_run:
        print("[+] Old lab VMs removed.")


def qemu_display_args(start_type: str) -> list[str]:
    """Map lab ``--start-type`` to QEMU display flags."""
    if start_type in ("headless", "separate", "none"):
        return ["-display", "none"]
    # gui
    return ["-display", "gtk"]


def qemu_serial_tcp_args(port: int, host: str = SERIAL_TCP_HOST) -> list[str]:
    return ["-serial", f"tcp:{host}:{port},server,nowait"]


def fresh_lab_identity(vm_name: str) -> dict[str, str]:
    """Return hardware UUID + NIC MAC(s) as 12-hex and colon forms."""
    from VM.vm_config import (
        CLIENTK_NIC_OUI,
        CLIENT_NIC_OUI,
        G3100_MAC_OUI,
        TARGET_NIC_OUI,
        format_mac_colon,
        random_client_mac,
        random_clientk_mac,
        random_g3100_mac,
        random_lab_hardware_uuid,
        random_target_mac,
    )

    result: dict[str, str] = {"hardware_uuid": random_lab_hardware_uuid()}
    if vm_name in (TEST_CLIENTA_VM_NAME, "Test_Client"):
        mac = random_client_mac()
        result["nic1"] = mac
        result["nic1_colon"] = format_mac_colon(mac)
        oui = CLIENT_NIC_OUI.lower().replace(":", "")
        oui_colon = ":".join(oui[i : i + 2] for i in range(0, 6, 2))
        print(f"[overdrive] {vm_name} NIC MAC (OUI {oui_colon}): {result['nic1_colon']}")
        print(f"[overdrive] {vm_name} hardware UUID: {result['hardware_uuid']}")
        return result
    if vm_name == TEST_CLIENTK_VM_NAME:
        mac = random_clientk_mac()
        result["nic1"] = mac
        result["nic1_colon"] = format_mac_colon(mac)
        oui = CLIENTK_NIC_OUI.lower().replace(":", "")
        oui_colon = ":".join(oui[i : i + 2] for i in range(0, 6, 2))
        print(f"[overdrive] {vm_name} NIC MAC (OUI {oui_colon}): {result['nic1_colon']}")
        print(f"[overdrive] {vm_name} hardware UUID: {result['hardware_uuid']}")
        return result
    if vm_name == TEST_TARGET_VM_NAME:
        mac = random_target_mac()
        result["nic1"] = mac
        result["nic1_colon"] = format_mac_colon(mac)
        oui = TARGET_NIC_OUI.lower().replace(":", "")
        oui_colon = ":".join(oui[i : i + 2] for i in range(0, 6, 2))
        print(f"[overdrive] {vm_name} NIC MAC (OUI {oui_colon}): {result['nic1_colon']}")
        print(f"[overdrive] {vm_name} hardware UUID: {result['hardware_uuid']}")
        return result
    if vm_name == TEST_ROUTER_VM_NAME:
        lan = random_g3100_mac()
        wan = random_g3100_mac()
        while wan == lan:
            wan = random_g3100_mac()
        result["nic1"] = lan
        result["nic2"] = wan
        result["nic1_colon"] = format_mac_colon(lan)
        result["nic2_colon"] = format_mac_colon(wan)
        oui = G3100_MAC_OUI.lower().replace(":", "")
        oui_colon = ":".join(oui[i : i + 2] for i in range(0, 6, 2))
        print(
            f"[overdrive] {vm_name} G3100 MACs (OUI {oui_colon}): "
            f"LAN={result['nic1_colon']}  WAN={result['nic2_colon']}"
        )
        print(f"[overdrive] {vm_name} hardware UUID: {result['hardware_uuid']}")
        return result
    raise ValueError(f"Unknown lab VM for identity: {vm_name!r}")


def convert_disk_to_qcow2(src: str, dst: str) -> None:
    _, qemu_img = require_qemu_tools()
    if os.path.exists(dst):
        os.remove(dst)
    print(f"Converting {src} -> qcow2 {dst}...")
    subprocess.run([qemu_img, "convert", "-p", "-O", "qcow2", src, dst], check=True)
    if not os.path.exists(dst):
        raise RuntimeError(f"qcow2 conversion finished but target missing: {dst}")


def expand_qcow2_size(qcow_path: str, target_mib: int) -> None:
    """Grow qcow2 virtual size with qemu-img (filesystem expand is caller's job)."""
    _, qemu_img = require_qemu_tools()
    target_bytes = target_mib * 1024 * 1024
    info = subprocess.run(
        [qemu_img, "info", "-U", "--output=json", qcow_path],
        capture_output=True,
        text=True,
        check=True,
    )
    import json

    current = int(json.loads(info.stdout).get("virtual-size") or 0)
    if current >= target_bytes:
        print(f"Disk virtual size already >= {target_mib} MiB.")
        return
    print(f"Growing qcow2 from {current // (1024 * 1024)} MiB to {target_mib} MiB...")
    subprocess.run([qemu_img, "resize", qcow_path, str(target_bytes)], check=True)


def build_client_qemu_argv(
    *,
    qemu: str,
    vm_name: str,
    qcow_path: str,
    memory_mib: int,
    cpus: int,
    tap_name: str,
    mac_colon: str,
    hardware_uuid: str,
    serial_port: int,
    start_type: str,
    pid_path: Path,
    nic_model: str = "virtio-net-pci",
) -> list[str]:
    ensure_tap_on_bridge(tap_name)
    argv = [
        qemu,
        "-name",
        vm_name,
        "-enable-kvm",
        "-cpu",
        "host",
        "-m",
        str(memory_mib),
        "-smp",
        str(cpus),
        # IDE keeps /dev/sda naming used by Alpine/Kali cloud images and guestfish expand.
        "-drive",
        f"file={qcow_path},if=ide,format=qcow2,discard=unmap",
        "-netdev",
        f"tap,id=lan,ifname={tap_name},script=no,downscript=no",
        "-device",
        f"{nic_model},netdev=lan,mac={mac_colon}",
        "-smbios",
        f"type=1,uuid={hardware_uuid}",
        *qemu_serial_tcp_args(serial_port),
        *qemu_display_args(start_type),
        "-pidfile",
        str(pid_path),
        "-daemonize",
    ]
    return argv


def build_router_qemu_argv(
    *,
    qemu: str,
    vm_name: str,
    qcow_path: str,
    memory_mib: int,
    cpus: int,
    lan_tap: str,
    lan_mac_colon: str,
    wan_mac_colon: str,
    hardware_uuid: str,
    serial_port: int,
    start_type: str,
    pid_path: Path,
) -> list[str]:
    ensure_tap_on_bridge(lan_tap)
    argv = [
        qemu,
        "-name",
        vm_name,
        "-enable-kvm",
        "-cpu",
        "host",
        "-m",
        str(memory_mib),
        "-smp",
        str(cpus),
        # IDE keeps /dev/sda naming expected by the OpenWrt combined image.
        "-drive",
        f"file={qcow_path},if=ide,format=qcow2,discard=unmap",
        # eth0 = LAN (tap on test-lan)
        "-netdev",
        f"tap,id=lan,ifname={lan_tap},script=no,downscript=no",
        "-device",
        f"virtio-net-pci,netdev=lan,mac={lan_mac_colon}",
        # eth1 = WAN (SLIRP / user networking)
        "-netdev",
        "user,id=wan",
        "-device",
        f"virtio-net-pci,netdev=wan,mac={wan_mac_colon}",
        "-smbios",
        f"type=1,uuid={hardware_uuid}",
        *qemu_serial_tcp_args(serial_port),
        *qemu_display_args(start_type),
        "-pidfile",
        str(pid_path),
        "-daemonize",
    ]
    return argv


def start_qemu_daemon(argv: list[str], *, log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Executing: {' '.join(argv)}")
    with log_path.open("ab") as log_file:
        proc = subprocess.run(
            argv,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if proc.returncode != 0:
        tail = ""
        try:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
        except OSError:
            pass
        # If GTK display failed, retry headless once.
        if "-display" in argv and "gtk" in argv:
            print("[!] QEMU GUI display failed; retrying with -display none...")
            retry = list(argv)
            try:
                i = retry.index("-display")
                retry[i + 1] = "none"
            except (ValueError, IndexError):
                retry.extend(["-display", "none"])
            with log_path.open("ab") as log_file:
                log_file.write(b"\n--- retry headless ---\n")
                proc = subprocess.run(retry, stdout=log_file, stderr=subprocess.STDOUT, check=False)
            if proc.returncode == 0:
                return
            try:
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
            except OSError:
                pass
        raise RuntimeError(f"QEMU failed to start (exit {proc.returncode}).\n{tail}")


# Serial port helpers used by verify
def default_serial_port_for_vm(vm_name: str) -> int:
    if vm_name == TEST_ROUTER_VM_NAME:
        return ROUTER_SERIAL_TCP_PORT
    if vm_name == TEST_CLIENTK_VM_NAME:
        return CLIENTK_SERIAL_TCP_PORT
    if vm_name == TEST_TARGET_VM_NAME:
        return TARGET_SERIAL_TCP_PORT
    if vm_name in (TEST_CLIENTA_VM_NAME, "Test_Client"):
        return CLIENTA_SERIAL_TCP_PORT
    return CLIENTA_SERIAL_TCP_PORT
