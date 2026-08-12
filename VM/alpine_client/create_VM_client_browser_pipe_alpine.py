#!/usr/bin/env python3
r"""
Create an Alpine Linux VM in VirtualBox for use **behind** the OpenWrt router from
``create_VM_OpenWrt_router.py``.

Networking (lab):
  * **NIC1** — VirtualBox **internal network** ``openwrt-lan`` (same name as the router’s LAN leg).
    The guest gets DHCP from OpenWrt’s LAN; default gateway is the OpenWrt LAN IP.

This VM is **not** bridged to your Windows/WSL LAN. To browse from the host
through OpenWrt, use a second setup—this script targets the standard “client on
router LAN” topology.

Serial console endpoint:
  The VM has COM1 wired to the guest's ``ttyS0`` login console at 115200 baud. This is useful when
  DHCP, graphics, SSH, or the browser environment is broken.

  Boot is unattended: VDI priming rewrites extlinux to ``DEFAULT <label>`` + ``TOTALTIMEOUT``
  (VirtualBox serial noise cancels plain ``TIMEOUT``, which otherwise waits forever for Enter).
  After start, the script also sends a few CR nudges on the serial port.
  Which endpoint you connect to depends on the **host VirtualBox is actually running on**:

  * Windows host / Windows VirtualBox:
      VirtualBox exposes COM1 as TCP server ``127.0.0.1:2325``. The script starts the VM
      and attaches from WSL using a native Python socket terminal.

  * WSL shell controlling Windows VirtualBox through ``VBoxManage.exe``:
      This is still **Windows VirtualBox**, so this script uses TCP instead of Windows named pipes.
      To attach to an already-running VM:
        ./create_VM_client_browser_pipe_alpine.py --serial-only

      The built-in WSL bridge uses raw terminal input, maps Enter to serial carriage return, and
      disconnects with Ctrl-].

  * Native Linux host / Linux VirtualBox:
      VirtualBox exposes the Unix socket ``/tmp/OpenWrt_LAN_Client_serial.sock``. After the VM
      starts, run ``socat`` in one terminal to create a PTY, then attach ``screen`` in another:
        rm -f /tmp/OpenWrt_LAN_Client_serial.pty
        socat -d -d UNIX-CONNECT:/tmp/OpenWrt_LAN_Client_serial.sock PTY,link=/tmp/OpenWrt_LAN_Client_serial.pty,raw,echo=0
        screen /tmp/OpenWrt_LAN_Client_serial.pty 115200


Username: root
Password: configured by ALPINE_CLIENT_ROOT_PASSWORD in VM/.env

Tracking identifiers (hostname, custom NIC MAC, DHCP client identity, machine-id,
egress User-Agent) are scrubbed at VDI prime / VM configure time. Rebuild the
client after changing those settings. LAN silence is intentional and still looks
lab-like to discovery probes.

Detection Python libs (Scapy, Selenium, …) and network diagnostics (nmap, dig,
tcpdump, Chromium) are NOT installed by the base package script (bootstrap does
install ``iptables`` so ``client-firewall`` can harden without them). Priming
copies ``install.py`` and runs it inside the guest so deps land in
``/root/virtual_env`` (plus remaining OS packages via that script's apk path).
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
from detections.common.common_vm import (
    find_vboxmanage,
    get_vm_state,
    get_system_paths,
    OPENWRT_LAN_INTNET_NAME,
    close_medium_best_effort,
    remove_existing_vm,
    resolve_vbox_settings_path,
    run_vboxmanage,
    SERIAL_BAUD,
    SERIAL_PTY_LINK_PATH,
    SERIAL_TCP_HOST,
    serial_endpoint_for_vbox,
    serial_tcp_host_candidates,
    spawn_serial_console_window,
    vboxmanage_targets_windows,
    vm_is_registered,
    wait_after_disk_operation,
    wsl_to_windows_path,
)
from VM.alpine_client.alpine_client_hardening import (
    CLIENT_FIREWALL_INIT_ALPINE,
    CLIENT_FIREWALL_SCRIPT,
    CLIENT_HARDENING_SCRIPT,
)
from VM.alpine_client.package_assets import client_package_install_script
from VM.alpine_client.pipeline import (
    AlpineClientBuildOptions,
    BuildStep,
    run_alpine_client_pipeline,
)
from VM.vm_config import (
    CLIENT_NIC_OUI,
    OPENWRT_LAN_DNS,
    alpine_client_root_password,
    format_mac_colon,
    random_client_mac_vbox,
)

LAN_INTNET_NAME = OPENWRT_LAN_INTNET_NAME
VM_NAME = "OpenWrt_LAN_Client_Alpine"
CLIENT_VDI_NAME = "client_browser_alpine.vdi"
CLIENT_VM_CPUS = 1
CLIENT_GUEST_HOSTNAME = "client"
# Chromium + detection Python deps need more than the tiny cloud image default.
CLIENT_VDI_SIZE_MIB = 8192
CLIENT_MEMORY_MIB = 2048
CLIENT_ROOT_DEVICE = "/dev/sda"

ALPINE_SERIAL_TCP_PORT = 2325

ALPINE_URL = "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/nocloud_alpine-3.20.10-x86_64-bios-tiny-r0.qcow2"
ALPINE_IMAGE_NAME = "nocloud_alpine-3.20.10-x86_64-bios-tiny-r0.qcow2"


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


def _libguestfs_env() -> dict[str, str]:
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
        print(f"Alpine client VDI virtual size is already at least {target_mib} MiB.")
    else:
        current_mib = current_bytes // (1024 * 1024)
        print(f"Growing Alpine client VDI from {current_mib} MiB to {target_mib} MiB...")

    if current_bytes is None or current_bytes < target_bytes:
        vdi_for_vbox = wsl_to_windows_path(vdi_linux) if vboxmanage_targets_windows(vboxmanage) else vdi_linux
        run_vboxmanage(vboxmanage, ["modifymedium", "disk", vdi_for_vbox, "--resize", str(target_mib)])
        close_medium_best_effort(vboxmanage, vdi_linux)
        wait_after_disk_operation(vboxmanage, seconds=2.0)

    guestfish = shutil.which("guestfish")
    if not guestfish:
        raise RuntimeError(
            "guestfish is required to expand the Alpine client filesystem.\n"
            "Install it in WSL with:\n"
            "  sudo apt install -y libguestfs-tools"
        )

    print(f"Expanding Alpine client filesystem on {CLIENT_ROOT_DEVICE}...")
    subprocess.run(
        [guestfish, "-a", vdi_linux, "run", ":", "resize2fs", CLIENT_ROOT_DEVICE],
        check=True,
        env=_libguestfs_env(),
    )


LAB_INTERFACES_ALPINE = """auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
"""

LAB_NET_UP_INIT_ALPINE = """#!/sbin/openrc-run
description="OpenWrt lab LAN: link up + DHCP"

depend() {
    need localmount client-firewall
    after bootmisc
}

start() {
    ebegin "Starting lab-net-up"
    /usr/local/sbin/lab-net-up
    eend $?
}
"""

LAB_NET_UP_SCRIPT = f"""#!/bin/sh
# Bring up Ethernet NICs and request DHCP from OpenWrt when still unaddressed.
set -u
ok=0
for path in /sys/class/net/*; do
  IFACE=$(basename "$path")
  [ "$IFACE" = lo ] && continue
  [ ! -e "$path/device" ] && continue
  ip link set "$IFACE" up || true
  if ip -4 -o addr show dev "$IFACE" 2>/dev/null | grep -q ' inet '; then
    ok=1
    continue
  fi
  # Neutral DHCP identity: send generic hostname, empty vendor class (no alpine/overdrive).
  if udhcpc -i "$IFACE" -n -q -x hostname:{CLIENT_GUEST_HOSTNAME} -V ""; then
    ok=1
  fi
done
ip -4 route show default 2>/dev/null | grep -q . && exit 0
[ "$ok" -eq 1 ]
"""

LAB_NET_TROUBLESHOOT_SCRIPT = f"""#!/bin/sh
# Installed by create_VM_client_browser_pipe_alpine.py
set -u
echo "================================================================"
echo " Lab network troubleshoot (OpenWrt intnet client - Alpine)"
echo "================================================================"
echo ""
echo "=== IPv4 addresses ==="
ip -br -4 addr 2>/dev/null || true
echo ""
echo "=== Link state ==="
ip -br link 2>/dev/null || true
echo ""
echo "=== Routes ==="
ip route 2>/dev/null || true
echo ""
echo "=== Default IPv4 route ==="
if ip -4 route show default 2>/dev/null | grep -q .; then
  ip -4 route show default
else
  echo "(none) - no DHCP lease or no gateway from OpenWrt."
fi
echo ""
echo "=== Resolver (/etc/resolv.conf) ==="
if [ -r /etc/resolv.conf ]; then
  cat /etc/resolv.conf
else
  echo "(missing) - no DNS nameserver configured."
fi
echo ""
echo "=== DHCP on each Ethernet-like interface ==="
for IFACE in /sys/class/net/*; do
  IFACE=$(basename "$IFACE")
  [ "$IFACE" = lo ] && continue
  [ ! -e "/sys/class/net/$IFACE/device" ] && continue
  echo "--- link up + udhcpc $IFACE ---"
  if [ "$(id -u)" -eq 0 ]; then
    ip link set "$IFACE" up 2>&1 || true
    udhcpc -i "$IFACE" -n -q -x hostname:{CLIENT_GUEST_HOSTNAME} -V "" 2>&1 || true
  else
    sudo ip link set "$IFACE" up 2>&1 || true
    sudo udhcpc -i "$IFACE" -n -q -x hostname:{CLIENT_GUEST_HOSTNAME} -V "" 2>&1 || true
  fi
done
echo ""
echo "=== After DHCP ==="
ip -br -4 addr 2>/dev/null || true
ip -4 route show default 2>/dev/null || true
echo ""
echo "=== L3 vs DNS ==="
echo "--- ping gateway ---"
ping -c2 -W2 {OPENWRT_LAN_DNS} 2>&1 || true
echo "--- ping 8.8.8.8 ---"
ping -c2 -W3 8.8.8.8 2>&1 || true
echo "--- ping google.com ---"
ping -c2 -W3 google.com 2>&1 || true
echo ""
if command -v dig >/dev/null 2>&1; then
  echo "=== dig via OpenWrt ({OPENWRT_LAN_DNS}) ==="
  dig +time=2 +tries=1 +short @{OPENWRT_LAN_DNS} google.com 2>&1 || true
  echo ""
fi
"""

CLIENT_IP_TIMEZONE_SCRIPT = r"""#!/bin/sh
# Set the Alpine client's timezone to the timezone reported for its current egress IP.
#
# This intentionally changes only the local timezone presentation
# (/etc/localtime + /etc/timezone). The system clock remains UTC internally.
set -u

LOG=/var/log/overdrive-ip-timezone.log
TZDIR=/usr/share/zoneinfo

log() {
  echo "[overdrive-tz] $*"
  echo "[overdrive-tz] $*" >> "$LOG"
}

valid_tz() {
  tz="$1"
  [ -n "$tz" ] || return 1
  case "$tz" in
    /*|*..*|*//*|*\\*|UTC|Etc/UTC|Etc/GMT*) return 1 ;;
  esac
  [ -f "$TZDIR/$tz" ]
}

fetch_timezone() {
  python3 <<'PY'
import json
import urllib.error
import urllib.request

URLS = (
    "http://ip-api.com/json/?fields=status,message,timezone,query",
    "https://ipapi.co/json/",
)

for url in URLS:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "curl/8.5.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError):
        continue
    if not isinstance(data, dict):
        continue
    if data.get("status") == "fail":
        continue
    tz = str(data.get("timezone") or "").strip()
    if "/" in tz:
        print(tz)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

sync_timezone() {
  : > "$LOG"
  if [ ! -d "$TZDIR" ]; then
    log "tzdata zoneinfo directory missing: $TZDIR"
    return 1
  fi

  attempts="${1:-18}"
  i=1
  while [ "$i" -le "$attempts" ]; do
    tz="$(fetch_timezone 2>>"$LOG" || true)"
    if valid_tz "$tz"; then
      cp "$TZDIR/$tz" /etc/localtime
      echo "$tz" > /etc/timezone
      log "timezone set to $tz from current egress IP"
      date >> "$LOG" 2>&1 || true
      return 0
    fi
    [ -n "$tz" ] && log "rejected timezone value: $tz"
    sleep 5
    i=$((i + 1))
  done

  log "could not determine a valid IP timezone after $attempts attempts"
  return 1
}

case "${1:-sync}" in
  sync) sync_timezone "${2:-18}" ;;
  once) sync_timezone 1 ;;
  *) echo "usage: $0 {sync|once} [attempts]" >&2; exit 2 ;;
esac
"""

CLIENT_IP_TIMEZONE_INIT_ALPINE = """#!/sbin/openrc-run
description="Set client timezone from current egress IP"

depend() {
    need net
    after lab-net-up networking
}

start() {
    ebegin "Syncing timezone to egress IP"
    /usr/local/sbin/overdrive-ip-timezone sync 18
    eend $?
}
"""


def serial_console_instructions(vboxmanage: str, endpoint: str) -> str:
    if vboxmanage_targets_windows(vboxmanage):
        hosts = ", ".join(serial_tcp_host_candidates(SERIAL_TCP_HOST))
        return (
            "--- Serial console TCP endpoint ---\n"
            f"VirtualBox exposes COM1 as TCP port {endpoint} on the Windows host.\n"
            f"From WSL, connect to one of: {hosts}\n"
            "To attach to an already-running VM from WSL:\n"
            f"  ./{Path(__file__).name} --serial-only\n"
        )
    return (
        "--- Serial console host socket ---\n"
        f"VirtualBox exposes COM1 as: {endpoint}\n"
        "Attach with socat plus screen:\n"
        f"  rm -f {SERIAL_PTY_LINK_PATH}\n"
        f"  socat -d -d UNIX-CONNECT:{endpoint} PTY,link={SERIAL_PTY_LINK_PATH},raw,echo=0\n"
        f"  screen {SERIAL_PTY_LINK_PATH} {SERIAL_BAUD}\n"
    )


def configure_serial_endpoint(vboxmanage: str, endpoint: str) -> None:
    if vboxmanage_targets_windows(vboxmanage):
        uart_mode = "tcpserver"
        print(f"Serial console: COM1 -> TCP {SERIAL_TCP_HOST}:{endpoint} ({SERIAL_BAUD} baud).")
    else:
        uart_mode = "server"
        print(f"Serial console: COM1 -> host socket {endpoint} ({SERIAL_BAUD} baud).")
    run_vboxmanage(vboxmanage, ["modifyvm", VM_NAME, "--uart1", "0x3F8", "4", "--uartmode1", uart_mode, endpoint])


@contextlib.contextmanager
def _raw_stdin_for_serial(input_fd: int | None = None):
    if platform.system().lower() != "linux":
        yield
        return
    fd = input_fd
    if fd is None:
        if not sys.stdin.isatty():
            yield
            return
        fd = sys.stdin.fileno()
    try:
        import termios
        import tty
    except ImportError:
        yield
        return
    old_attrs = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)


@contextlib.contextmanager
def _serial_input_fd():
    tty_fd: int | None = None
    try:
        tty_fd = os.open("/dev/tty", os.O_RDONLY)
    except OSError:
        pass
    if tty_fd is not None:
        try:
            yield tty_fd
        finally:
            os.close(tty_fd)
        return
    if sys.stdin.isatty():
        yield sys.stdin.fileno()
        return
    yield None


def _write_serial_output(data: bytes) -> None:
    try:
        os.write(sys.stdout.fileno(), data)
    except OSError:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def _probe_serial_guest_output(sock: socket.socket, *, wait_s: float = 6.0) -> bytes:
    print(f"[serial check] TCP socket connected. Waiting up to {wait_s:.0f}s for guest serial output...")
    sample = bytearray()
    sock.setblocking(False)
    deadline = time.monotonic() + wait_s
    next_enter_at = 0.0
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_enter_at:
            try:
                sock.sendall(b"\r")
            except OSError:
                return bytes(sample)
            next_enter_at = now + 4.0
        readable, _, _ = select.select([sock], [], [], 0.25)
        if sock not in readable:
            continue
        try:
            data = sock.recv(4096)
        except BlockingIOError:
            continue
        if not data:
            break
        sample.extend(data)
        _write_serial_output(data)
        if b"login:" in sample.lower():
            break
    return bytes(sample)


def _connect_tcp_serial_windows(sock: socket.socket) -> None:
    try:
        import msvcrt
    except ImportError:
        raise RuntimeError("Windows serial bridge requires the msvcrt module.")
    stop = threading.Event()
    sock.settimeout(0.25)

    def recv_loop() -> None:
        while not stop.is_set():
            try:
                data = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            _write_serial_output(data)
        stop.set()

    reader = threading.Thread(target=recv_loop, daemon=True)
    reader.start()
    print("[serial interactive] Type normally. Press Ctrl+] to detach.")
    while not stop.is_set():
        if not msvcrt.kbhit():
            time.sleep(0.03)
            continue
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            if msvcrt.kbhit():
                msvcrt.getwch()
            continue
        if ch == "\x1d":
            print("\n[serial detached]")
            stop.set()
            return
        sock.sendall(b"\r" if ch in ("\r", "\n") else ch.encode("utf-8", errors="ignore"))


def _connect_tcp_serial_posix(sock: socket.socket) -> None:
    sock.setblocking(False)
    with _serial_input_fd() as input_fd:
        with _raw_stdin_for_serial(input_fd):
            watch_fds = [sock]
            if input_fd is not None:
                watch_fds.append(input_fd)
            print("[serial interactive] Type normally. Press Ctrl+] to detach.")
            while True:
                readable, _, _ = select.select(watch_fds, [], [])
                if sock in readable:
                    try:
                        data = sock.recv(4096)
                    except BlockingIOError:
                        data = b""
                    if not data:
                        return
                    _write_serial_output(data)
                if input_fd is not None and input_fd in readable:
                    try:
                        data = os.read(input_fd, 1024)
                    except BlockingIOError:
                        data = b""
                    if not data:
                        continue
                    if b"\x1d" in data:
                        return
                    sock.sendall(data.replace(b"\n", b"\r"))


def _open_tcp_serial_socket(host: str, port: int, *, timeout_s: float) -> socket.socket:
    host_candidates = serial_tcp_host_candidates(host)
    deadline = time.monotonic() + timeout_s
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        for candidate in host_candidates:
            try:
                return socket.create_connection((candidate, port), timeout=1.0)
            except OSError as exc:
                last_error = exc
        time.sleep(0.25)
    raise RuntimeError(f"Could not connect to serial TCP endpoint: {last_error}")


@contextlib.contextmanager
def _serial_attach_lock(port: int):
    """Prevent Overdrive helpers from competing for one VirtualBox TCP serial endpoint."""
    if os.name == "nt":
        yield
        return

    import fcntl

    lock_path = Path("/tmp") / f"overdrive-serial-{port}.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                f"Serial TCP :{port} is already attached by another Overdrive process. "
                "Close that serial pane/window first; not resetting VirtualBox COM1."
            ) from exc
        os.ftruncate(fd, 0)
        os.write(fd, f"pid={os.getpid()}\n".encode("ascii"))
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def connect_tcp_serial_console(host: str, port: int, *, timeout_s: float = 20.0, force_interactive: bool = False) -> bool:
    with _serial_attach_lock(port):
        with _open_tcp_serial_socket(host, port, timeout_s=timeout_s) as sock:
            sample = _probe_serial_guest_output(sock)
            if not sample and not force_interactive:
                return False
            if os.name == "nt":
                _connect_tcp_serial_windows(sock)
            else:
                _connect_tcp_serial_posix(sock)
    return True


def connect_serial_console(vboxmanage: str, endpoint: str, *, force_interactive: bool = False) -> bool:
    if vboxmanage_targets_windows(vboxmanage):
        return connect_tcp_serial_console(SERIAL_TCP_HOST, int(endpoint), force_interactive=force_interactive)
    print(f"Native Linux socket serial connection mode is ready. Connect using host-side socket helper.")
    return True


CLIENT_IDENTITY_COMMAND = (
    "mkdir -p /usr/local/sbin /root && "
    f"echo '{CLIENT_GUEST_HOSTNAME}' > /etc/hostname"
)

INSTALL_DETECTION_LIBRARIES_COMMAND = "cd /root && python3 /root/install.py --non-interactive"

REMOTE_BOOT_SERVICE_CLEANUP_COMMAND = (
    "for svc in sshd ssh dropbear tiny-cloud-boot tiny-cloud-early tiny-cloud-main "
    "tiny-cloud-final cloud-init cloud-final; do "
    "rm -f \"/etc/init.d/$svc\" \"/etc/conf.d/$svc\" 2>/dev/null || true; "
    "for level in default boot sysinit shutdown nonetwork; do "
    "rc-update del \"$svc\" \"$level\" >/dev/null 2>&1 || true; "
    "rm -f \"/etc/runlevels/$level/$svc\" 2>/dev/null || true; "
    "done; "
    "done && "
    "rm -f /etc/tiny-cloud.conf 2>/dev/null || true"
)

CONFIGURE_CLIENT_SERVICES_AND_BOOT_COMMAND = (
    "mv /usr/local/sbin/lab_net_troubleshoot.sh /usr/local/sbin/lab-net-troubleshoot && "
    "mv /etc/init.d/lab-net-up.init /etc/init.d/lab-net-up && "
    "mv /etc/init.d/client-firewall.init /etc/init.d/client-firewall && "
    "mv /etc/init.d/overdrive-ip-timezone.init /etc/init.d/overdrive-ip-timezone && "
    "chmod 0755 /usr/local/sbin/lab-net-troubleshoot && "
    "chmod 0755 /usr/local/sbin/lab-net-up && "
    "chmod 0755 /usr/local/sbin/client-firewall && "
    "chmod 0755 /usr/local/sbin/overdrive-ip-timezone && "
    "chmod 0755 /etc/init.d/lab-net-up && "
    "chmod 0755 /etc/init.d/client-firewall && "
    "chmod 0755 /etc/init.d/overdrive-ip-timezone && "
    "find /root/local_host -type f -name '*.py' -exec chmod 0755 {} \\; && "
    f"{REMOTE_BOOT_SERVICE_CLEANUP_COMMAND} && "
    "rc-update add lab-net-up default && "
    "rc-update add overdrive-ip-timezone default && "
    "grep -q '^ttyS0' /etc/inittab || echo 'ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100' >> /etc/inittab && "
    "grep -qx 'ttyS0' /etc/securetty 2>/dev/null || echo ttyS0 >> /etc/securetty || true && "
    # Unattended boot: stock nocloud uses DEFAULT menu.c32 + TIMEOUT, but VBox
    # serial noise cancels TIMEOUT so the menu waits forever for Enter.
    # Boot the MENU DEFAULT / first LABEL directly + TOTALTIMEOUT.
    "for f in /boot/extlinux.conf /boot/syslinux/syslinux.cfg /boot/syslinux.cfg "
    "/media/*/boot/syslinux/syslinux.cfg; do "
    "[ -f \"$f\" ] || continue; "
    "DEF=$(awk 'BEGIN{l=\"\"} "
    "tolower($1)==\"label\"{l=$2; next} "
    "tolower($1)==\"menu\" && tolower($2)==\"default\"{print l; exit}' \"$f\"); "
    "[ -n \"$DEF\" ] || DEF=$(awk 'tolower($1)==\"label\"{print $2; exit}' \"$f\"); "
    "tmp=$(mktemp); "
    "awk 'BEGIN{ignore=0} "
    "tolower($1)==\"serial\"{next} "
    "tolower($1)==\"timeout\"{next} "
    "tolower($1)==\"totaltimeout\"{next} "
    "tolower($1)==\"prompt\"{next} "
    "tolower($1)==\"default\"{next} "
    "tolower($1)==\"noescape\"{next} "
    "tolower($1)==\"ui\"{next} "
    "tolower($1)==\"menu\" && (tolower($2)==\"title\"||tolower($2)==\"hidden\"||tolower($2)==\"autoboot\"||tolower($2)==\"separator\"){next} "
    "{print}' \"$f\" > \"$tmp\"; "
    "{ "
    "echo 'SERIAL 0 115200'; "
    "echo 'PROMPT 0'; "
    "echo 'NOESCAPE 1'; "
    "echo 'TIMEOUT 5'; "
    "echo 'TOTALTIMEOUT 20'; "
    "[ -n \"$DEF\" ] && echo \"DEFAULT $DEF\"; "
    "echo; "
    "cat \"$tmp\"; "
    "} > \"$f.new\"; "
    "mv \"$f.new\" \"$f\"; rm -f \"$tmp\"; "
    "grep -q 'console=ttyS0' \"$f\" || "
    "sed -i -E 's/^([[:space:]]*(APPEND|append)[[:space:]].*)$/\\1 console=ttyS0,115200/' \"$f\"; "
    "echo \"[overdrive] unattended bootloader: $f default=${DEF:-none}\"; "
    "done"
)

ASSERT_NO_REMOTE_BOOT_HOOKS_COMMAND = (
    "! find /etc/init.d /etc/runlevels /etc/conf.d "
    "\\( -name 'sshd' -o -name 'ssh' -o -name 'dropbear' "
    "-o -name 'tiny-cloud-*' -o -name 'cloud-init' -o -name 'cloud-final' \\) "
    "-print -quit | grep -q . && "
    "[ ! -e /etc/ssh ] && "
    "[ ! -e /etc/tiny-cloud.conf ]"
)

CLEAN_CLIENT_PRIME_HELPERS_COMMAND = (
    "rm -f "
    "/root/install-client-packages.sh /root/harden-client.sh "
    "/tmp/install-client-packages.sh /tmp/harden-client.sh "
    "/var/tmp/install-client-packages.sh /var/tmp/harden-client.sh"
)


@dataclass(frozen=True)
class ClientPrimeAssets:
    interfaces_host: Path
    troubleshoot_host: Path
    lab_net_up_host: Path
    lab_net_up_init_host: Path
    client_firewall_host: Path
    client_firewall_init_host: Path
    hardening_script_host: Path
    package_script_host: Path
    timezone_script_host: Path
    timezone_init_host: Path
    root_password_file: Path
    local_host_payload_host: Path
    detections_payload_host: Path
    setup_venv_host: Path


def prepare_client_prime_assets(work_root: Path) -> ClientPrimeAssets:
    """Write host-side files that later virt-customize stages copy into the guest."""
    interfaces_host = work_root / "interfaces"
    interfaces_host.write_text(LAB_INTERFACES_ALPINE, encoding="utf-8", newline="\n")

    troubleshoot_host = work_root / "lab_net_troubleshoot.sh"
    troubleshoot_host.write_text(LAB_NET_TROUBLESHOOT_SCRIPT, encoding="utf-8", newline="\n")

    lab_net_up_host = work_root / "lab-net-up"
    lab_net_up_host.write_text(LAB_NET_UP_SCRIPT, encoding="utf-8", newline="\n")

    lab_net_up_init_host = work_root / "lab-net-up.init"
    lab_net_up_init_host.write_text(LAB_NET_UP_INIT_ALPINE, encoding="utf-8", newline="\n")

    client_firewall_host = work_root / "client-firewall"
    client_firewall_host.write_text(CLIENT_FIREWALL_SCRIPT, encoding="utf-8", newline="\n")

    client_firewall_init_host = work_root / "client-firewall.init"
    client_firewall_init_host.write_text(CLIENT_FIREWALL_INIT_ALPINE, encoding="utf-8", newline="\n")

    hardening_script_host = work_root / "harden-client.sh"
    hardening_script_host.write_text(CLIENT_HARDENING_SCRIPT, encoding="utf-8", newline="\n")
    hardening_script_host.chmod(0o700)

    package_script_host = work_root / "install-client-packages.sh"
    package_script_host.write_text(
        client_package_install_script(),
        encoding="utf-8",
        newline="\n",
    )
    package_script_host.chmod(0o700)

    timezone_script_host = work_root / "overdrive-ip-timezone"
    timezone_script_host.write_text(CLIENT_IP_TIMEZONE_SCRIPT, encoding="utf-8", newline="\n")

    timezone_init_host = work_root / "overdrive-ip-timezone.init"
    timezone_init_host.write_text(CLIENT_IP_TIMEZONE_INIT_ALPINE, encoding="utf-8", newline="\n")

    root_password_file = work_root / "alpine-root-password"
    root_password_file.write_text(alpine_client_root_password(), encoding="utf-8", newline="\n")
    root_password_file.chmod(0o600)

    local_host_payload_host = work_root / "local_host"
    if local_host_payload_host.exists():
        shutil.rmtree(local_host_payload_host)
    detections_payload_host = work_root / "detections"
    if detections_payload_host.exists():
        shutil.rmtree(detections_payload_host)
    shutil.copytree(
        Path(REPO_ROOT) / "local_host",
        local_host_payload_host,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    shutil.copytree(
        Path(REPO_ROOT) / "detections",
        detections_payload_host,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    setup_venv_host = work_root / "install.py"
    shutil.copy2(Path(REPO_ROOT) / "install.py", setup_venv_host)

    return ClientPrimeAssets(
        interfaces_host=interfaces_host,
        troubleshoot_host=troubleshoot_host,
        lab_net_up_host=lab_net_up_host,
        lab_net_up_init_host=lab_net_up_init_host,
        client_firewall_host=client_firewall_host,
        client_firewall_init_host=client_firewall_init_host,
        hardening_script_host=hardening_script_host,
        package_script_host=package_script_host,
        timezone_script_host=timezone_script_host,
        timezone_init_host=timezone_init_host,
        root_password_file=root_password_file,
        local_host_payload_host=local_host_payload_host,
        detections_payload_host=detections_payload_host,
        setup_venv_host=setup_venv_host,
    )


def run_client_virt_customize(
    vdi_linux: str,
    args: list[str],
    *,
    skip_prime: bool,
    network: bool = False,
) -> None:
    vc = require_vdi_prime_tools(skip_prime=skip_prime)
    virt_env = _libguestfs_env()
    command = [vc, "-a", vdi_linux]
    if network:
        command.append("--network")
    command.extend(args)
    subprocess.run(command, check=True, env=virt_env)


def prime_client_identity_and_base_packages(
    vdi_linux: str,
    assets: ClientPrimeAssets,
    *,
    skip_prime: bool,
) -> None:
    """Set guest identity/password and install only bootstrap OS packages."""
    run_client_virt_customize(
        vdi_linux,
        [
            "--hostname",
            CLIENT_GUEST_HOSTNAME,
            "--root-password",
            f"file:{assets.root_password_file}",
            "--run-command",
            CLIENT_IDENTITY_COMMAND,
            "--run",
            str(assets.package_script_host),
        ],
        skip_prime=skip_prime,
        network=True,
    )


def copy_client_payloads_and_service_assets(
    vdi_linux: str,
    assets: ClientPrimeAssets,
    *,
    skip_prime: bool,
) -> None:
    """Copy local payloads and service scripts into the guest image."""
    run_client_virt_customize(
        vdi_linux,
        [
            "--copy-in",
            f"{assets.interfaces_host}:/etc/network",
            "--copy-in",
            f"{assets.troubleshoot_host}:/usr/local/sbin",
            "--copy-in",
            f"{assets.lab_net_up_host}:/usr/local/sbin",
            "--copy-in",
            f"{assets.lab_net_up_init_host}:/etc/init.d",
            "--copy-in",
            f"{assets.client_firewall_host}:/usr/local/sbin",
            "--copy-in",
            f"{assets.client_firewall_init_host}:/etc/init.d",
            "--copy-in",
            f"{assets.timezone_script_host}:/usr/local/sbin",
            "--copy-in",
            f"{assets.timezone_init_host}:/etc/init.d",
            "--copy-in",
            f"{assets.local_host_payload_host}:/root",
            "--copy-in",
            f"{assets.detections_payload_host}:/root",
            "--copy-in",
            f"{assets.setup_venv_host}:/root",
        ],
        skip_prime=skip_prime,
    )


def install_client_detection_libraries(
    vdi_linux: str,
    *,
    skip_prime: bool,
) -> None:
    """Run repo install.py inside the guest; installs network/detection libraries."""
    run_client_virt_customize(
        vdi_linux,
        [
            "--run-command",
            INSTALL_DETECTION_LIBRARIES_COMMAND,
        ],
        skip_prime=skip_prime,
        network=True,
    )


def configure_client_guest_services_and_boot(
    vdi_linux: str,
    *,
    skip_prime: bool,
) -> None:
    """Wire copied scripts into OpenRC and make the bootloader serial/unattended."""
    run_client_virt_customize(
        vdi_linux,
        [
            "--run-command",
            CONFIGURE_CLIENT_SERVICES_AND_BOOT_COMMAND,
        ],
        skip_prime=skip_prime,
    )


def harden_and_clean_client_guest_image(
    vdi_linux: str,
    assets: ClientPrimeAssets,
    *,
    skip_prime: bool,
) -> None:
    """Apply privacy hardening and prove unwanted remote-login hooks are absent."""
    run_client_virt_customize(
        vdi_linux,
        [
            "--run",
            str(assets.hardening_script_host),
            "--run-command",
            ASSERT_NO_REMOTE_BOOT_HOOKS_COMMAND,
            "--run-command",
            CLEAN_CLIENT_PRIME_HELPERS_COMMAND,
        ],
        skip_prime=skip_prime,
    )


def prime_client_vdi_for_intnet_lab(
    vdi_linux: str,
    work_root: Path,
    *,
    skip_prime: bool,
) -> bool:
    """Compatibility wrapper for older callers; setup_client_vm uses discrete steps."""
    print("Injecting custom configuration and packages into Alpine image...")
    assets = prepare_client_prime_assets(work_root)
    prime_client_identity_and_base_packages(vdi_linux, assets, skip_prime=skip_prime)
    copy_client_payloads_and_service_assets(vdi_linux, assets, skip_prime=skip_prime)
    install_client_detection_libraries(vdi_linux, skip_prime=skip_prime)
    configure_client_guest_services_and_boot(vdi_linux, skip_prime=skip_prime)
    harden_and_clean_client_guest_image(vdi_linux, assets, skip_prime=skip_prime)
    return True


def nudge_alpine_boot_menu(*, rounds: int = 8, interval_s: float = 1.0) -> None:
    """Send Enter a few times on COM1 in case the boot menu is still waiting.

    Primary fix is unattended extlinux (TOTALTIMEOUT + DEFAULT label). This is a
    short, non-interactive safety net so create never depends on a human keypress.
    """
    import socket

    print("[overdrive] Nudging Alpine serial boot (Enter) for unattended start...")
    deadline = time.monotonic() + 20.0
    last_err: OSError | None = None
    while time.monotonic() < deadline:
        for host in serial_tcp_host_candidates(SERIAL_TCP_HOST):
            try:
                with socket.create_connection((host, ALPINE_SERIAL_TCP_PORT), timeout=2.0) as sock:
                    sock.settimeout(0.5)
                    for _ in range(rounds):
                        sock.sendall(b"\r")
                        time.sleep(interval_s)
                        try:
                            while sock.recv(4096):
                                pass
                        except OSError:
                            pass
                print("[overdrive] Boot nudge sent.")
                return
            except OSError as exc:
                last_err = exc
        time.sleep(0.5)
    print(f"[!] Could not nudge Alpine serial boot ({last_err}); relying on extlinux TOTALTIMEOUT.")


def setup_client_vm(
    *,
    start_vm: bool = True,
    connect_serial: bool = True,
    skip_vdi_prime: bool = False,
) -> None:
    options = AlpineClientBuildOptions(
        start_vm=start_vm,
        connect_serial=connect_serial,
        skip_vdi_prime=skip_vdi_prime,
    )
    paths = get_system_paths(VM_NAME, ALPINE_IMAGE_NAME)
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError("VBoxManage not found.")

    vm_base = paths["vm_base"]
    vms_root = paths["vms_root"]
    download_dir = paths["downloads"]
    img_path = paths["img_path"]
    vdi_wsl = os.path.join(vm_base, CLIENT_VDI_NAME)

    vdi_for_vbox = wsl_to_windows_path(vdi_wsl) if paths["is_wsl"] else vdi_wsl
    vms_root_for_vbox = wsl_to_windows_path(vms_root) if paths["is_wsl"] else vms_root
    src_path = wsl_to_windows_path(img_path) if paths["is_wsl"] else img_path

    serial_endpoint = serial_endpoint_for_vbox(vboxmanage, tcp_port=ALPINE_SERIAL_TCP_PORT)
    prime_assets: ClientPrimeAssets | None = None

    def require_prime_assets() -> ClientPrimeAssets:
        if prime_assets is None:
            raise RuntimeError("Alpine guest prime assets were not prepared before image customization.")
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

    def download_base_image() -> None:
        download_alpine_image(ALPINE_URL, img_path)

    def convert_base_image() -> None:
        if os.path.exists(vdi_wsl):
            print("Alpine client VDI already exists after cleanup; reusing it.")
            return
        print("Converting base Alpine image into VDI format...")
        run_vboxmanage(
            vboxmanage,
            ["clonemedium", "disk", src_path, vdi_for_vbox, "--format", "VDI"],
        )

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
                "Linux_64",
                "--basefolder",
                vms_root_for_vbox,
                "--register",
            ],
        )

    def configure_vm_hardware() -> None:
        client_mac = random_client_mac_vbox()
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
                "--macaddress1",
                client_mac,
            ],
        )
        oui = CLIENT_NIC_OUI.lower().replace(":", "")
        oui_colon = ":".join(oui[i : i + 2] for i in range(0, 6, 2))
        print(
            f"[overdrive] Client NIC MAC (OUI {oui_colon}): {format_mac_colon(client_mac)}"
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
        print(f"Starting {VM_NAME}...")
        run_vboxmanage(vboxmanage, ["startvm", VM_NAME, "--type", "gui"])

        # Unattended: don't leave the Syslinux menu waiting for a human Enter.
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
                title=f"LAN Alpine Client serial ({ALPINE_SERIAL_TCP_PORT})",
                extra_args=extra_args,
                cwd=Path(SCRIPT_DIR),
            )
            if not spawned:
                connect_serial_console(vboxmanage, serial_endpoint, force_interactive=True)

    steps = [
        BuildStep("cleanup.existing-vm", "remove previous VM and disk", remove_previous_vm),
        BuildStep("workspace.prepare", "prepare workspace", ensure_workspace),
        BuildStep("image.download-base", "download Alpine base image", download_base_image),
        BuildStep("disk.convert-vdi", "convert image to VDI", convert_base_image),
        BuildStep("disk.expand", "expand client disk", expand_disk),
        BuildStep(
            "guest-assets.prepare",
            "prepare guest customization assets",
            prepare_guest_prime_assets,
        ),
        BuildStep(
            "guest.base-packages",
            "set guest identity and install base packages",
            install_guest_identity_and_base_packages,
            description="Installs only bootstrap packages needed for later customization.",
        ),
        BuildStep(
            "guest.payloads",
            "copy payloads and service assets",
            copy_guest_payloads_and_service_assets,
        ),
        BuildStep(
            "guest.detection-libs",
            "install detection/network libraries",
            install_guest_detection_libraries,
            description="Future optional boundary for Chromium, network tools, and Python detection dependencies.",
        ),
        BuildStep(
            "guest.services-boot",
            "configure guest services and unattended boot",
            configure_guest_services_and_boot,
        ),
        BuildStep("guest.hardening", "apply hardening and cleanup", harden_guest_image),
        BuildStep("vbox.register", "create VirtualBox VM registration", create_vm_registration),
        BuildStep("vbox.hardware", "configure VM hardware and serial", configure_vm_hardware),
        BuildStep("vbox.storage", "attach VDI storage", attach_storage),
        BuildStep(
            "vbox.start",
            "start VM and attach serial",
            start_and_connect,
            enabled=options.start_vm,
        ),
    ]

    run_alpine_client_pipeline(steps)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Create / configure Alpine Linux router-lab client VM.")
    ap.add_argument("--no-start", action="store_true", help="Configure the VM but do not start it.")
    ap.add_argument("--serial-only", action="store_true", help="Open serial console for already running Alpine client.")
    ap.add_argument("--serial-here", action="store_true", help="Attach to serial directly in this console window.")
    ap.add_argument("--force-interactive-serial", action="store_true", help="Forces interactive socket bridge on startup.")
    ap.add_argument("--serial-port", type=int, default=ALPINE_SERIAL_TCP_PORT, help="TCP port for serial console.")
    ns = ap.parse_args()

    if ns.serial_here or ns.serial_only:
        paths = get_system_paths(VM_NAME)
        vboxmanage = find_vboxmanage(paths)
        if not vboxmanage:
            raise RuntimeError("VBoxManage not found.")
        serial_endpoint = serial_endpoint_for_vbox(vboxmanage, tcp_port=ns.serial_port)
        if ns.serial_only and not ns.serial_here:
            extra_args=["--force-interactive-serial"] if ns.force_interactive_serial else []
            extra_args.extend(["--serial-port", str(ns.serial_port)])
            spawned = spawn_serial_console_window(Path(__file__).resolve(), title=f"LAN Alpine Client serial ({ns.serial_port})", extra_args=extra_args, cwd=Path(SCRIPT_DIR))
            if spawned:
                raise SystemExit(0)
        connect_serial_console(vboxmanage, serial_endpoint, force_interactive=ns.force_interactive_serial or ns.serial_here)
        raise SystemExit(0)

    setup_client_vm(
        start_vm=not ns.no_start,
        connect_serial=not ns.no_start,
    )
