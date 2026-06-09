#!/usr/bin/env python3
r"""
Create a Linux VM in VirtualBox for use **behind** the OpenWrt router from
``create_VM_OpenWrt_router.py``.

Confirm current password on https://www.osboxes.org/

Networking (lab):
  * **NIC1** — VirtualBox **internal network** ``openwrt-lan`` (same name as the router’s LAN leg).
    The guest gets DHCP from OpenWrt’s LAN; default gateway is the OpenWrt LAN IP (e.g. 192.168.1.1).

The client often has **no path to the Internet** until OpenWrt DHCP works, so **this script** (on the
**WSL host**, which does have Internet) runs ``virt-customize`` to pre-install ``isc-dhcp-client``,
    ``dig``, and a ``lab-net-troubleshoot`` helper **into the VDI before first lab boot**. Use
``--skip-vdi-prime`` only if you know what you are doing.

This VM is **not** bridged to your Windows/WSL LAN. WSL **mirrored** mode only affects the Linux
namespace on the host; it does not change VirtualBox intnet isolation. To browse from the host
through OpenWrt, use RDP/guest tools or a second setup—this script targets the standard “client on
router LAN” topology.


Serial console endpoint:
  The VM has COM1 wired to the guest's ``ttyS0`` login console at 115200 baud. This is useful when
  DHCP, graphics, SSH, or the browser environment is broken because it is a tiny text-only backdoor
  into the guest.

  Which endpoint you connect to depends on the **host VirtualBox is actually running on**:

  * Windows host / Windows VirtualBox:
      VirtualBox exposes COM1 as TCP server ``127.0.0.1:2323``. The script starts the VM headless
      and attaches from WSL using a native Python socket terminal.

  * WSL shell controlling Windows VirtualBox through ``VBoxManage.exe``:
      This is still **Windows VirtualBox**, so this script uses TCP instead of Windows named pipes.
      To attach to an already-running VM:
        ./create_VM_client_browser_pipe.py --serial-only

      By default, this script starts the VM headless and then attaches this terminal. Use
      ``--no-connect-serial`` when you only want to create/start the VM and return to the shell.

      The built-in WSL bridge uses raw terminal input, maps Enter to serial carriage return, and
      disconnects with Ctrl-].

  * Native Linux host / Linux VirtualBox:
      VirtualBox exposes the Unix socket ``/tmp/OpenWrt_LAN_Client_serial.sock``. After the VM
      starts, run ``socat`` in one terminal to create a PTY, then attach ``screen`` in another:
        rm -f /tmp/OpenWrt_LAN_Client_serial.pty
        socat -d -d UNIX-CONNECT:/tmp/OpenWrt_LAN_Client_serial.sock PTY,link=/tmp/OpenWrt_LAN_Client_serial.pty,raw,echo=0
        screen /tmp/OpenWrt_LAN_Client_serial.pty 115200

      Detach/close screen with Ctrl-a then k.


"""

from __future__ import annotations

import argparse
import contextlib
import os
import platform
import shutil
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

# Ensure the repo package path is importable when running this script from VM/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from detections.common.common_vm import (
    CLIENT_VDI_NAME,
    find_vboxmanage,
    get_half_cpus,
    get_vm_state,
    get_system_paths,
    is_wsl_environment,
    OPENWRT_CLIENT_VM_NAME,
    OPENWRT_LAN_INTNET_NAME,
    OSBOXES_ARCHIVE_NAME,
    OSBOXES_LOGIN_PASSWORD_HINT,
    OSBOXES_LOGIN_USER,
    OSBOXES_URL,
    remove_existing_vm,
    resolve_vbox_settings_path,
    run_vboxmanage,
    SERIAL_BAUD,
    SERIAL_PTY_LINK_PATH,
    SERIAL_TCP_HOST,
    serial_endpoint_for_vbox,
    serial_tcp_host_candidates,
    SERIAL_UNIX_SOCKET_PATH,
    vboxmanage_targets_windows,
    vm_is_registered,
    wsl_to_windows_path,
)

LAN_INTNET_NAME = OPENWRT_LAN_INTNET_NAME
VM_NAME = OPENWRT_CLIENT_VM_NAME
ARCHIVE_NAME = OSBOXES_ARCHIVE_NAME
CLIENT_VM_CPUS = min(2, get_half_cpus())


def download_osboxes_archive(url: str, archive_path: str) -> None:
    """Download the OSBoxes archive with a useful error when the host has no route."""
    try:
        import requests
        from requests.exceptions import RequestException
    except ImportError as exc:
        raise RuntimeError(
            "The Python 'requests' package is required only when downloading the OSBoxes archive.\n"
            "Install it in this environment, or pass --archive-path with an existing archive."
        ) from exc

    print(f"Downloading OSBoxes archive to {archive_path}...")
    try:
        r = requests.get(url, stream=True, allow_redirects=True, timeout=120)
        r.raise_for_status()
    except RequestException as e:
        raise RuntimeError(
            "Could not download the OSBoxes archive.\n"
            f"  URL: {url}\n"
            f"  Destination: {archive_path}\n"
            f"  Error: {e}\n\n"
            "Your shell currently has no working outbound network route, or SourceForge is "
            "not reachable from it. Download the archive from a machine/network that can "
            "reach SourceForge, then rerun with:\n"
            "  ./create_VM_client_browser.py --archive-path /path/to/ubuntu_osboxes_2404.7z"
        ) from None

    with open(archive_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)


def validate_7z_archive(archive_path: str) -> None:
    """Verify the archive is a valid 7z container before extraction."""
    if not os.path.isfile(archive_path):
        raise RuntimeError(f"OSBoxes archive does not exist: {archive_path}")
    try:
        subprocess.run(
            ["7z", "t", archive_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "7z is required to validate/extract the OSBoxes archive. "
            "Install it with: sudo apt install p7zip-full"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "OSBoxes archive appears to be invalid or corrupt.\n"
            f"  Archive: {archive_path}\n"
            "Remove it and re-run this script, or provide a valid archive with "
            "--archive-path."
        ) from exc


def require_vdi_prime_tools(*, skip_prime: bool) -> str:
    """Return virt-customize path or fail before expensive client VDI work."""
    if skip_prime:
        raise RuntimeError(
            "--skip-vdi-prime is incompatible with the current client VM requirement: "
            "WSL must be able to reach a working ttyS0 serial login. Do not skip VDI priming."
        )
    vc = shutil.which("virt-customize")
    if not vc:
        raise RuntimeError(
            "virt-customize is required to enable ttyS0 serial login in the client guest.\n"
            "Install it in WSL with:\n"
            "  sudo apt install -y libguestfs-tools\n"
            "Without this step, VirtualBox can expose TCP port 2323 but Ubuntu may never "
            "start serial-getty@ttyS0."
        )
    return vc


# If VDI priming was skipped and the guest somehow has Internet, this still works:
IN_GUEST_INSTALL_ISC_DHCP_CLIENT = "sudo apt install -y isc-dhcp-client"

# Installed into the guest by ``prime_client_vdi_for_intnet_lab`` (host-side virt-customize).
LAB_NET_TROUBLESHOOT_SCRIPT = r"""#!/bin/bash
# Installed by create_VM_client_browser.py — run: lab-net-troubleshoot  (uses sudo when needed)
set -u
echo "================================================================"
echo " Lab network troubleshoot (OpenWrt intnet client)"
echo " Run: lab-net-troubleshoot   (or sudo lab-net-troubleshoot)"
echo "================================================================"
echo ""
echo "=== IPv4 addresses ==="
ip -br -4 addr 2>/dev/null || true
echo ""
echo "=== Routes ==="
ip route 2>/dev/null || true
echo ""
echo "=== Default IPv4 route ==="
if ip -4 route show default 2>/dev/null | grep -q .; then
  ip -4 route show default
else
  echo "(none) — no DHCP lease or no gateway from OpenWrt."
fi
echo ""
echo "=== DHCP on each Ethernet-like interface ==="
if ! command -v dhclient >/dev/null 2>&1; then
  echo "ERROR: dhclient missing. Re-run create_VM_client_browser.py on WSL with libguestfs-tools."
  exit 1
fi
for IFACE in /sys/class/net/*; do
  IFACE=$(basename "$IFACE")
  [ "$IFACE" = lo ] && continue
  [ ! -e "/sys/class/net/$IFACE/device" ] && continue
  echo "--- dhclient $IFACE ---"
  if [ "$(id -u)" -eq 0 ]; then
    dhclient -v -1 "$IFACE" 2>&1 | tail -25 || true
  else
    sudo dhclient -v -1 "$IFACE" 2>&1 | tail -25 || true
  fi
done
echo ""
echo "=== After DHCP ==="
ip -br -4 addr 2>/dev/null || true
ip -4 route show default 2>/dev/null || true
echo ""
echo "=== Static fallback (OpenWrt LAN often 192.168.1.1/24) ==="
echo "  IFACE=enp0s3    # from: ip -br link"
echo '  sudo ip addr flush dev "$IFACE" 2>/dev/null || true'
echo '  sudo ip addr add 192.168.1.50/24 dev "$IFACE"'
echo '  sudo ip link set "$IFACE" up'
echo '  sudo ip route replace default via 192.168.1.1 dev "$IFACE"'
echo "  ping -c2 192.168.1.1"
echo ""
if command -v dig >/dev/null 2>&1; then
  echo "=== dig via router (optional) ==="
  dig +short @192.168.1.1 openwrt.org 2>/dev/null || true
fi
"""


def guest_serial_console_commands() -> list[str]:
    """Commands run inside the guest image so ttyS0 has a login prompt."""
    return [
        (
            "mkdir -p /etc/systemd/system/getty.target.wants && "
            "if [ -e /lib/systemd/system/serial-getty@.service ]; then "
            "ln -sf /lib/systemd/system/serial-getty@.service "
            "/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service; "
            "elif [ -e /usr/lib/systemd/system/serial-getty@.service ]; then "
            "ln -sf /usr/lib/systemd/system/serial-getty@.service "
            "/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service; "
            "else echo 'serial-getty template not found' >&2; exit 1; fi"
        ),
        (
            "if [ -f /etc/default/grub ]; then "
            "if grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub; then "
            "sed -i 's#^GRUB_CMDLINE_LINUX=.*#GRUB_CMDLINE_LINUX=\"console=tty0 console=ttyS0,"
            f"{SERIAL_BAUD}n8\"#' /etc/default/grub; "
            "else echo 'GRUB_CMDLINE_LINUX=\"console=tty0 console=ttyS0,"
            f"{SERIAL_BAUD}n8\"' >> /etc/default/grub; fi; "
            "update-grub || grub-mkconfig -o /boot/grub/grub.cfg || true; "
            "fi"
        ),
    ]


def serial_console_instructions(vboxmanage: str, endpoint: str) -> str:
    """Host-specific commands for attaching to the VM serial console."""
    if vboxmanage_targets_windows(vboxmanage):
        hosts = ", ".join(serial_tcp_host_candidates(SERIAL_TCP_HOST))
        return (
            "--- Serial console TCP endpoint ---\n"
            f"VirtualBox exposes COM1 as TCP port {endpoint} on the Windows host.\n"
            f"From WSL, connect to one of: {hosts}\n"
            "This avoids Windows named-pipe stdin issues when attaching from WSL.\n"
            "If the endpoint is busy/stuck, refresh only the live UART backend:\n"
            f"  VBoxManage.exe controlvm {VM_NAME} changeuartmode1 disconnected\n"
            f"  VBoxManage.exe controlvm {VM_NAME} changeuartmode1 tcpserver {endpoint}\n"
            "This script attaches to the serial console automatically after starting the VM.\n"
            "To attach to an already-running VM from WSL:\n"
            f"  ./{Path(__file__).name} --serial-only\n"
            "To create/start without attaching:\n"
            f"  ./{Path(__file__).name} --no-connect-serial\n"
            "The guest should show a ttyS0 login; press Enter once if the console is blank.\n"
        )
    return (
        "--- Serial console host socket ---\n"
        f"VirtualBox exposes COM1 as: {endpoint}\n"
        "Because this is native Linux VirtualBox, attach with socat plus screen:\n"
        f"  rm -f {SERIAL_PTY_LINK_PATH}\n"
        f"  socat -d -d UNIX-CONNECT:{endpoint} PTY,link={SERIAL_PTY_LINK_PATH},raw,echo=0\n"
        f"  screen {SERIAL_PTY_LINK_PATH} {SERIAL_BAUD}\n"
        "Run the socat command in one terminal after the VM starts, then screen from another terminal.\n"
        "Detach screen with Ctrl-a then k. The guest should show a ttyS0 login.\n"
    )


def configure_serial_endpoint(vboxmanage: str, endpoint: str) -> None:
    """Expose COM1 as a host pipe/socket that a terminal program can attach to."""
    if vboxmanage_targets_windows(vboxmanage):
        uart_mode = "tcpserver"
        print(f"Serial console: COM1 -> TCP {SERIAL_TCP_HOST}:{endpoint} ({SERIAL_BAUD} baud).")
    else:
        uart_mode = "server"
        print(f"Serial console: COM1 -> host socket {endpoint} ({SERIAL_BAUD} baud).")
    run_vboxmanage(
        vboxmanage,
        [
            "modifyvm",
            VM_NAME,
            "--uart1",
            "0x3F8",
            "4",
            "--uartmode1",
            uart_mode,
            endpoint,
        ],
    )


def refresh_live_serial_endpoint(vboxmanage: str, endpoint: str) -> None:
    """Refresh COM1's serial backend for an already-running VM.

    This briefly suspends/resumes the guest in VirtualBox, so only use it as a
    manual recovery action after the VM has finished booting.
    """
    if vboxmanage_targets_windows(vboxmanage):
        uart_mode = "tcpserver"
        print(f"Refreshing live serial TCP backend for {VM_NAME}: {SERIAL_TCP_HOST}:{endpoint}")
    else:
        uart_mode = "server"
        print(f"Refreshing live serial socket backend for {VM_NAME}: {endpoint}")
    run_vboxmanage(vboxmanage, ["controlvm", VM_NAME, "changeuartmode1", "disconnected"])
    run_vboxmanage(vboxmanage, ["controlvm", VM_NAME, "changeuartmode1", uart_mode, endpoint])


@contextlib.contextmanager
def _raw_stdin_for_serial(input_fd: int | None = None):
    """Put the controlling TTY into raw mode while the serial bridge owns keyboard input."""
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
    """Prefer the controlling terminal for keyboard input instead of inherited stdin."""
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
    """Write serial bytes to stdout even when the console has a narrow encoding."""
    try:
        os.write(sys.stdout.fileno(), data)
    except OSError:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def _print_serial_health_hint(sample: bytes) -> None:
    """Surface guest-side failures before asking the user to type into the console."""
    lower = sample.lower()
    if b"soft lockup" in lower or b"watchdog: bug" in lower:
        print(
            "\n[!] Guest output contains Linux watchdog soft-lockup messages.\n"
            "    The serial TCP connection works, but the Ubuntu guest appears wedged.\n"
            "    Power off OpenWrt_LAN_Client, then rerun this script so the stable "
            f"{CLIENT_VM_CPUS}-CPU profile is applied before boot.\n"
        )


def _probe_serial_guest_output(sock: socket.socket, *, wait_s: float = 6.0) -> bytes:
    """Send Enter and wait briefly for guest bytes so the user knows the console is alive."""
    print(
        "[serial check] TCP socket connected. Sending Enter and waiting "
        f"up to {wait_s:.0f}s for guest serial output..."
    )
    sample = bytearray()

    sock.setblocking(False)
    deadline = time.monotonic() + wait_s
    next_enter_at = 0.0
    next_progress_at = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_enter_at:
            try:
                sock.sendall(b"\r")
            except OSError:
                return bytes(sample)
            next_enter_at = now + 5.0
        if now >= next_progress_at:
            remaining = max(0.0, deadline - now)
            print(f"[serial check] Still waiting for guest serial output ({remaining:.0f}s left)...")
            next_progress_at = now + 10.0
        timeout = max(0.05, min(0.25, deadline - time.monotonic()))
        readable, _, _ = select.select([sock], [], [], timeout)
        if sock not in readable:
            continue
        try:
            data = sock.recv(4096)
        except BlockingIOError:
            continue
        if not data:
            print("\n[serial check] TCP endpoint closed during probe.")
            return bytes(sample)
        sample.extend(data)
        _write_serial_output(data)
        if b"login:" in sample.lower() or b"password:" in sample.lower():
            break

    if sample:
        print("\n[serial check] Guest serial output received; interactive bridge is ready.")
        _print_serial_health_hint(bytes(sample))
    else:
        print(
            "[serial check] TCP socket is reachable, but the guest produced no serial output.\n"
            "    If the VirtualBox GUI is already at a tty1 login prompt, the likely issue is "
            "that ttyS0/serial-getty is not enabled inside the guest."
        )
    return bytes(sample)


def _connect_tcp_serial_windows(sock: socket.socket) -> None:
    """Interactive TCP serial bridge for Windows consoles."""
    try:
        import msvcrt
    except ImportError as exc:
        raise RuntimeError("Windows serial bridge requires the msvcrt module.") from exc

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
                print("\n[serial disconnected]")
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
            # Function/arrow keys arrive as two-code sequences. Ignore the suffix.
            if msvcrt.kbhit():
                msvcrt.getwch()
            continue
        if ch == "\x1d":
            print("\n[serial detached]")
            stop.set()
            return
        if ch in ("\r", "\n"):
            data = b"\r"
        else:
            data = ch.encode("utf-8", errors="ignore")
        if data:
            try:
                sock.sendall(data)
            except OSError:
                print("\n[serial disconnected]")
                stop.set()
                return


def _connect_tcp_serial_posix(sock: socket.socket) -> None:
    """Interactive TCP serial bridge for POSIX terminals."""
    sock.setblocking(False)
    with _serial_input_fd() as input_fd:
        if input_fd is None:
            print(
                "[!] No controlling terminal for keyboard input. "
                "Run from an interactive shell or let run_VMs.py open a new terminal tab."
            )
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
                        print("\n[serial disconnected]")
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
                        before, _, _ = data.partition(b"\x1d")
                        if before:
                            sock.sendall(before.replace(b"\n", b"\r"))
                        print("\n[serial detached]")
                        return
                    sock.sendall(data.replace(b"\n", b"\r"))


def _open_tcp_serial_socket(host: str, port: int, *, timeout_s: float) -> socket.socket:
    """Open the VirtualBox TCP serial endpoint."""
    host_candidates = serial_tcp_host_candidates(host)
    deadline = time.monotonic() + timeout_s
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        for candidate in host_candidates:
            try:
                sock = socket.create_connection((candidate, port), timeout=1.0)
                print(f"CONNECTED_TO_SERIAL_TCP: {candidate}:{port}")
                return sock
            except OSError as exc:
                last_error = exc
        time.sleep(0.25)
    tried = ", ".join(f"{candidate}:{port}" for candidate in host_candidates)
    raise RuntimeError(f"Could not connect to serial TCP endpoint; tried {tried}: {last_error}")


def wait_for_tcp_serial_guest_output(
    host: str,
    port: int,
    *,
    timeout_s: float,
    connect_timeout_s: float = 30.0,
    probe_wait_s: float | None = None,
) -> bool:
    """Poll until the serial endpoint returns actual guest bytes."""
    print("[serial readiness] Waiting for the TCP endpoint, then for guest serial bytes...")
    try:
        with _open_tcp_serial_socket(host, port, timeout_s=connect_timeout_s) as sock:
            sample = _probe_serial_guest_output(sock, wait_s=probe_wait_s or timeout_s)
    except RuntimeError as exc:
        print(f"[serial readiness] TCP endpoint did not become reachable: {exc}")
        sample = b""
    if sample:
        print("[serial readiness] Guest serial output is available.")
        return True
    print(
        "[serial readiness] Timed out waiting for guest serial output. "
        "Not opening an interactive serial window."
    )
    return False


def connect_tcp_serial_console(
    host: str,
    port: int,
    *,
    timeout_s: float = 20.0,
    force_interactive: bool = False,
) -> bool:
    """Attach this terminal to a VirtualBox TCP serial endpoint."""
    print(
        f"Connecting terminal to serial TCP port {port} "
        f"({SERIAL_BAUD} baud equivalent)."
    )
    print("The script will verify guest output before handing you the interactive console.")

    with _open_tcp_serial_socket(host, port, timeout_s=timeout_s) as sock:
        sample = _probe_serial_guest_output(sock)
        if not sample and not force_interactive:
            print(
                "[serial interactive] Not opening interactive mode because the guest "
                "did not produce serial output. Re-run with --force-interactive-serial "
                "only if you intentionally want a raw socket bridge."
            )
            return False
        if os.name == "nt":
            _connect_tcp_serial_windows(sock)
        else:
            _connect_tcp_serial_posix(sock)
    return True


def connect_serial_console(
    vboxmanage: str,
    endpoint: str,
    *,
    timeout_ms: int = 15000,
    force_interactive: bool = False,
) -> bool:
    """Attach the current terminal to the VM serial console."""
    if vboxmanage_targets_windows(vboxmanage):
        return connect_tcp_serial_console(
            SERIAL_TCP_HOST,
            int(endpoint),
            timeout_s=timeout_ms / 1000,
            force_interactive=force_interactive,
        )

    socat = shutil.which("socat")
    screen = shutil.which("screen")
    if not socat or not screen:
        raise RuntimeError(
            "Native Linux serial attach requires socat and screen. Install them with:\n"
            "  sudo apt install -y socat screen"
        )
    print(
        "Native Linux VirtualBox uses a Unix socket. Run these in two terminals:\n"
        f"  rm -f {SERIAL_PTY_LINK_PATH}\n"
        f"  socat -d -d UNIX-CONNECT:{endpoint} PTY,link={SERIAL_PTY_LINK_PATH},raw,echo=0\n"
        f"  screen {SERIAL_PTY_LINK_PATH} {SERIAL_BAUD}"
    )
    return True




def remove_existing_client_vm(
    vboxmanage: str,
    vm_base: str,
    *,
    medium_path_for_vbox: str,
) -> None:
    """Compatibility wrapper; use ``common_vm.remove_existing_vm`` for new code."""
    remove_existing_vm(
        vboxmanage,
        VM_NAME,
        vm_base,
        medium_path_for_vbox=medium_path_for_vbox,
    )
    return
    if vm_is_registered(vboxmanage, VM_NAME):
        state = get_vm_state(vboxmanage, VM_NAME)
        if state == "saved":
            print(f"Discarding saved state for {VM_NAME!r}…")
            subprocess.run(
                [vboxmanage, "discardstate", VM_NAME], capture_output=True, text=True
            )
            state = get_vm_state(vboxmanage, VM_NAME)
        if state in ("running", "paused", "stopping", "starting"):
            print(f"Powering off existing VM {VM_NAME!r} ({state})…")
            subprocess.run([vboxmanage, "controlvm", VM_NAME, "poweroff"], check=False)
            for _ in range(45):
                time.sleep(1)
                st = get_vm_state(vboxmanage, VM_NAME)
                if st in (None, "poweroff", "aborted"):
                    break
            else:
                print(
                    f"[!] VM {VM_NAME!r} did not reach poweroff in time; "
                    "unregister may fail — close the VM window or run ``VBoxManage controlvm … poweroff``."
                )
        time.sleep(3)

        print(f"Unregistering and deleting VirtualBox VM {VM_NAME!r} (all media)…")
        if not try_unregistervm_delete(vboxmanage, VM_NAME):
            raise RuntimeError(
                f"Could not unregister {VM_NAME!r} (VirtualBox still has it locked). "
                "Close any window showing that VM, exit stray VBoxManage sessions, then re-run."
            )

    vbox_closemedium_disk_delete_best_effort(vboxmanage, medium_path_for_vbox)

    if os.path.isdir(vm_base):
        print(f"Removing leftover VM directory {vm_base!r}…")
        shutil.rmtree(vm_base, ignore_errors=True)



def prime_client_vdi_for_intnet_lab(
    vdi_linux: str,
    vboxmanage: str,
    vm_name: str,
    work_root: Path,
    *,
    force_poweroff: bool,
    skip_prime: bool,
) -> bool:
    """
    On the **WSL/Linux host** (which has Internet), inject DHCP client, ping, dig, and
    ``lab-net-troubleshoot`` into the VDI so the guest works **without** in-guest ``apt`` when
    OpenWrt has not yet provided a route.
    """
    if is_wsl_environment():
        print(
            "[!] Running under WSL: attempting host-side virt-customize/libguestfs VDI priming."
            " libguestfs/supermin is unreliable on WSL — re-run without WSL or use --skip-vdi-prime"
        )

    vc = require_vdi_prime_tools(skip_prime=skip_prime)
    virt_env = os.environ.copy()
    if is_wsl_environment():
        virt_env.setdefault("LIBGUESTFS_BACKEND", "direct")

    if not _poweroff_vm_for_vdi_edit(vboxmanage, vm_name, force_poweroff=force_poweroff):
        raise RuntimeError(
            "VDI priming could not run because the VM was not powered off. "
            "Fresh rebuild should prevent this; close VirtualBox windows for the client and rerun."
        )

    script_host = work_root / "lab_net_troubleshoot.sh"
    script_host.write_text(LAB_NET_TROUBLESHOOT_SCRIPT, encoding="utf-8")
    script_host.chmod(0o644)

    print("Enabling guest ttyS0 serial login in the VDI...")
    try:
        result = subprocess.run(
            [vc, "-a", vdi_linux]
            + [
                item
                for command in guest_serial_console_commands()
                for item in ("--run-command", command)
            ],
            capture_output=True,
            text=True,
            env=virt_env,
        )
        if result.returncode != 0:
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            if detail:
                print(detail)
            raise subprocess.CalledProcessError(result.returncode, result.args)
    except subprocess.CalledProcessError:
        raise RuntimeError(
            "Could not enable serial-getty@ttyS0 in the guest image. "
            "The client serial TCP socket may open, but WSL will not get a usable login prompt."
        )

    print("Injecting lab network troubleshoot helper and optional network packages...")
    try:
        result = subprocess.run(
            [
                vc,
                "-a",
                vdi_linux,
                "--install",
                "isc-dhcp-client,dnsutils,iputils-ping",
                "--copy-in",
                f"{script_host}:/usr/local/sbin",
                "--run-command",
                (
                    "mv /usr/local/sbin/lab_net_troubleshoot.sh "
                    "/usr/local/sbin/lab-net-troubleshoot && "
                    "chmod 0755 /usr/local/sbin/lab-net-troubleshoot"
                ),
            ],
            capture_output=True,
            text=True,
            env=virt_env,
        )
        if result.returncode != 0:
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            if detail:
                print(detail)
            raise subprocess.CalledProcessError(result.returncode, result.args)
    except subprocess.CalledProcessError:
        print(
            "[!] Optional lab package/helper injection failed, but ttyS0 serial login was enabled."
        )
        return True

    return True


def _poweroff_vm_for_vdi_edit(
    vboxmanage: str, vm_name: str, *, force_poweroff: bool
) -> bool:
    """Return True if the VM is off (or we powered it off)."""
    state = get_vm_state(vboxmanage, vm_name)
    if state not in ("running", "paused"):
        return True
    if not force_poweroff:
        print(
            f"[!] VM {vm_name!r} is {state}; power it off to modify the VDI, "
            "or pass --force-poweroff-for-vdi."
        )
        return False
    print(f"Powering off {vm_name} for VDI maintenance…")
    subprocess.run([vboxmanage, "controlvm", vm_name, "poweroff"], check=False)
    for _ in range(30):
        time.sleep(1)
        st = get_vm_state(vboxmanage, vm_name)
        if st in (None, "poweroff", "aborted"):
            return True
    print("[!] VM did not power off in time.")
    return False


def setup_client_vm(
    *,
    force_poweroff_for_vdi: bool = False,
    start_vm: bool = True,
    connect_serial: bool = True,
    recreate: bool = True,
    skip_vdi_prime: bool = False,
    archive_override: str | None = None,
) -> None:
    paths = get_system_paths(VM_NAME)
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError("VBoxManage not found. Install VirtualBox or add it to PATH.")

    vm_base = paths["vm_base"]
    vms_root = paths["vms_root"]
    download_dir = paths["downloads"]
    os.makedirs(download_dir, exist_ok=True)
    serial_endpoint = serial_endpoint_for_vbox(vboxmanage)
    vdi_wsl = os.path.join(vm_base, CLIENT_VDI_NAME)

    if recreate:
        print(f"Fresh rebuild: removing existing {VM_NAME!r} registration and disk first.")
        remove_existing_vm(
            vboxmanage,
            VM_NAME,
            vm_base,
            medium_path_for_vbox=wsl_to_windows_path(vdi_wsl)
            if paths["is_wsl"]
            else vdi_wsl,
        )
    existing_registered_vm = vm_is_registered(vboxmanage, VM_NAME)

    os.makedirs(vm_base, exist_ok=True)
    os.makedirs(vms_root, exist_ok=True)
    require_vdi_prime_tools(skip_prime=skip_vdi_prime)

    extract_dir = os.path.join(download_dir, "temp_osboxes_client_extract")

    # Paths passed to Windows VBoxManage must be Windows-style when running from WSL.
    # ``createvm --basefolder`` must be the *parent* ``VirtualBox VMs`` dir, not ``.../<VM_NAME>``.
    if paths["is_wsl"]:
        vdi_for_vbox = wsl_to_windows_path(vdi_wsl)
        vms_root_for_vbox = wsl_to_windows_path(vms_root)
    else:
        vdi_for_vbox = vdi_wsl
        vms_root_for_vbox = vms_root

    if existing_registered_vm and not os.path.exists(vdi_wsl):
        print(
            f"{VM_NAME} is already registered; no VDI found at {vdi_wsl}. "
            "Reusing the registered VM without downloading or extracting a new disk."
        )
    elif os.path.exists(vdi_wsl):
        print(f"VDI already exists at {vdi_wsl}; skipping download/extract.")
    else:
        archive_path = archive_override or os.path.join(download_dir, ARCHIVE_NAME)
        if archive_override:
            archive_path = os.path.abspath(os.path.expanduser(archive_path))
            if not os.path.isfile(archive_path):
                raise RuntimeError(f"--archive-path does not exist or is not a file: {archive_path}")
        elif not os.path.exists(archive_path):
            download_osboxes_archive(OSBOXES_URL, archive_path)
        else:
            print(f"Using OSBoxes archive at {archive_path}")

        print("Extracting VDI (requires p7zip: sudo apt install p7zip-full)...")
        validate_7z_archive(archive_path)
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        os.makedirs(extract_dir, exist_ok=True)
        try:
            subprocess.run(["7z", "x", archive_path, f"-o{extract_dir}", "-y"], check=True)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                "Failed to extract the OSBoxes archive. The archive may be corrupt or "
                "incomplete, or the file is not a valid 7z archive.\n"
                f"  Archive: {archive_path}\n"
                "Remove it and re-run the script, or pass a valid archive with "
                "--archive-path."
            ) from exc

        found_vdi: str | None = None
        for root, _, files in os.walk(extract_dir):
            for name in files:
                if name.lower().endswith((".vdi", ".vmdk")):
                    found_vdi = os.path.join(root, name)
                    break
            if found_vdi:
                break

        if not found_vdi:
            raise RuntimeError("No .vdi/.vmdk found inside OSBoxes archive.")
        shutil.copy2(found_vdi, vdi_wsl)
        shutil.rmtree(extract_dir, ignore_errors=True)

    work_root = Path(download_dir)

    if os.path.exists(vdi_wsl):
        serial_console_ready = prime_client_vdi_for_intnet_lab(
            vdi_wsl,
            vboxmanage,
            VM_NAME,
            work_root,
            force_poweroff=force_poweroff_for_vdi,
            skip_prime=skip_vdi_prime,
        )
    else:
        serial_console_ready = False
        print("[!] Skipping VDI priming because no client VDI was found.")

    if not serial_console_ready:
        raise RuntimeError(
            "Client VM serial console was not confirmed during offline VDI priming. "
            "Refusing to boot a client that WSL cannot control over ttyS0."
        )

    if not vm_is_registered(vboxmanage, VM_NAME):
        existing_vbox = resolve_vbox_settings_path(vm_base, VM_NAME)
        if existing_vbox:
            reg_path = (
                wsl_to_windows_path(existing_vbox)
                if paths["is_wsl"]
                else existing_vbox
            )
            print(f"Registering existing settings file: {existing_vbox}")
            run_vboxmanage(vboxmanage, ["registervm", reg_path])
        else:
            run_vboxmanage(
                vboxmanage,
                [
                    "createvm",
                    "--name",
                    VM_NAME,
                    "--ostype",
                    "Ubuntu_64",
                    "--basefolder",
                    vms_root_for_vbox,
                    "--register",
                ],
            )

    if get_vm_state(vboxmanage, VM_NAME) == "running":
        raise RuntimeError(f"{VM_NAME} is already running after rebuild; refusing to reuse it.")

    # NIC1 = LAN leg behind OpenWrt (DHCP from OpenWrt br-lan)
    print(
        f"Networking: NIC1 → internal network {LAN_INTNET_NAME!r} "
        f"(OpenWrt router LAN is NIC1 on the same intnet; start router before client DHCP)."
    )
    run_vboxmanage(
        vboxmanage,
        [
            "modifyvm",
            VM_NAME,
            "--memory",
            "4096",
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

    if existing_registered_vm:
        print(f"{VM_NAME} is already registered; keeping existing storage attachment.")
    else:
        # SATA controller + disk (ignore error if controller already exists)
        try:
            run_vboxmanage(
                vboxmanage,
                ["storagectl", VM_NAME, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci"],
            )
        except RuntimeError as exc:
            if "already exists" in str(exc).lower():
                pass
            else:
                raise

        try:
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
        except RuntimeError as exc:
            if (
                "already attached" in str(exc).lower()
                or "vbox_e_invalid_object_state" in str(exc).lower()
            ):
                print("Disk is already attached; keeping existing storage attachment.")
            else:
                raise

    print(
        f"\nDone. Start the OpenWrt VM first, then start {VM_NAME}.\n"
        "\n"
        "--- Lab networking (no guest Internet required) ---\n"
        "This script should have **pre-installed** dhclient/dig on the **disk from WSL**.\n"
        "After login run:   lab-net-troubleshoot\n"
        "That script renews DHCP and prints static-IP fallback commands if OpenWrt has no DHCP.\n"
        "Only if the guest **does** have Internet and tools are missing:\n"
        f"  sudo apt update && {IN_GUEST_INSTALL_ISC_DHCP_CLIENT}\n"
        "\n"
        "--- If ``ip -4 route show default`` prints nothing ---\n"
        "There is no default IPv4 route (usually DHCP from OpenWrt never ran or failed).\n"
        "• Start the **OpenWrt** VM **before** this client; router **LAN (NIC1)** and this client **NIC1** must use intnet ``openwrt-lan``.\n"
        "• In OpenWrt (LuCI): LAN = static or DHCP **server** on br-lan, firewall zone LAN→WAN allowed.\n"
        "• In the client: ``ip -br a`` and ``ip route`` — confirm an address on the LAN interface.\n"
        "• Run ``lab-net-troubleshoot`` first; only then try ``sudo networkctl renew <iface>``.\n"
        "• Manual test route: ``sudo ip route add default via 192.168.1.1 dev <iface>`` (use your OpenWrt LAN IP).\n"
        "\n"
    )
    print(serial_console_instructions(vboxmanage, serial_endpoint))
    if start_vm:
        state = get_vm_state(vboxmanage, VM_NAME)
        if state == "running":
            raise RuntimeError(f"{VM_NAME} is already running before startvm; refusing to reuse it.")
        else:
            run_vboxmanage(vboxmanage, ["startvm", VM_NAME, "--type", "headless"])
        if connect_serial:
            time.sleep(2)
            connect_serial_console(vboxmanage, serial_endpoint)
    else:
        print("Not starting VM (--no-start).")
        if connect_serial:
            connect_serial_console(vboxmanage, serial_endpoint)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Freshly rebuild the OpenWrt LAN client VM for headless serial bash.",
    )
    ap.add_argument(
        "--force-poweroff-for-vdi",
        action="store_true",
        help="If the VM is running, power it off so virt-customize can modify the VDI (priming).",
    )
    ap.add_argument(
        "--no-start",
        action="store_true",
        help="Configure the VM but do not start it.",
    )
    ap.add_argument(
        "--recreate",
        action="store_true",
        help="Delete and rebuild the client VM/disk. This is now the default for normal setup.",
    )
    ap.add_argument(
        "--skip-vdi-prime",
        action="store_true",
        help="Debug-only; normal setup rejects this because ttyS0 serial login is required.",
    )
    ap.add_argument(
        "--archive-path",
        help=(
            "Use an already downloaded OSBoxes 24.04 7z archive instead of downloading "
            f"{ARCHIVE_NAME} into ~/Downloads."
        ),
    )
    ap.add_argument(
        "--connect-serial",
        action="store_true",
        help="Attach this terminal to the serial console after starting the VM (default).",
    )
    ap.add_argument(
        "--no-connect-serial",
        action="store_true",
        help="Create/start the VM but do not attach this terminal to the serial console.",
    )
    ap.add_argument(
        "--serial-only",
        action="store_true",
        help="Do not create or modify the VM; just attach to the existing serial console.",
    )
    ap.add_argument(
        "--serial-check-only",
        action="store_true",
        help="Probe the serial TCP endpoint until guest output appears; do not open interactive mode.",
    )
    ap.add_argument(
        "--serial-ready-timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for guest serial output with --serial-check-only (default: 30).",
    )
    ap.add_argument(
        "--force-interactive-serial",
        action="store_true",
        help="Open the raw serial bridge even when the guest emits no serial output.",
    )
    ap.add_argument(
        "--refresh-live-serial",
        action="store_true",
        help=(
            "Manually bounce the running VM's UART backend before serial attach/check. "
            "This briefly suspends/resumes the guest; avoid during boot."
        ),
    )
    ns = ap.parse_args()
    if ns.serial_check_only:
        paths = get_system_paths(VM_NAME)
        vboxmanage = find_vboxmanage(paths)
        if not vboxmanage:
            raise RuntimeError("VBoxManage not found. Install VirtualBox or add it to PATH.")
        serial_endpoint = serial_endpoint_for_vbox(vboxmanage)
        if get_vm_state(vboxmanage, VM_NAME) != "running":
            print(f"[serial readiness] {VM_NAME} is not running.")
            raise SystemExit(1)
        if vboxmanage_targets_windows(vboxmanage):
            if ns.refresh_live_serial:
                refresh_live_serial_endpoint(vboxmanage, serial_endpoint)
            ready = wait_for_tcp_serial_guest_output(
                SERIAL_TCP_HOST,
                int(serial_endpoint),
                timeout_s=ns.serial_ready_timeout,
            )
            raise SystemExit(0 if ready else 1)
        print("[serial readiness] Native Linux socket mode does not support TCP readiness probing.")
        raise SystemExit(0)

    if ns.serial_only:
        paths = get_system_paths(VM_NAME)
        vboxmanage = find_vboxmanage(paths)
        if not vboxmanage:
            raise RuntimeError("VBoxManage not found. Install VirtualBox or add it to PATH.")
        serial_endpoint = serial_endpoint_for_vbox(vboxmanage)
        if ns.refresh_live_serial and get_vm_state(vboxmanage, VM_NAME) == "running":
            refresh_live_serial_endpoint(vboxmanage, serial_endpoint)
        connected = connect_serial_console(
            vboxmanage,
            serial_endpoint,
            force_interactive=ns.force_interactive_serial,
        )
        raise SystemExit(0 if connected else 1)

    setup_client_vm(
        force_poweroff_for_vdi=ns.force_poweroff_for_vdi,
        start_vm=not ns.no_start,
        connect_serial=ns.connect_serial or (not ns.no_start and not ns.no_connect_serial),
        recreate=True,
        skip_vdi_prime=ns.skip_vdi_prime,
        archive_override=ns.archive_path,
    )
