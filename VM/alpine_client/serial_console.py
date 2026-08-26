"""VirtualBox serial console attach for the Alpine lab client."""

from __future__ import annotations

import contextlib
import os
import platform
import select
import socket
import sys
import threading
import time
from pathlib import Path

from detections.common.common_vm import (
    SERIAL_BAUD,
    SERIAL_PTY_LINK_PATH,
    SERIAL_TCP_HOST,
    run_vboxmanage,
    serial_tcp_host_candidates,
    vboxmanage_targets_windows,
)
from VM.alpine_client.client_config import (
    ALPINE_SERIAL_TCP_PORT,
    CREATE_SCRIPT_NAME,
    VM_NAME,
)

__all__ = [
    "configure_serial_endpoint",
    "connect_serial_console",
    "connect_tcp_serial_console",
    "nudge_alpine_boot_menu",
    "serial_console_instructions",
]


def serial_console_instructions(vboxmanage: str, endpoint: str) -> str:
    if vboxmanage_targets_windows(vboxmanage):
        hosts = ", ".join(serial_tcp_host_candidates(SERIAL_TCP_HOST))
        return (
            "--- Serial console TCP endpoint ---\n"
            f"VirtualBox exposes COM1 as TCP port {endpoint} on the Windows host.\n"
            f"From WSL, connect to one of: {hosts}\n"
            "To attach to an already-running VM from WSL:\n"
            f"  ./{CREATE_SCRIPT_NAME} --serial-only\n"
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
    print("Native Linux socket serial connection mode is ready. Connect using host-side socket helper.")
    return True


def nudge_alpine_boot_menu(*, rounds: int = 8, interval_s: float = 1.0) -> None:
    """Send Enter a few times on COM1 in case the boot menu is still waiting.

    Primary fix is unattended extlinux (TOTALTIMEOUT + DEFAULT label). This is a
    short, non-interactive safety net so create never depends on a human keypress.
    """
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
