"""QEMU serial console attach for the Metasploitable target."""

from __future__ import annotations

import contextlib
import os
import platform
import select
import socket
import sys
import time

from detections.common.common_vm import (
    SERIAL_BAUD,
    SERIAL_TCP_HOST,
    serial_tcp_host_candidates,
)
from VM.metasploitable_target.target_config import (
    CREATE_SCRIPT_NAME,
    TARGET_SERIAL_TCP_PORT,
    VM_NAME,
)

__all__ = [
    "configure_serial_endpoint",
    "connect_serial_console",
    "serial_console_instructions",
]


def serial_console_instructions(endpoint: str) -> str:
    hosts = ", ".join(serial_tcp_host_candidates(SERIAL_TCP_HOST))
    return (
        "--- Serial console TCP endpoint ---\n"
        f"QEMU exposes COM1 as TCP port {endpoint} on the host.\n"
        f"From WSL, connect to one of: {hosts}\n"
        "Stock login: msfadmin / msfadmin\n"
        f"  ./{CREATE_SCRIPT_NAME} --serial-only\n"
    )


def configure_serial_endpoint(endpoint: str) -> None:
    print(f"Serial console: COM1 -> TCP {SERIAL_TCP_HOST}:{endpoint} ({SERIAL_BAUD} baud).")


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
        tty_fd = None
    try:
        yield tty_fd if tty_fd is not None else (sys.stdin.fileno() if sys.stdin.isatty() else None)
    finally:
        if tty_fd is not None:
            os.close(tty_fd)


def connect_serial_console(endpoint: str, *, force_interactive: bool = False) -> None:
    _ = force_interactive
    host = SERIAL_TCP_HOST
    port = int(endpoint)
    print(f"[overdrive] Attaching to {VM_NAME} serial {host}:{port} (Ctrl-] to detach)")
    print("Stock credentials: msfadmin / msfadmin")
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(0.25)
    # Wake console / GRUB
    try:
        sock.sendall(b"\r")
    except OSError:
        pass
    with _serial_input_fd() as input_fd:
        with _raw_stdin_for_serial(input_fd):
            try:
                while True:
                    readers = [sock]
                    if input_fd is not None:
                        readers.append(input_fd)
                    ready, _, _ = select.select(readers, [], [], 0.5)
                    if sock in ready:
                        try:
                            data = sock.recv(4096)
                        except socket.timeout:
                            data = b""
                        if not data:
                            print("\n[overdrive] Serial connection closed.")
                            break
                        os.write(sys.stdout.fileno(), data)
                    if input_fd is not None and input_fd in ready:
                        data = os.read(input_fd, 1024)
                        if not data or data == b"\x1d":
                            break
                        sock.sendall(data)
            except KeyboardInterrupt:
                print()
            finally:
                sock.close()
