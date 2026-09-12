#!/usr/bin/env python3
"""Host-side manager for direct QEMU/KVM lab VMs.

Examples:

    python3 VM/qemu_manager.py              # interactive menu
    python3 VM/qemu_manager.py list
    python3 VM/qemu_manager.py status
    python3 VM/qemu_manager.py stop Test_Router
    python3 VM/qemu_manager.py kill --all -y
    python3 VM/qemu_manager.py serial Test_Clienta
    python3 VM/qemu_manager.py show Test_Clientk

Lab serial ports: router 2324, clienta 2325, clientk 2326, target 2327.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_qemu import (
    default_serial_port_for_vm,
    is_qemu_vm_running,
    lab_vms_root,
    stop_qemu_vm,
)
from detections.common.common_vm import (
    SERIAL_TCP_HOST,
    TEST_CLIENTA_VM_NAME,
    TEST_CLIENTK_VM_NAME,
    TEST_ROUTER_VM_NAME,
    TEST_TARGET_VM_NAME,
)

LAB_VM_NAMES = (TEST_ROUTER_VM_NAME, TEST_CLIENTA_VM_NAME, TEST_CLIENTK_VM_NAME, TEST_TARGET_VM_NAME)

_NAME_RE = re.compile(r"(?:^|\s)-name\s+(\S+)")
_MEM_RE = re.compile(r"(?:^|\s)-m\s+(\S+)")
_SMP_RE = re.compile(r"(?:^|\s)-smp\s+(\S+)")
_DISK_RE = re.compile(r"(?:^|\s)-(?:hda|cdrom)\s+(\S+)|(?:^|\s|-drive\s+)file=([^,\s]+)")
_HOSTFWD_RE = re.compile(r"hostfwd=([^,\s]+)")
_MONITOR_RE = re.compile(r"(?:^|\s)-(?:monitor|qmp)\s+unix:([^,\s]+)")
_SERIAL_TCP_RE = re.compile(r"-serial\s+tcp:([^,\s]+)")
_VNC_RE = re.compile(r"(?:^|\s)-vnc\s+(\S+)")


@dataclass(frozen=True)
class QemuInstance:
    pid: int
    name: str
    cmdline: str
    memory: str
    smp: str
    disk: str
    network: str
    display: str
    monitor_socket: str | None
    serial_tcp: str | None

    @property
    def label(self) -> str:
        return self.name


def _ps_qemu_rows() -> list[tuple[int, str]]:
    """Return (pid, cmdline) for qemu-system processes."""
    rows: list[tuple[int, str]] = []
    try:
        proc = subprocess.run(
            ["ps", "-eo", "pid=,args="],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"Unable to list processes (ps): {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "ps failed").strip())
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or "qemu-system" not in line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        rows.append((pid, parts[1]))
    return rows


def _is_lab_or_named_qemu(cmdline: str) -> bool:
    """Drop virt-customize appliance helpers; keep named lab/user VMs."""
    if _NAME_RE.search(cmdline):
        return True
    if "libguestfs" in cmdline or "guestfs" in cmdline:
        return False
    if "appliance" in cmdline and "-display none" in cmdline:
        return False
    return True


def _parse_instance(pid: int, cmdline: str) -> QemuInstance:
    name_m = _NAME_RE.search(cmdline)
    name = name_m.group(1) if name_m else f"[unnamed pid {pid}]"

    mem_m = _MEM_RE.search(cmdline)
    memory = mem_m.group(1) if mem_m else "?"

    smp_m = _SMP_RE.search(cmdline)
    smp = smp_m.group(1) if smp_m else "1"

    disk = "n/a"
    for m in _DISK_RE.finditer(cmdline):
        candidate = m.group(1) or m.group(2)
        if not candidate:
            continue
        # Prefer lab qcow disks over appliance/root helpers.
        if "appliance" in candidate or candidate.endswith("/root"):
            continue
        disk = candidate
        if candidate.endswith((".qcow2", ".raw", ".img", ".vdi")):
            break

    fwds = _HOSTFWD_RE.findall(cmdline)
    if fwds:
        network = "portfwd " + ", ".join(fwds)
    elif " tap," in cmdline or "tap," in cmdline or "ifname=tap-" in cmdline:
        network = "tap/bridge"
    elif re.search(r"(?:^|\s)-netdev\s+user", cmdline) or "id=wan" in cmdline:
        network = "user/SLIRP"
    else:
        network = "default/none"

    if "-display none" in cmdline or "-nographic" in cmdline:
        display = "headless"
    else:
        vnc_m = _VNC_RE.search(cmdline)
        if vnc_m:
            display = f"vnc {vnc_m.group(1)}"
        elif "-display gtk" in cmdline:
            display = "gtk"
        elif "-display sdl" in cmdline:
            display = "sdl"
        else:
            display = "gui/default"

    mon_m = _MONITOR_RE.search(cmdline)
    monitor = mon_m.group(1) if mon_m else None

    serial_m = _SERIAL_TCP_RE.search(cmdline)
    serial_tcp = serial_m.group(1) if serial_m else None
    if serial_tcp is None and name in LAB_VM_NAMES:
        serial_tcp = f"{SERIAL_TCP_HOST}:{default_serial_port_for_vm(name)}"

    return QemuInstance(
        pid=pid,
        name=name,
        cmdline=cmdline,
        memory=memory,
        smp=smp,
        disk=disk,
        network=network,
        display=display,
        monitor_socket=monitor,
        serial_tcp=serial_tcp,
    )


def list_instances(*, include_guestfs: bool = False) -> list[QemuInstance]:
    out: list[QemuInstance] = []
    for pid, cmdline in _ps_qemu_rows():
        if not include_guestfs and not _is_lab_or_named_qemu(cmdline):
            continue
        out.append(_parse_instance(pid, cmdline))
    rank = {n: i for i, n in enumerate(LAB_VM_NAMES)}
    out.sort(key=lambda i: (rank.get(i.name, 100), i.name, i.pid))
    return out


def resolve_target(token: str, instances: list[QemuInstance] | None = None) -> QemuInstance:
    """Resolve by 1-based index, exact name, or unique prefix."""
    instances = instances if instances is not None else list_instances()
    if not instances:
        raise RuntimeError("No running QEMU VMs found.")
    if token.isdigit():
        idx = int(token)
        if idx < 1 or idx > len(instances):
            raise RuntimeError(f"Index {idx} out of range (1-{len(instances)}).")
        return instances[idx - 1]
    exact = [i for i in instances if i.name == token]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise RuntimeError(f"Multiple VMs named {token!r}; use index from `list`.")
    prefix = [i for i in instances if i.name.lower().startswith(token.lower())]
    if len(prefix) == 1:
        return prefix[0]
    if len(prefix) > 1:
        names = ", ".join(i.name for i in prefix)
        raise RuntimeError(f"Ambiguous name {token!r}: {names}")
    raise RuntimeError(f"No running VM matching {token!r}. Try `list`.")


def format_table(instances: list[QemuInstance]) -> str:
    if not instances:
        return "No running QEMU virtual machines found."
    lines = [
        "=" * 78,
        "Active QEMU VM instances",
        "=" * 78,
    ]
    for idx, inst in enumerate(instances, start=1):
        lines.append(
            f"{idx:2d}) {inst.name:<22} PID {inst.pid:<7} CPU {inst.smp:<4} RAM {inst.memory}"
        )
        lines.append(f"    disk    : {inst.disk}")
        lines.append(f"    config  : net={inst.network} | display={inst.display}")
        if inst.serial_tcp:
            lines.append(f"    serial  : tcp:{inst.serial_tcp}")
        if inst.monitor_socket:
            lines.append(f"    monitor : unix:{inst.monitor_socket}")
        lines.append("-" * 78)
    return "\n".join(lines)


def cmd_list(_: argparse.Namespace) -> int:
    print(format_table(list_instances()))
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    """Show known lab VMs (running or stopped) plus any other QEMU processes."""
    running = {i.name: i for i in list_instances()}
    print("=" * 78)
    print("Lab VMs")
    print("=" * 78)
    root = Path(lab_vms_root())
    for name in LAB_VM_NAMES:
        port = default_serial_port_for_vm(name)
        alive = is_qemu_vm_running(name) or name in running
        inst = running.get(name)
        state = "running" if alive else "stopped"
        pid = f"pid {inst.pid}" if inst else "-"
        disk_dir = root / name
        print(f"  {name:<16} {state:<8} {pid:<12} serial {SERIAL_TCP_HOST}:{port}")
        if disk_dir.is_dir():
            print(f"    {'':16} path {disk_dir}")
    extras = [i for i in running.values() if i.name not in LAB_VM_NAMES]
    if extras:
        print()
        print("Other QEMU processes")
        print("-" * 78)
        for inst in extras:
            print(f"  {inst.name:<16} running  pid {inst.pid}")
    print("=" * 78)
    return 0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _stop_pid(pid: int, name: str, *, force: bool, timeout_s: float = 10.0) -> None:
    if force:
        print(f"Force killing {name} (pid {pid})...")
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            print(f"  already gone.")
            return
        time.sleep(0.3)
        if _pid_alive(pid):
            raise RuntimeError(f"Failed to kill pid {pid}")
        print(f"  killed.")
        return

    print(f"Stopping {name} (pid {pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print("  already gone.")
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            print("  stopped.")
            return
        time.sleep(0.25)
    print(f"  still running after {timeout_s:.0f}s; sending SIGKILL...")
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        print("  stopped.")
        return
    time.sleep(0.3)
    if _pid_alive(pid):
        raise RuntimeError(f"Failed to kill pid {pid}")
    print("  killed.")


def cmd_stop(args: argparse.Namespace) -> int:
    if args.all:
        instances = list_instances()
        if not instances:
            print("No running QEMU VMs.")
            return 0
        for inst in instances:
            if inst.name in LAB_VM_NAMES and not args.force:
                stop_qemu_vm(inst.name)
            else:
                _stop_pid(inst.pid, inst.name, force=False)
        return 0
    if not args.target:
        raise SystemExit("stop requires a VM name/index or --all")
    inst = resolve_target(args.target)
    if inst.name in LAB_VM_NAMES:
        stop_qemu_vm(inst.name)
    else:
        _stop_pid(inst.pid, inst.name, force=False)
    return 0


def cmd_kill(args: argparse.Namespace) -> int:
    if args.all:
        instances = list_instances()
        if not instances:
            print("No running QEMU VMs.")
            return 0
        if not args.yes:
            reply = input(f"Force kill {len(instances)} VM(s)? [y/N] ").strip().lower()
            if reply not in ("y", "yes"):
                print("Cancelled.")
                return 0
        for inst in instances:
            _stop_pid(inst.pid, inst.name, force=True)
        return 0
    if not args.target:
        raise SystemExit("kill requires a VM name/index or --all")
    inst = resolve_target(args.target)
    if not args.yes:
        reply = input(f"Force kill {inst.name} (pid {inst.pid})? [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            print("Cancelled.")
            return 0
    _stop_pid(inst.pid, inst.name, force=True)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    inst = resolve_target(args.target)
    print(f"name     : {inst.name}")
    print(f"pid      : {inst.pid}")
    print(f"cpu/ram  : {inst.smp} / {inst.memory}")
    print(f"disk     : {inst.disk}")
    print(f"network  : {inst.network}")
    print(f"display  : {inst.display}")
    print(f"serial   : {inst.serial_tcp or '-'}")
    print(f"monitor  : {inst.monitor_socket or '-'}")
    print("-" * 78)
    print(inst.cmdline)
    return 0


def _attach_serial_tcp(endpoint: str) -> int:
    """Attach to a QEMU TCP serial server (lab VMs use 127.0.0.1:2324-2326)."""
    import select
    import termios
    import tty

    if ":" not in endpoint:
        raise RuntimeError(f"Bad serial endpoint: {endpoint}")
    host, _, port_s = endpoint.rpartition(":")
    port = int(port_s)
    print(f"Connecting to serial {host}:{port}")
    print("  Ctrl-] disconnects. Press Enter to wake a login prompt.")
    print("-" * 78)
    which = subprocess.run(
        ["bash", "-lc", "command -v socat"],
        capture_output=True,
        text=True,
        check=False,
    )
    if which.returncode == 0 and which.stdout.strip():
        return subprocess.call(
            ["socat", "-,raw,echo=0,escape=0x1d", f"TCP:{host}:{port}"]
        )

    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(0.2)
    stdin_fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(stdin_fd)
    except termios.error:
        old = None
    try:
        if old is not None:
            tty.setraw(stdin_fd)
        while True:
            r, _, _ = select.select([stdin_fd, sock], [], [], 0.5)
            if stdin_fd in r:
                data = os.read(stdin_fd, 1024)
                if not data or data == b"\x1d":  # Ctrl-]
                    break
                sock.sendall(data)
            if sock in r:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
    except KeyboardInterrupt:
        print()
    finally:
        if old is not None:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old)
        sock.close()
    return 0


def _attach_monitor_unix(path: str) -> int:
    if not Path(path).is_socket() and not Path(path).exists():
        raise RuntimeError(f"Monitor socket not found: {path}")
    print(f"Connecting to monitor {path} (type 'quit' to leave)...")
    if subprocess.run(["bash", "-lc", "command -v socat"], capture_output=True).returncode == 0:
        return subprocess.call(["socat", "-", f"UNIX-CONNECT:{path}"])
    if subprocess.run(["bash", "-lc", "command -v nc"], capture_output=True).returncode == 0:
        return subprocess.call(["nc", "-U", path])
    raise RuntimeError("Need socat or nc to attach to a UNIX monitor socket.")


def cmd_serial(args: argparse.Namespace) -> int:
    inst = resolve_target(args.target)
    if args.monitor:
        if not inst.monitor_socket:
            raise RuntimeError(
                f"{inst.name} has no -monitor unix:… socket. "
                "Lab VMs use TCP serial instead — omit --monitor."
            )
        return _attach_monitor_unix(inst.monitor_socket)
    endpoint = inst.serial_tcp
    if not endpoint:
        # Lab name fallback even if cmdline parse missed it.
        if inst.name in LAB_VM_NAMES:
            endpoint = f"{SERIAL_TCP_HOST}:{default_serial_port_for_vm(inst.name)}"
        else:
            raise RuntimeError(
                f"{inst.name} has no TCP serial endpoint. "
                "Lab ports: router 2324, clienta 2325, clientk 2326."
            )
    return _attach_serial_tcp(endpoint)


def cmd_interactive(_: argparse.Namespace) -> int:
    instances = list_instances()
    print(format_table(instances))
    if not instances:
        return 0
    print("  A) Stop ALL")
    print("  K) Force kill ALL")
    print("  Q) Quit")
    print("-" * 78)
    choice = input(f"Select VM (1-{len(instances)}) or A/K/Q: ").strip()
    if not choice or choice.lower() == "q":
        print("Exiting.")
        return 0
    if choice.lower() == "a":
        return cmd_stop(argparse.Namespace(target=None, all=True, force=False))
    if choice.lower() == "k":
        return cmd_kill(argparse.Namespace(target=None, all=True, yes=False))
    try:
        inst = resolve_target(choice, instances)
    except RuntimeError as exc:
        print(exc)
        return 1

    print()
    print(f"Selected: {inst.name} (pid {inst.pid})")
    print("  1) Graceful stop")
    print("  2) Force kill")
    print("  3) Serial console (TCP)")
    print("  4) Show full command line")
    print("  5) Cancel")
    action = input("Choose action (1-5): ").strip()
    if action == "1":
        return cmd_stop(argparse.Namespace(target=str(instances.index(inst) + 1), all=False, force=False))
    if action == "2":
        return cmd_kill(argparse.Namespace(target=str(instances.index(inst) + 1), all=False, yes=False))
    if action == "3":
        return cmd_serial(argparse.Namespace(target=str(instances.index(inst) + 1), monitor=False))
    if action == "4":
        return cmd_show(argparse.Namespace(target=str(instances.index(inst) + 1)))
    print("Cancelled.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="qemu_manager.py",
        description="List and manage Overdrive QEMU/KVM VMs from the host (no libvirt).",
    )
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("list", help="List running QEMU VMs")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("status", help="Lab VM status (running/stopped + serial ports)")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("stop", help="Graceful stop (SIGTERM)")
    sp.add_argument("target", nargs="?", help="VM name, prefix, or list index")
    sp.add_argument("--all", action="store_true", help="Stop every running QEMU VM")
    sp.set_defaults(func=cmd_stop, force=False)

    sp = sub.add_parser("kill", help="Force kill (SIGKILL)")
    sp.add_argument("target", nargs="?", help="VM name, prefix, or list index")
    sp.add_argument("--all", action="store_true", help="Kill every running QEMU VM")
    sp.add_argument("-y", "--yes", action="store_true", help="Do not ask for confirmation")
    sp.set_defaults(func=cmd_kill)

    sp = sub.add_parser("show", help="Show VM details and full qemu argv")
    sp.add_argument("target", help="VM name, prefix, or list index")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("serial", help="Attach to VM serial console (TCP)")
    sp.add_argument("target", help="VM name, prefix, or list index")
    sp.add_argument(
        "--monitor",
        action="store_true",
        help="Attach to QEMU monitor UNIX socket instead of serial",
    )
    sp.set_defaults(func=cmd_serial)

    sp = sub.add_parser("interactive", help="Interactive menu (default)")
    sp.set_defaults(func=cmd_interactive)

    return p


def main(argv: list[str] | None = None) -> int:
    if sys.platform == "win32":
        print(
            "Run this inside WSL (QEMU lab host), e.g.:\n"
            "  wsl -e python3 /mnt/c/code/overdrive/VM/qemu_manager.py list",
            file=sys.stderr,
        )
        return 2
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        return cmd_interactive(argparse.Namespace())
    try:
        return int(args.func(args))
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
