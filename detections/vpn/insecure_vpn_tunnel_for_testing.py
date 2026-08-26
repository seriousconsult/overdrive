#!/usr/bin/env python3
"""Create an intentionally insecure local VPN-like test tunnel.

Default mode is synthetic and kernel-safe:

  - creates a local interface named ``wg-overdrive`` with MTU 1420
  - assigns 10.77.0.2/24 to it
  - starts a tiny UDP echo responder on port 51820

This is not a product VPN, does not encrypt traffic, and does not change the
default route. Its purpose is detection calibration: run detections with this
test artifact down, then up, and compare which local VPN signals change.

There is an opt-in ``--real-wireguard`` mode for systems where the WireGuard
kernel module is known to be safe. Do not use that mode on the Alpine client if
it triggers kernel soft-lockups.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CLIENT_IFACE = "wg-overdrive"
DEFAULT_PEER_IFACE = "wg-od-peer"
DEFAULT_NETNS = "overdrive-wg"
DEFAULT_VETH_PEER = "odwg-peer"
DEFAULT_CLIENT_ADDR = "10.77.0.2/24"
DEFAULT_MTU = 1420
DEFAULT_UDP_PORT = 51820
STATE_DIR = Path("/tmp/overdrive-insecure-vpn-tunnel")
PID_FILE = STATE_DIR / "udp_responder.pid"


@dataclass(frozen=True)
class LabConfig:
    client_iface: str
    peer_iface: str
    netns: str
    veth_peer: str
    client_addr: str
    mtu: int
    udp_port: int
    real_wireguard: bool


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    input_text: str | None = None,
    timeout: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        input=input_text,
        capture_output=capture,
        text=True,
        check=False,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        rendered = " ".join(cmd)
        detail = ((proc.stdout or "") + (proc.stderr or "")).strip()
        raise RuntimeError(f"command failed ({proc.returncode}): {rendered}\n{detail}")
    return proc


def output(cmd: list[str], *, check: bool = True) -> str:
    return run(cmd, check=check, capture=True).stdout.strip()


def require_root() -> None:
    geteuid = getattr(os, "geteuid", None)
    if not geteuid or geteuid() != 0:
        raise RuntimeError(
            "run as root, for example: sudo ./insecure_vpn_tunnel_for_testing.py up"
        )


def require_tools(*, real_wireguard: bool) -> None:
    tools = ["ip"]
    if real_wireguard:
        tools.append("wg")
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        extra = " and wireguard-tools" if real_wireguard else ""
        raise RuntimeError(
            f"missing required tool(s): {', '.join(missing)}. Install iproute2{extra}."
        )


def link_exists(name: str, *, netns: str | None = None) -> bool:
    cmd = ["ip"]
    if netns:
        cmd += ["netns", "exec", netns]
    cmd += ["link", "show", "dev", name]
    return run(cmd, check=False, capture=True).returncode == 0


def netns_exists(name: str) -> bool:
    names = output(["ip", "netns", "list"], check=False).splitlines()
    return any(line.split()[0] == name for line in names if line.strip())


def cleanup(cfg: LabConfig) -> None:
    stop_udp_responder()
    if link_exists(cfg.client_iface):
        run(["ip", "link", "del", "dev", cfg.client_iface], check=False)
    if link_exists(cfg.veth_peer):
        run(["ip", "link", "del", "dev", cfg.veth_peer], check=False)
    if netns_exists(cfg.netns):
        run(["ip", "netns", "del", cfg.netns], check=False)


def setup_synthetic(cfg: LabConfig) -> None:
    require_root()
    require_tools(real_wireguard=False)
    cleanup(cfg)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Prefer veth because it is commonly available without loading a special
    # dummy module. The interface name is intentionally wg-* for detection tests.
    run(
        [
            "ip",
            "link",
            "add",
            cfg.client_iface,
            "type",
            "veth",
            "peer",
            "name",
            cfg.veth_peer,
        ]
    )
    run(["ip", "addr", "add", cfg.client_addr, "dev", cfg.client_iface])
    run(["ip", "link", "set", "dev", cfg.client_iface, "mtu", str(cfg.mtu), "up"])
    run(["ip", "link", "set", "dev", cfg.veth_peer, "mtu", str(cfg.mtu), "up"])
    start_udp_responder(cfg.udp_port)


def start_udp_responder(port: int) -> None:
    stop_udp_responder()
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    code = textwrap.dedent(
        f"""
        import os
        import signal
        import socket
        import sys

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", {port}))

        def stop(_signum, _frame):
            sock.close()
            sys.exit(0)

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while True:
            data, addr = sock.recvfrom(2048)
            sock.sendto(data or b"overdrive", addr)
        """
    ).strip()
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    PID_FILE.write_text(str(proc.pid), encoding="utf-8")
    time.sleep(0.2)
    if proc.poll() is not None:
        raise RuntimeError(f"UDP responder on port {port} exited immediately")


def stop_udp_responder() -> None:
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.2)
    except ProcessLookupError:
        pass
    except OSError:
        pass
    try:
        PID_FILE.unlink()
    except OSError:
        pass


def wg_keypair(label: str) -> tuple[Path, str]:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_path = STATE_DIR / f"{label}.key"
    private = output(["wg", "genkey"])
    private_path.write_text(private + "\n", encoding="utf-8")
    private_path.chmod(0o600)
    proc = run(["wg", "pubkey"], input_text=private + "\n", capture=True)
    public = proc.stdout.strip()
    if not public:
        raise RuntimeError(f"wg pubkey returned no public key for {label}")
    return private_path, public


def setup_real_wireguard(cfg: LabConfig) -> None:
    require_root()
    require_tools(real_wireguard=True)
    if shutil.which("modprobe"):
        run(["modprobe", "wireguard"], check=False)
    cleanup(cfg)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    client_key, _client_pub = wg_keypair("client")
    run(["ip", "link", "add", cfg.client_iface, "type", "wireguard"])
    run(
        [
            "wg",
            "set",
            cfg.client_iface,
            "private-key",
            str(client_key),
            "listen-port",
            str(cfg.udp_port),
        ]
    )
    run(["ip", "addr", "add", cfg.client_addr, "dev", cfg.client_iface])
    run(["ip", "link", "set", "dev", cfg.client_iface, "mtu", str(cfg.mtu), "up"])


def udp_responder_running() -> bool:
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def status(cfg: LabConfig) -> int:
    print("=" * 60)
    print("Overdrive insecure VPN-like test tunnel")
    print("=" * 60)
    print("Purpose: detection calibration only; not secure, encrypted, or remote-exit.")
    print("Default route: unchanged.")
    print(f"Mode: {'real WireGuard (opt-in)' if cfg.real_wireguard else 'synthetic safe default'}")
    print()

    client_up = link_exists(cfg.client_iface)
    udp_up = udp_responder_running()
    print(f"client interface {cfg.client_iface}: {'present' if client_up else 'absent'}")
    print(f"UDP responder 0.0.0.0:{cfg.udp_port}: {'running' if udp_up else 'absent'}")

    if client_up:
        print("\n[ip link]")
        print(output(["ip", "-o", "link", "show", "dev", cfg.client_iface], check=False))
        print("\n[ip addr]")
        print(output(["ip", "-o", "addr", "show", "dev", cfg.client_iface], check=False))
        if shutil.which("wg"):
            wg_out = output(["wg", "show", cfg.client_iface], check=False)
            if wg_out:
                print("\n[wg show]")
                print(wg_out)
        print("\n[route check]")
        print(output(["ip", "route", "show", "default"], check=False) or "(no default route)")

    print("\nDetection checks to compare with tunnel up/down:")
    print("  ./tunnel_interface.py")
    print("  ./MTU.py")
    print("  ./vpn_ports.py")
    print("\nLifecycle:")
    print("  sudo ./insecure_vpn_tunnel_for_testing.py up")
    print("  sudo ./insecure_vpn_tunnel_for_testing.py down")
    print("=" * 60)
    return 0 if client_up and (udp_up or cfg.real_wireguard) else 1


def config_from_args(args: argparse.Namespace) -> LabConfig:
    return LabConfig(
        client_iface=args.client_iface,
        peer_iface=args.peer_iface,
        netns=args.netns,
        veth_peer=args.veth_peer,
        client_addr=args.client_addr,
        mtu=args.mtu,
        udp_port=args.udp_port,
        real_wireguard=args.real_wireguard,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create/remove an insecure VPN-like artifact for detection calibration.",
    )
    parser.add_argument("command", choices=["up", "down", "restart", "status"])
    parser.add_argument(
        "--real-wireguard",
        action="store_true",
        help=(
            "Opt-in to an actual WireGuard interface. Default synthetic mode is safer "
            "for VMs that soft-lock with the WireGuard kernel module."
        ),
    )
    parser.add_argument("--client-iface", default=DEFAULT_CLIENT_IFACE)
    parser.add_argument("--peer-iface", default=DEFAULT_PEER_IFACE)
    parser.add_argument("--netns", default=DEFAULT_NETNS)
    parser.add_argument("--veth-peer", default=DEFAULT_VETH_PEER)
    parser.add_argument("--client-addr", default=DEFAULT_CLIENT_ADDR)
    parser.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT)
    parser.add_argument("--mtu", type=int, default=DEFAULT_MTU)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = config_from_args(args)

    try:
        if args.command in {"up", "restart"}:
            if cfg.real_wireguard:
                setup_real_wireguard(cfg)
            else:
                setup_synthetic(cfg)
            return status(cfg)
        if args.command == "down":
            require_root()
            cleanup(cfg)
            print("Removed insecure VPN-like test tunnel.")
            return 0
        return status(cfg)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
