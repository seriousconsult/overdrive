#!/usr/bin/env python3
"""Create a local WireGuard test tunnel for detection calibration.

This is a lab helper, not a product VPN and not a remote-exit security tool.
It creates a real local WireGuard peer pair so VPN detections can be compared
with the tunnel up versus down:

  - client namespace: wg-overdrive, 10.77.0.2/24, MTU 1420
  - peer namespace:   wg-od-peer, 10.77.0.1/24, MTU 1420
  - outer transport:  veth pair on 169.254.250.0/30, UDP 51820/51821

The default route is not changed. Internet traffic is not sent through this
tunnel. The point is to expose typical WireGuard artifacts to local detections:
wg interface name, WireGuard peer state, UDP listener, and reduced tunnel MTU.
"""

from __future__ import annotations

import argparse
import os
import socket
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CLIENT_IFACE = "wg-overdrive"
DEFAULT_PEER_IFACE = "wg-od-peer"
DEFAULT_NETNS = "overdrive-wg"
DEFAULT_VETH_HOST = "odwg-host"
DEFAULT_VETH_PEER = "odwg-peer"
DEFAULT_HOST_OUTER = "169.254.250.1/30"
DEFAULT_PEER_OUTER = "169.254.250.2/30"
DEFAULT_PEER_ENDPOINT = "169.254.250.2"
DEFAULT_CLIENT_ADDR = "10.77.0.2/24"
DEFAULT_PEER_ADDR = "10.77.0.1/24"
DEFAULT_PEER_TUNNEL_IP = "10.77.0.1"
DEFAULT_CLIENT_PORT = 51821
DEFAULT_PEER_PORT = 51820
DEFAULT_MTU = 1420
STATE_DIR = Path("/tmp/overdrive-insecure-vpn-tunnel")


@dataclass(frozen=True)
class LabConfig:
    client_iface: str
    peer_iface: str
    netns: str
    veth_host: str
    veth_peer: str
    host_outer: str
    peer_outer: str
    peer_endpoint: str
    client_addr: str
    peer_addr: str
    peer_tunnel_ip: str
    client_port: int
    peer_port: int
    mtu: int


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        input=input_text,
        capture_output=capture,
        text=True,
        check=False,
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


def require_tools() -> None:
    missing = [tool for tool in ("ip", "wg") if shutil.which(tool) is None]
    if missing:
        raise RuntimeError(
            "missing required tool(s): "
            + ", ".join(missing)
            + ". Install iproute2 and wireguard-tools in the client VM."
        )


def maybe_load_wireguard_module() -> None:
    if shutil.which("modprobe"):
        run(["modprobe", "wireguard"], check=False)


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


def netns_exists(name: str) -> bool:
    names = output(["ip", "netns", "list"], check=False).splitlines()
    return any(line.split()[0] == name for line in names if line.strip())


def link_exists(name: str, *, netns: str | None = None) -> bool:
    cmd = ["ip"]
    if netns:
        cmd += ["netns", "exec", netns]
    cmd += ["link", "show", "dev", name]
    return run(cmd, check=False, capture=True).returncode == 0


def cleanup(cfg: LabConfig) -> None:
    if link_exists(cfg.client_iface):
        run(["ip", "link", "del", "dev", cfg.client_iface], check=False)
    if link_exists(cfg.veth_host):
        run(["ip", "link", "del", "dev", cfg.veth_host], check=False)
    if netns_exists(cfg.netns):
        run(["ip", "netns", "del", cfg.netns], check=False)


def setup(cfg: LabConfig) -> None:
    require_root()
    require_tools()
    maybe_load_wireguard_module()

    cleanup(cfg)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    client_key, client_pub = wg_keypair("client")
    peer_key, peer_pub = wg_keypair("peer")

    run(["ip", "netns", "add", cfg.netns])
    run(["ip", "link", "add", cfg.veth_host, "type", "veth", "peer", "name", cfg.veth_peer])
    run(["ip", "link", "set", cfg.veth_peer, "netns", cfg.netns])
    run(["ip", "addr", "add", cfg.host_outer, "dev", cfg.veth_host])
    run(["ip", "link", "set", "dev", cfg.veth_host, "up"])
    run(["ip", "netns", "exec", cfg.netns, "ip", "link", "set", "dev", "lo", "up"])
    run(
        [
            "ip",
            "netns",
            "exec",
            cfg.netns,
            "ip",
            "addr",
            "add",
            cfg.peer_outer,
            "dev",
            cfg.veth_peer,
        ]
    )
    run(["ip", "netns", "exec", cfg.netns, "ip", "link", "set", "dev", cfg.veth_peer, "up"])

    run(["ip", "link", "add", cfg.client_iface, "type", "wireguard"])
    run(
        [
            "ip",
            "netns",
            "exec",
            cfg.netns,
            "ip",
            "link",
            "add",
            cfg.peer_iface,
            "type",
            "wireguard",
        ]
    )

    run(
        [
            "wg",
            "set",
            cfg.client_iface,
            "private-key",
            str(client_key),
            "listen-port",
            str(cfg.client_port),
            "peer",
            peer_pub,
            "endpoint",
            f"{cfg.peer_endpoint}:{cfg.peer_port}",
            "allowed-ips",
            "10.77.0.1/32",
            "persistent-keepalive",
            "5",
        ]
    )
    run(
        [
            "ip",
            "netns",
            "exec",
            cfg.netns,
            "wg",
            "set",
            cfg.peer_iface,
            "private-key",
            str(peer_key),
            "listen-port",
            str(cfg.peer_port),
            "peer",
            client_pub,
            "endpoint",
            f"169.254.250.1:{cfg.client_port}",
            "allowed-ips",
            "10.77.0.2/32",
            "persistent-keepalive",
            "5",
        ]
    )

    run(["ip", "addr", "add", cfg.client_addr, "dev", cfg.client_iface])
    run(["ip", "link", "set", "dev", cfg.client_iface, "mtu", str(cfg.mtu), "up"])
    run(
        [
            "ip",
            "netns",
            "exec",
            cfg.netns,
            "ip",
            "addr",
            "add",
            cfg.peer_addr,
            "dev",
            cfg.peer_iface,
        ]
    )
    run(
        [
            "ip",
            "netns",
            "exec",
            cfg.netns,
            "ip",
            "link",
            "set",
            "dev",
            cfg.peer_iface,
            "mtu",
            str(cfg.mtu),
            "up",
        ]
    )

    # Trigger a handshake. UDP does not require ICMP to be allowed; ping is only
    # a best-effort extra for humans who want a familiar reachability check.
    trigger_udp(cfg.peer_tunnel_ip)
    run(["ping", "-c", "1", "-W", "1", cfg.peer_tunnel_ip], check=False)
    time.sleep(1.0)


def trigger_udp(peer_ip: str) -> None:
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(b"overdrive-wireguard-test", (peer_ip, 9))
    except OSError:
        pass
    finally:
        if sock is not None:
            sock.close()


def status(cfg: LabConfig) -> int:
    print("=" * 60)
    print("Overdrive local WireGuard test tunnel")
    print("=" * 60)
    print("Purpose: detection calibration only; not a secure or remote-exit VPN.")
    print("Default route: unchanged.")
    print()

    client_up = link_exists(cfg.client_iface)
    peer_ns_up = netns_exists(cfg.netns)
    peer_up = peer_ns_up and link_exists(cfg.peer_iface, netns=cfg.netns)
    print(f"client interface {cfg.client_iface}: {'present' if client_up else 'absent'}")
    print(f"peer namespace {cfg.netns}: {'present' if peer_ns_up else 'absent'}")
    print(f"peer interface {cfg.peer_iface}: {'present' if peer_up else 'absent'}")

    if client_up:
        print("\n[ip link]")
        print(output(["ip", "-o", "link", "show", "dev", cfg.client_iface], check=False))
        print("\n[ip addr]")
        print(output(["ip", "-o", "addr", "show", "dev", cfg.client_iface], check=False))
        print("\n[wg show]")
        print(output(["wg", "show", cfg.client_iface], check=False) or "(no wg output)")
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
    return 0 if client_up and peer_up else 1


def config_from_args(args: argparse.Namespace) -> LabConfig:
    return LabConfig(
        client_iface=args.client_iface,
        peer_iface=args.peer_iface,
        netns=args.netns,
        veth_host=args.veth_host,
        veth_peer=args.veth_peer,
        host_outer=args.host_outer,
        peer_outer=args.peer_outer,
        peer_endpoint=args.peer_endpoint,
        client_addr=args.client_addr,
        peer_addr=args.peer_addr,
        peer_tunnel_ip=args.peer_tunnel_ip,
        client_port=args.client_port,
        peer_port=args.peer_port,
        mtu=args.mtu,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create/remove a local WireGuard test tunnel for VPN detection calibration.",
    )
    parser.add_argument("command", choices=["up", "down", "restart", "status"])
    parser.add_argument("--client-iface", default=DEFAULT_CLIENT_IFACE)
    parser.add_argument("--peer-iface", default=DEFAULT_PEER_IFACE)
    parser.add_argument("--netns", default=DEFAULT_NETNS)
    parser.add_argument("--veth-host", default=DEFAULT_VETH_HOST)
    parser.add_argument("--veth-peer", default=DEFAULT_VETH_PEER)
    parser.add_argument("--host-outer", default=DEFAULT_HOST_OUTER)
    parser.add_argument("--peer-outer", default=DEFAULT_PEER_OUTER)
    parser.add_argument("--peer-endpoint", default=DEFAULT_PEER_ENDPOINT)
    parser.add_argument("--client-addr", default=DEFAULT_CLIENT_ADDR)
    parser.add_argument("--peer-addr", default=DEFAULT_PEER_ADDR)
    parser.add_argument("--peer-tunnel-ip", default=DEFAULT_PEER_TUNNEL_IP)
    parser.add_argument("--client-port", type=int, default=DEFAULT_CLIENT_PORT)
    parser.add_argument("--peer-port", type=int, default=DEFAULT_PEER_PORT)
    parser.add_argument("--mtu", type=int, default=DEFAULT_MTU)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = config_from_args(args)

    try:
        if args.command == "up":
            setup(cfg)
            return status(cfg)
        if args.command == "restart":
            setup(cfg)
            return status(cfg)
        if args.command == "down":
            require_root()
            cleanup(cfg)
            print("Removed local WireGuard test tunnel.")
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
