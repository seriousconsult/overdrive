#!/usr/bin/env python3
"""Local port inventory for the current host.

Purpose: Discover listening TCP/UDP sockets and classify whether services are bound to
loopback-only addresses or appear network-accessible.

Environment: Linux, WSL, or Windows. On Linux this prefers `ss -tulnp` when available.
"""

from __future__ import annotations

import ipaddress
import csv
import os
import platform
import re
import shutil
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_local import is_wsl_local
from detections.common.common_utils import normalize_address, run_command, split_address_port


@dataclass
class PortListener:
    proto: str
    local_address: str
    local_port: int | None
    remote_address: str | None
    state: str | None
    pid: str | None
    process: str | None


def _wsl_resolver_addresses() -> set[str]:
    addresses: set[str] = set()
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return addresses

    for line in lines:
        line = line.split("#", 1)[0].strip()
        if not line.startswith("nameserver "):
            continue
        parts = line.split()
        if len(parts) >= 2:
            addresses.add(normalize_address(parts[1]))
    return addresses


def _service_name(port: int | None, proto: str) -> str:
    if port is None:
        return ""
    try:
        return socket.getservbyport(port, proto.lower())
    except (OSError, ValueError):
        return ""


def _parse_ss_line(line: str) -> PortListener | None:
    fields = re.split(r"\s+", line.strip(), maxsplit=6)
    if len(fields) < 5:
        return None
    proto = fields[0].lower()
    state = fields[1] if len(fields) > 1 else None
    local = fields[4] if len(fields) > 4 else ""
    remote = fields[5] if len(fields) > 5 else None
    users = fields[6] if len(fields) > 6 else ""

    name = None
    pid = None
    proc_match = re.search(r"users:\(\(\"(.+?)\",pid=(\d+),", users)
    if proc_match:
        name = proc_match.group(1)
        pid = proc_match.group(2)

    local_host, local_port = split_address_port(local)
    local_host = normalize_address(local_host)

    remote_host = None
    if remote:
        remote_host = normalize_address(split_address_port(remote)[0])

    return PortListener(
        proto=proto,
        local_address=local_host,
        local_port=local_port,
        remote_address=remote_host,
        state=state,
        pid=pid,
        process=name,
    )


def _parse_netstat_line(line: str, proc_map: dict[str, str]) -> PortListener | None:
    fields = re.split(r"\s+", line.strip())
    if not fields:
        return None
    proto = fields[0].lower()
    if proto not in {"tcp", "udp"}:
        return None

    if proto == "tcp":
        if len(fields) < 5:
            return None
        local = fields[1]
        remote = fields[2]
        state = fields[3]
        pid = fields[4]
    else:
        if len(fields) < 4:
            return None
        local = fields[1]
        remote = fields[2]
        state = None
        pid = fields[3]

    process = proc_map.get(pid)
    local_host, local_port = split_address_port(local)
    local_host = normalize_address(local_host)
    remote_host = normalize_address(split_address_port(remote)[0])

    return PortListener(
        proto=proto,
        local_address=local_host,
        local_port=local_port,
        remote_address=remote_host,
        state=state,
        pid=pid,
        process=process,
    )


def _windows_process_map() -> dict[str, str]:
    proc_map: dict[str, str] = {}
    returncode, output = run_command(["tasklist", "/FO", "CSV", "/NH"])
    if returncode != 0 or not output:
        return proc_map

    reader = csv.reader(output.splitlines())
    for row in reader:
        if len(row) < 2:
            continue
        name = row[0].strip('"')
        pid = row[1].strip('"')
        proc_map[pid] = name
    return proc_map


def _is_network_accessible(binding: str) -> bool:
    host = normalize_address(binding)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or host in {"*", "0.0.0.0", "::"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not ip.is_loopback


def _is_wsl_internal_dns(entry: PortListener, resolver_addresses: set[str]) -> bool:
    if entry.local_port != 53:
        return False

    host = normalize_address(entry.local_address)
    if host in {"*", "0.0.0.0", "::"}:
        return False

    if host == "10.255.255.254":
        return True

    if host not in resolver_addresses:
        return False

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return not ip.is_loopback and (ip.is_private or ip.is_link_local)


def _is_dhcp_client_socket(entry: PortListener) -> bool:
    if entry.proto.lower() != "udp":
        return False
    if entry.local_port in {68, 546}:
        return True
    proc = (entry.process or "").lower()
    return proc in {"dhclient", "dhcpcd", "udhcpc"} and (entry.state or "").upper() in {"", "-", "UNCONN"}


def _listener_scope(entry: PortListener, *, wsl: bool, resolver_addresses: set[str]) -> str:
    if _is_dhcp_client_socket(entry):
        return "dhcp-client"
    if wsl and _is_wsl_internal_dns(entry, resolver_addresses):
        return "wsl-dns"
    if _is_network_accessible(entry.local_address):
        return "non-loopback"
    return "loopback"


def _format_local_address(host: str, port: int | None) -> str:
    if port is None:
        return host
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _collect_linux_listeners() -> list[PortListener]:
    listeners: list[PortListener] = []
    ss_path = shutil.which("ss")
    if ss_path:
        ret, out = run_command([ss_path, "-tulnp", "-H"])
        if ret == 0 and out:
            for line in out.splitlines():
                entry = _parse_ss_line(line)
                if entry is not None:
                    listeners.append(entry)
            return listeners

    # Fallback: attempt /proc/net parsing if ss is unavailable.
    for proto, path in (("tcp", "/proc/net/tcp"), ("udp", "/proc/net/udp"), ("tcp", "/proc/net/tcp6"), ("udp", "/proc/net/udp6")):
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            local_hex, state = parts[1], parts[3]
            host_port = _decode_proc_address(local_hex, proto.endswith("6"))
            local_host, local_port = split_address_port(host_port)
            local_host = normalize_address(local_host)
            listeners.append(
                PortListener(
                    proto=proto,
                    local_address=local_host,
                    local_port=local_port,
                    remote_address=None,
                    state=state,
                    pid=None,
                    process=None,
                )
            )
    return listeners


def _decode_proc_address(hexaddr: str, ipv6: bool) -> str:
    host_hex, _, port_hex = hexaddr.partition(":")
    if not port_hex:
        return hexaddr
    try:
        port = int(port_hex, 16)
    except ValueError:
        port = None
    if ipv6:
        if len(host_hex) != 32:
            return f"{host_hex}:{port or '?'}"
        parts = [host_hex[i : i + 4] for i in range(0, 32, 4)]
        addr = ":".join(part.lstrip("0") or "0" for part in parts)
        return f"{addr}:{port or '?'}"
    if len(host_hex) != 8:
        return f"{host_hex}:{port or '?'}"
    addr = ".".join(str(int(host_hex[i : i + 2], 16)) for i in range(6, -2, -2))
    return f"{addr}:{port or '?'}"


def _collect_windows_listeners() -> list[PortListener]:
    listeners: list[PortListener] = []
    proc_map = _windows_process_map()
    ret, out = run_command(["netstat", "-ano"])
    if ret != 0 or not out:
        return listeners
    for line in out.splitlines():
        if not line.strip() or line.startswith("Proto") or line.startswith("Active"):
            continue
        entry = _parse_netstat_line(line, proc_map)
        if entry is not None:
            listeners.append(entry)
    return listeners


def _format_listener(entry: PortListener, *, scope: str | None = None) -> str:
    service = _service_name(entry.local_port, entry.proto)
    proto = entry.proto.upper()
    addr = _format_local_address(entry.local_address, entry.local_port)
    proc = entry.process or "(unknown)"
    pid = entry.pid or "-"
    state = entry.state or "-"
    if scope:
        summary = f"{proto:<5} {addr:<40} {state:<12} {pid:<7} {proc:<20} {scope:<14}"
    else:
        summary = f"{proto:<5} {addr:<40} {state:<12} {pid:<7} {proc:<20}"
    if service:
        summary += f" ({service})"
    return summary


def run_audit() -> int:
    wsl = is_wsl_local()
    resolver_addresses = _wsl_resolver_addresses() if wsl else set()

    if platform.system() == "Windows":
        listeners = _collect_windows_listeners()
    else:
        listeners = _collect_linux_listeners()

    if wsl:
        print(
            "[WSL2] Running inside WSL. These bindings are from the Linux guest namespace, "
            "not a direct inventory of Windows or your LAN."
        )
        print(
            "[WSL2] Port 53 on 10.255.255.254 or the WSL resolver address is treated as "
            "internal DNS plumbing."
        )
    print("\nLocal listening port inventory:\n")
    if not listeners:
        print("No listening TCP/UDP sockets detected.")
        print("\nSCORE: 1")
        print("STATUS: No active listening ports found.")
        return 0

    listeners.sort(key=lambda e: (e.proto, e.local_address, e.local_port or 0))
    scopes = [
        _listener_scope(entry, wsl=wsl, resolver_addresses=resolver_addresses)
        for entry in listeners
    ]
    print(f"{'PROTO':<5} {'LOCAL ADDRESS':<40} {'STATE':<12} {'PID':<7} {'PROCESS':<20} SCOPE")
    print("-" * 104)
    for entry, scope in zip(listeners, scopes):
        print(_format_listener(entry, scope=scope))

    internal_wsl_dns = [e for e, scope in zip(listeners, scopes) if scope == "wsl-dns"]
    dhcp_clients = [e for e, scope in zip(listeners, scopes) if scope == "dhcp-client"]
    other_non_loopback = [e for e, scope in zip(listeners, scopes) if scope == "non-loopback"]
    loopback_only = [e for e, scope in zip(listeners, scopes) if scope == "loopback"]

    print("\nSummary:\n")
    print(f"Total listening sockets: {len(listeners)}")
    print(f"Loopback-only listeners: {len(loopback_only)}")
    print(f"Client DHCP sockets: {len(dhcp_clients)}")
    if wsl:
        print(f"WSL-internal DNS listeners: {len(internal_wsl_dns)}")
        print(f"Other non-loopback service listeners: {len(other_non_loopback)}")
    else:
        print(f"Network-facing service listeners: {len(other_non_loopback)}")

    if other_non_loopback:
        score = 3
        if wsl:
            status = (
                "At least one non-loopback listener remains after ignoring WSL internal DNS; "
                "review manually because WSL reachability depends on Windows/WSL networking mode."
            )
        else:
            status = (
                "At least one service listener is bound to a network-facing address; "
                "alerting but not proof of an artificial host."
            )
    else:
        score = 1
        if wsl and internal_wsl_dns:
            status = (
                "Only loopback and WSL-internal DNS listeners detected; this is normal WSL2 resolver behavior, "
                "not evidence of external port exposure."
            )
        elif dhcp_clients:
            status = (
                "Only loopback and client DHCP sockets detected; no direct network-facing service listeners detected."
            )
        else:
            status = (
                "All services are bound to loopback-only addresses; no direct network-facing listeners detected."
            )

    print(f"\nSCORE: {score}")
    print(f"STATUS: {status}")
    return 0


def main() -> int:
    try:
        return run_audit()
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
