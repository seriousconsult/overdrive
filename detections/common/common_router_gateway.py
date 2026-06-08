"""Gateway, MAC, OUI, and router-address helpers."""

from __future__ import annotations

import os
import re
import socket
import struct
import subprocess
import time
from typing import Any
from urllib.parse import quote

from detections.common.common_local import is_wsl_local, mac_oui_colon_prefix, normalize_mac_colon

KNOWN_VIRTUAL_OUI: dict[str, str] = {
    "00:15:5d": "Microsoft - Hyper-V dynamic virtual NIC (typical WSL2 / vSwitch gateway)",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox (PCS / virtual NIC)",
    "52:54:00": "QEMU / KVM (common virtual NIC)",
    "00:1c:42": "Parallels",
    "00:16:3e": "Xen virtual NIC",
}


def default_ipv4_gateway() -> str | None:
    """Get the default IPv4 gateway from the routing table."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0 and out.stdout:
            m = re.search(r"default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})", out.stdout)
            if m:
                return m.group(1)
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def run_cmd(cmd: list[str]) -> str:
    """Run a subprocess command and return stdout."""
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return ""


def normalize_oui(mac: str) -> str:
    """Normalize MAC address to XX:XX:XX format."""
    mac = mac.strip().upper().replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 3:
        raise ValueError(f"Bad MAC format: {mac!r}")
    return f"{parts[0]}:{parts[1]}:{parts[2]}"


def valid_ipv4(value: str) -> bool:
    """Return True for syntactically valid dotted IPv4 strings."""
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value.strip()))


def is_wsl2_style_nat_gateway(ip: str) -> bool:
    """True for 172.16.0.0/12 addresses commonly used by WSL2 NAT gateways."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return a == 172 and 16 <= b <= 31


def vendor_from_mac(mac: str, *, timeout: float = 8) -> str:
    """Resolve a MAC vendor from built-in OUI hints, then macvendors.com."""
    oui = mac_oui_colon_prefix(mac)
    if oui in KNOWN_VIRTUAL_OUI:
        return KNOWN_VIRTUAL_OUI[oui]
    try:
        import requests

        r = requests.get(
            f"https://api.macvendors.com/{quote(mac)}",
            timeout=timeout,
            headers={"User-Agent": "overdrive-router-utils/1.0"},
        )
        if r.status_code == 200:
            body = (r.text or "").strip()
            if body and "not found" not in body.lower():
                return body
        if r.status_code == 429:
            return "Unknown (macvendors API rate-limited; retry later)"
    except Exception:
        pass
    return "Unknown manufacturer (no built-in OUI match; API unreachable or OUI not in registry)"


def windows_ping_once(ip: str) -> None:
    """Ping once via Windows to populate its neighbor cache."""
    try:
        subprocess.run(
            ["cmd.exe", "/c", f"ping -n 1 -w 2000 {ip}"],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def powershell_exes() -> list[str]:
    """PowerShell executable candidates reachable from Windows or WSL."""
    return [
        "powershell.exe",
        "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    ]


def run_powershell_first_ipv4(script: str) -> str | None:
    """Run a PowerShell script and return the first IPv4-looking output line."""
    for exe in powershell_exes():
        try:
            out = subprocess.run(
                [exe, "-NoProfile", "-NoLogo", "-Command", script],
                capture_output=True,
                text=True,
                timeout=18,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
            continue
        line = (out.stdout or "").strip().splitlines()
        hop = line[0].strip() if line else ""
        if valid_ipv4(hop):
            return hop
    return None


def default_ipv4_gateway_linux() -> tuple[str | None, str | None]:
    """Return ``(gateway, iface)`` from the current Linux network namespace."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            line = out.stdout.strip().splitlines()[0]
            m = re.search(
                r"default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+dev\s+(\S+))?",
                line,
            )
            if m:
                return m.group(1), m.group(2)
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            next(f)
            for line in f:
                fields = line.split()
                if len(fields) < 4:
                    continue
                dest, gw_hex, flags = fields[1], fields[2], fields[3]
                if dest == "00000000" and int(flags, 16) & 2:
                    gw_int = int(gw_hex, 16)
                    gw = socket.inet_ntoa(struct.pack("<I", gw_int))
                    if gw != "0.0.0.0":
                        return gw, None
    except (OSError, ValueError, IndexError, struct.error):
        pass
    return None, None


def windows_home_router_ipv4(env_var: str = "MY_MORE_ROUTER_IP") -> str | None:
    """Return Windows' likely home router IPv4, callable from WSL."""
    env = (os.environ.get(env_var) or "").strip()
    if env and valid_ipv4(env):
        return env

    ps_filtered = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | "
        "Sort-Object RouteMetric | "
        "Where-Object { $_.InterfaceAlias -notmatch "
        "'(?i)(WSL|vEthernet\\s*\\(\\s*WSL|Docker|VirtualBox|Default Switch)' } | "
        "Select-Object -First 1 -ExpandProperty NextHop"
    )
    hop = run_powershell_first_ipv4(ps_filtered)
    if hop and not is_wsl2_style_nat_gateway(hop):
        return hop

    ps_any = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | "
        "Sort-Object RouteMetric | "
        "Select-Object -First 1 -ExpandProperty NextHop"
    )
    hop2 = run_powershell_first_ipv4(ps_any)
    if hop2 and not is_wsl2_style_nat_gateway(hop2):
        return hop2

    try:
        ic = subprocess.run(
            ["cmd.exe", "/c", "ipconfig"],
            capture_output=True,
            text=True,
            timeout=20,
            encoding="utf-8",
            errors="replace",
        )
        text = (ic.stdout or "") + "\n" + (ic.stderr or "")
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        text = ""

    gateways: list[str] = []
    for match in re.finditer(
        r"(?i)(?:default\s+gateway|standardgateway)[^\d\n]{0,40}(\d{1,3}(?:\.\d{1,3}){3})",
        text,
    ):
        gateway = match.group(1)
        if gateway != "0.0.0.0" and valid_ipv4(gateway):
            gateways.append(gateway)
    for gateway in gateways:
        if not is_wsl2_style_nat_gateway(gateway):
            return gateway
    return hop2 or hop or (gateways[0] if gateways else None)


def resolve_router_ipv4_and_iface() -> tuple[str, str | None, bool]:
    """Return ``(ip, iface, used_windows_route)`` for the likely router/gateway."""
    if is_wsl_local():
        win_gw = windows_home_router_ipv4()
        if win_gw:
            return win_gw, None, True
        raise RuntimeError(
            "Could not determine home router IPv4 from Windows while running in WSL. "
            "Workaround: export MY_MORE_ROUTER_IP=192.168.1.1"
        )
    gw, iface = default_ipv4_gateway_linux()
    if not gw:
        raise RuntimeError("Could not determine default IPv4 gateway.")
    return gw, iface, False


def mac_from_windows(ip: str) -> str | None:
    """Read a MAC address from Windows' neighbor cache."""
    windows_ping_once(ip)
    ps = (
        f"$ip='{ip}'; "
        f"$rows = Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue; "
        f"$row = $rows | Where-Object {{ $_.State -match 'Reachable|Stale|Permanent' }} "
        f"| Select-Object -First 1; "
        f"if (-not $row) {{ $row = $rows | Select-Object -First 1 }}; "
        f"if ($row -and $row.LinkLayerAddress) {{ [string]$row.LinkLayerAddress }}"
    )
    for exe in powershell_exes():
        try:
            out = subprocess.run(
                [exe, "-NoProfile", "-NoLogo", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
            continue
        line = (out.stdout or "").strip().splitlines()
        raw = line[0].strip() if line else ""
        mac = normalize_mac_colon(raw)
        if mac:
            return mac
    try:
        ar = subprocess.run(
            ["cmd.exe", "/c", f"arp -a {ip}"],
            capture_output=True,
            text=True,
            timeout=12,
            encoding="utf-8",
            errors="replace",
        )
        m = re.search(
            rf"{re.escape(ip)}\s+([0-9A-Fa-f:-]{{17}})\s+(?:dynamic|dynamisch)",
            ar.stdout or "",
            re.I,
        )
        if m:
            return normalize_mac_colon(m.group(1))
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def linux_ping_once(ip: str, iface: str | None) -> None:
    """Ping once from Linux to populate ARP/neighbor cache."""
    cmd = ["ping", "-c", "1", "-W", "2", ip]
    if iface:
        cmd = ["ping", "-I", iface, "-c", "1", "-W", "2", ip]
    try:
        subprocess.run(cmd, capture_output=True, timeout=6)
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass


def mac_from_linux_neigh(ip: str, iface: str | None) -> str | None:
    """Read a MAC address via Scapy ARP when available, then Linux neighbor/ARP tables."""
    try:
        from scapy.all import ARP, Ether, srp

        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        kwargs: dict[str, Any] = {"timeout": 3, "verbose": 0}
        if iface:
            kwargs["iface"] = iface
        result = srp(packet, **kwargs)[0]
        if result:
            mac = normalize_mac_colon(result[0][1].hwsrc) or str(result[0][1].hwsrc).lower()
            if mac:
                return mac
    except Exception:
        pass

    linux_ping_once(ip, iface)
    mac = try_ip_neigh(ip, iface) or mac_from_proc_net_arp(ip)
    return normalize_mac_colon(mac) if mac else None


def try_ip_neigh(ip: str, iface: str | None = None) -> str | None:
    """Try to get MAC address from ip neigh command."""
    try:
        cmd = ["ip", "neigh", "show", "to", ip]
        if iface:
            cmd.extend(["dev", iface])
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        out = (proc.stdout or "").strip()
        if not out:
            return None

        m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
        if m:
            return m.group(1).lower()
        m2 = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", out)
        if m2:
            return out[m2.start() : m2.end()].lower()
        return None
    except Exception:
        return None


def mac_from_proc_net_arp(ip: str) -> str | None:
    """Get MAC address from /proc/net/arp."""
    try:
        with open("/proc/net/arp", encoding="utf-8", errors="ignore") as f:
            f.readline()
            for line in f:
                cols = line.split()
                if len(cols) < 4:
                    continue
                row_ip, _hwtype, flags, hw_addr = cols[0], cols[1], cols[2], cols[3]
                if row_ip != ip or flags == "0x0" or hw_addr == "00:00:00:00:00:00":
                    continue
                if re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", hw_addr, re.I):
                    return hw_addr.lower()
    except OSError:
        pass
    return None


def ping_first(ip: str, iface: str | None, count: int, timeout_s: int) -> None:
    """Ping an IP to populate ARP cache."""
    cmd = ["ping", "-c", str(count), "-W", str(timeout_s), ip]
    if iface:
        cmd = ["ping", "-I", iface, "-c", str(count), "-W", str(timeout_s), ip]
    subprocess.run(cmd, capture_output=True, text=True, check=False)


def resolve_mac(ip: str, iface: str | None, retries: int, ping_first_user: bool) -> tuple[str | None, list[str]]:
    """Try to resolve MAC address for an IP."""
    errs: list[str] = []
    n = max(1, retries)
    for attempt in range(n):
        if ping_first_user and attempt == 0:
            ping_first(ip, iface, 1, 1)

        mac = try_ip_neigh(ip, iface) or mac_from_proc_net_arp(ip)
        if mac:
            return mac, errs

        if attempt < n - 1:
            ping_first(ip, iface, 1, 1)
            time.sleep(0.3)
        else:
            errs.append("No MAC from ip neigh or /proc/net/arp after probes.")

    return None, errs
