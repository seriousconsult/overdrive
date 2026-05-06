#!/usr/bin/env python3
"""

Resolve the LAN default gateway, then show router MAC + vendor and UPnP model info.

- **WSL:** Gateway IP comes from Windows (not the WSL vNIC). MAC comes from Windows neighbor
  cache (``Get-NetNeighbor`` / ``arp``) after a Windows ping — Scapy cannot ARP the LAN router.
- **Linux:** MAC from Scapy ARP, then ``ip neigh`` / ``/proc/net/arp`` fallback.
- **Model:** Parsed from UPnP device description XML (several common URLs). Set
  ``MY_MORE_ROUTER_IP`` if gateway discovery fails; ``MY_MORE_UPNP_RAW=1`` to dump XML when
  parsing finds no standard fields.

  
  NOTE: run with  sudo /mnt/c/code/overdrive/virtual_env/bin/python ./my_router.py
  
  """

from __future__ import annotations

import os
import re
import socket
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from urllib.parse import quote

import requests
from scapy.all import ARP, Ether, srp

# First 3 octets (lowercase) -> organization. OUI names the *vendor*, not device model.
KNOWN_OUI: dict[str, str] = {
    "00:15:5d": "Microsoft — Hyper-V dynamic virtual NIC (typical WSL2 / vSwitch gateway)",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox (PCS / virtual NIC)",
    "52:54:00": "QEMU / KVM (common virtual NIC)",
    "00:1c:42": "Parallels",
    "00:16:3e": "Xen virtual NIC",
}


def _mac_oui_key(mac: str) -> str:
    m = re.sub(r"[:-]", ":", mac.strip().lower())
    parts = [p for p in m.split(":") if p]
    if len(parts) < 3:
        return ""
    return ":".join(parts[:3])


def _normalize_mac_colon(s: str) -> str | None:
    s = s.strip().lower().replace("-", ":")
    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", s):
        return s
    return None


def vendor_from_mac(mac: str) -> str:
    """Resolve vendor from MAC: built-in OUI hints, then macvendors.com API."""
    oui = _mac_oui_key(mac)
    if oui in KNOWN_OUI:
        return KNOWN_OUI[oui]
    try:
        r = requests.get(
            f"https://api.macvendors.com/{quote(mac)}",
            timeout=8,
            headers={"User-Agent": "overdrive-my_more/1.0"},
        )
        if r.status_code == 200:
            body = (r.text or "").strip()
            if body and "not found" not in body.lower():
                return body
        if r.status_code == 429:
            return "Unknown (macvendors API rate-limited; retry later)"
    except requests.RequestException:
        pass
    return "Unknown manufacturer (no built-in OUI match; API unreachable or OUI not in registry)"


def _windows_ping_once(ip: str) -> None:
    try:
        subprocess.run(
            ["cmd.exe", "/c", f"ping -n 1 -w 2000 {ip}"],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def mac_from_windows(ip: str) -> str | None:
    """
    Read the router MAC from Windows' neighbor cache (WSL cannot ARP the LAN router).
    Pings once from Windows to populate ARP/NDP, then Get-NetNeighbor or arp -a.
    """
    _windows_ping_once(ip)
    ps = (
        f"$ip='{ip}'; "
        f"$rows = Get-NetNeighbor -IPAddress $ip -ErrorAction SilentlyContinue; "
        f"$row = $rows | Where-Object {{ $_.State -match 'Reachable|Stale|Permanent' }} "
        f"| Select-Object -First 1; "
        f"if (-not $row) {{ $row = $rows | Select-Object -First 1 }}; "
        f"if ($row -and $row.LinkLayerAddress) {{ [string]$row.LinkLayerAddress }}"
    )
    for exe in _powershell_exes():
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
        mac = _normalize_mac_colon(raw)
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
        text = ar.stdout or ""
        m = re.search(
            rf"{re.escape(ip)}\s+([0-9A-Fa-f:-]{{17}})\s+(?:dynamic|dynamisch)",
            text,
            re.I,
        )
        if m:
            return _normalize_mac_colon(m.group(1))
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def _linux_ping_once(ip: str, iface: str | None) -> None:
    cmd = ["ping", "-c", "1", "-W", "2", ip]
    if iface:
        cmd = ["ping", "-I", iface, "-c", "1", "-W", "2", ip]
    try:
        subprocess.run(cmd, capture_output=True, timeout=6)
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass


def mac_from_linux_neigh(ip: str, iface: str | None) -> str | None:
    """Neighbor table after ping (no Scapy)."""
    _linux_ping_once(ip, iface)
    try:
        cmd = ["ip", "neigh", "show", "to", ip]
        if iface:
            cmd.extend(["dev", iface])
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        m = re.search(r"lladdr\s+([0-9a-f:]{17})", (out.stdout or ""), re.I)
        if m:
            return _normalize_mac_colon(m.group(1))
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    try:
        with open("/proc/net/arp", encoding="utf-8", errors="ignore") as f:
            f.readline()
            for line in f:
                cols = line.split()
                if len(cols) < 4 or cols[0] != ip:
                    continue
                hw = cols[3]
                if hw == "00:00:00:00:00:00":
                    continue
                return _normalize_mac_colon(hw)
    except OSError:
        pass
    return None


def _upnp_urls(ip: str) -> list[str]:
    return [
        f"http://{ip}:49152/description.xml",
        f"http://{ip}/description.xml",
        f"http://{ip}/rootDesc.xml",
        f"http://{ip}/igddesc.xml",
        f"http://{ip}:5000/rootDesc.xml",
        f"http://{ip}:8080/description.xml",
    ]


def parse_upnp_device_xml(xml_text: str) -> dict[str, str]:
    """UPnP device description uses namespaced tags; collect common device fields."""
    fields: dict[str, str] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return fields
    interesting = frozenset(
        {
            "friendlyname",
            "manufacturer",
            "modelname",
            "modelnumber",
            "modeldescription",
            "serialnumber",
            "presentationurl",
        }
    )
    for el in root.iter():
        local = el.tag.split("}")[-1].lower()
        if local not in interesting:
            continue
        val = (el.text or "").strip()
        if val:
            fields[local] = val
    return fields


def fetch_upnp_device_info(ip: str) -> tuple[str | None, dict[str, str]]:
    """
    Try several common description URLs; return (raw_xml_or_None, parsed_fields).
    """
    headers = {"User-Agent": "overdrive-my_more/1.0"}
    for url in _upnp_urls(ip):
        try:
            r = requests.get(url, timeout=6, headers=headers)
        except requests.RequestException:
            continue
        if r.status_code != 200 or not (r.text or "").strip():
            continue
        body = r.text.strip()
        if not body.lstrip().startswith("<"):
            continue
        parsed = parse_upnp_device_xml(body)
        if parsed or "<device>" in body.lower() or "root xmlns" in body[:500].lower():
            return body, parsed
    return None, {}


def _is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        with open("/proc/version", encoding="utf-8", errors="ignore") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def _default_route_via_ip() -> tuple[str | None, str | None]:
    """Parse `ip -4 route show default` -> (gateway, iface)."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode != 0 or not out.stdout.strip():
            return None, None
        line = out.stdout.strip().splitlines()[0]
        m = re.search(
            r"default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+dev\s+(\S+))?",
            line,
        )
        if not m:
            return None, None
        gw, iface = m.group(1), m.group(2)
        return gw, iface
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        return None, None


def _default_gateway_proc_net_route() -> str | None:
    """Fallback when `ip` is missing: read /proc/net/route."""
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            next(f)
            for line in f:
                fields = line.split()
                if len(fields) < 3:
                    continue
                dest, gw_hex, flags = fields[1], fields[2], fields[3]
                if dest == "00000000" and int(flags, 16) & 2:
                    gw_int = int(gw_hex, 16)
                    gw = socket.inet_ntoa(struct.pack("<I", gw_int))
                    if gw != "0.0.0.0":
                        return gw
    except (OSError, ValueError, IndexError, struct.error):
        pass
    return None


def default_ipv4_gateway_linux() -> tuple[str | None, str | None]:
    """(gateway, iface) from this Linux network namespace."""
    gw, iface = _default_route_via_ip()
    if gw:
        return gw, iface
    g2 = _default_gateway_proc_net_route()
    return g2, None


def _valid_ipv4(s: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", s.strip()))


def _is_wsl2_style_nat_gateway(ip: str) -> bool:
    """172.16.0.0/12 is where WSL2 vEthernet NAT gateways usually live."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return a == 172 and 16 <= b <= 31


def _powershell_exes() -> list[str]:
    return [
        "powershell.exe",
        "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    ]


def _run_powershell_first_hop(script: str) -> str | None:
    for exe in _powershell_exes():
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
        hop = (out.stdout or "").strip().splitlines()
        hop = hop[0].strip() if hop else ""
        if _valid_ipv4(hop):
            return hop
    return None


def windows_home_router_ipv4() -> str | None:
    """
    Default IPv4 next hop on **Windows** (FiOS / LAN router), callable from WSL.

    Skips routes bound to WSL / Docker / VirtualBox-style vNICs. Optional override:
    ``MY_MORE_ROUTER_IP``.
    """
    env = (os.environ.get("MY_MORE_ROUTER_IP") or "").strip()
    if env and _valid_ipv4(env):
        return env

    # Prefer default routes whose interface is not a known virtual / WSL vNIC.
    ps_filtered = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | "
        "Sort-Object RouteMetric | "
        "Where-Object { $_.InterfaceAlias -notmatch "
        "'(?i)(WSL|vEthernet\\s*\\(\\s*WSL|Docker|VirtualBox|Default Switch)' } | "
        "Select-Object -First 1 -ExpandProperty NextHop"
    )
    hop = _run_powershell_first_hop(ps_filtered)
    if hop and not _is_wsl2_style_nat_gateway(hop):
        return hop
    if hop:
        # Filtered script only returned a 172.x hop (unusual); keep trying.
        pass

    # Any default route on Windows (physical or not); then drop obvious WSL NAT if possible.
    ps_any = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | "
        "Sort-Object RouteMetric | "
        "Select-Object -First 1 -ExpandProperty NextHop"
    )
    hop2 = _run_powershell_first_hop(ps_any)
    if hop2 and not _is_wsl2_style_nat_gateway(hop2):
        return hop2

    # ipconfig: collect all Default Gateway lines (locale variants), prefer non-172.16/12.
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
    for m in re.finditer(
        r"(?i)(?:default\s+gateway|standardgateway)[^\d\n]{0,40}(\d{1,3}(?:\.\d{1,3}){3})",
        text,
    ):
        g = m.group(1)
        if g != "0.0.0.0" and _valid_ipv4(g):
            gateways.append(g)
    preferred: list[str] = []
    fallback172: list[str] = []
    for g in gateways:
        if _is_wsl2_style_nat_gateway(g):
            fallback172.append(g)
        else:
            preferred.append(g)
    if preferred:
        return preferred[0]
    if hop2 and _valid_ipv4(hop2):
        return hop2
    if hop and _valid_ipv4(hop):
        return hop
    if fallback172:
        return fallback172[0]
    return None


def resolve_router_ipv4_and_iface() -> tuple[str, str | None, bool]:
    """
    Gateway to probe: on WSL, **only** Windows LAN router (never Linux vNIC default).

    Returns (ip, iface, used_windows_route). On WSL, ``used_windows_route`` is always True
    when successful; ``iface`` is always None (ARP/HTTP target is off the WSL vEthernet).
    """
    if _is_wsl():
        win_gw = windows_home_router_ipv4()
        if win_gw:
            return win_gw, None, True
        print(
            "Could not determine your **home** router IPv4 from Windows while running in WSL.\n"
            "Check: WSL interop (not disabled), powershell.exe reachable, and NetRoute/ipconfig.\n"
            "Workaround:  export MY_MORE_ROUTER_IP=192.168.1.1   # your FiOS / gateway IP",
            file=sys.stderr,
        )
        sys.exit(1)
    gw, iface = default_ipv4_gateway_linux()
    if not gw:
        print(
            "Could not determine default IPv4 gateway (need `ip` or /proc/net/route).",
            file=sys.stderr,
        )
        sys.exit(1)
    return gw, iface, False


def _print_upnp_summary(fields: dict[str, str]) -> None:
    if not fields:
        return
    print("--- Router model (from UPnP device description) ---")
    order = [
        ("manufacturer", "Manufacturer"),
        ("modelname", "Model name"),
        ("modelnumber", "Model number"),
        ("friendlyname", "Friendly name"),
        ("modeldescription", "Description"),
        ("serialnumber", "Serial"),
        ("presentationurl", "Admin URL"),
    ]
    for key, label in order:
        if key in fields:
            print(f"  {label}: {fields[key]}")


def main() -> None:
    target_ip, iface, via_windows = resolve_router_ipv4_and_iface()
    print(f"Using router / gateway IP: {target_ip}" + (f" (iface={iface})" if iface else ""))
    if _is_wsl() and via_windows:
        print(
            "MAC is read from Windows (Get-NetNeighbor / arp); "
            "WSL cannot ARP your LAN router directly."
        )
    if _is_wsl() and _is_wsl2_style_nat_gateway(target_ip):
        print(
            "Warning: gateway looks like a 172.16–172.31 address (often virtual). "
            "Set MY_MORE_ROUTER_IP if this is not your FiOS / home router.",
            file=sys.stderr,
        )

    mac: str | None = None
    if _is_wsl():
        mac = mac_from_windows(target_ip)
        if not mac:
            print(
                "Router MAC: not found from Windows neighbor cache.\n"
                "  Try: ping the gateway from Windows once, then re-run; "
                "or run this script from native Linux / PowerShell on Windows.",
                file=sys.stderr,
            )
    else:
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        kwargs: dict = {"timeout": 3, "verbose": 0}
        if iface:
            kwargs["iface"] = iface
        result = []
        try:
            result = srp(packet, **kwargs)[0]
        except Exception as e:
            print(f"ARP scan failed ({e}). Trying kernel neighbor table…", file=sys.stderr)
        if result:
            mac = _normalize_mac_colon(result[0][1].hwsrc) or str(result[0][1].hwsrc).lower()
        if not mac:
            mac = mac_from_linux_neigh(target_ip, iface)
        if not mac:
            print(
                "Router MAC: not found (no ARP reply and no ip neigh entry). "
                "Try: sudo and correct iface, or ping the gateway first.",
                file=sys.stderr,
            )

    if mac:
        print(f"Router MAC Address: {mac}")
        print(f"OUI vendor / organization: {vendor_from_mac(mac)}")

    _raw_xml, upnp_fields = fetch_upnp_device_info(target_ip)
    if upnp_fields:
        _print_upnp_summary(upnp_fields)
    elif _raw_xml:
        print(
            "UPnP returned XML but no standard device fields were parsed "
            "(non-standard schema).",
            file=sys.stderr,
        )
        if os.environ.get("MY_MORE_UPNP_RAW"):
            print("--- Raw UPnP XML (MY_MORE_UPNP_RAW set) ---")
            print(_raw_xml[:8000])
    else:
        print(
            "Router model (UPnP): not available — tried :49152 and common paths on :80. "
            "Enable UPnP on the router or set MY_MORE_UPNP_RAW=1 after a working URL.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
