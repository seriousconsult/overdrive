#!/usr/bin/env python3
 
'''
For awareness, which DNS are you using?
For example:
The ISP/Internal label means the script performed a reverse lookup.
It asked the IP 10.255.255.254 for its name, and it responded with HW3P674.
This is likely the Device Name of your physical router or the server handling
network traffic in your building.

NOTE: wsl2

In WSL2, Microsoft introduced DNS Tunneling. Instead of WSL trying 
to talk directly to your router or VPN’s DNS over the network (which often broke when the VPN 
changed routing tables), it now sends all DNS queries to a "black box" at 10.255.255.254.  
Windows catches those requests and resolves them using the Windows Host's current DNS settings.  
    VPN Off: Windows uses your ISP/Router DNS; the tunnel passes the result back.
    VPN On: Windows uses the VPN's DNS; the tunnel passes the result back.
Because your script sees the "gateway" IP (10.255.255.254) as the nameserver in both cases, 
it thinks the DNS hasn't changed, even though the upstream resolver on the Windows side likely has.
'''
import ipaddress
import json
import os
import platform
import socket
import subprocess
import urllib.error
import urllib.request
from typing import Any


def is_wsl() -> bool:
    if platform.system() != "Linux":
        return False
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def wsl_dns() -> str | None:
    """First nameserver in /etc/resolv.conf — on WSL2 this is typically the DNS tunnel host."""
    path = "/etc/resolv.conf"
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
    except OSError:
        return None
    return None


def _resolv_nameservers() -> list[str]:
    path = "/etc/resolv.conf"
    if not os.path.isfile(path):
        return []
    out: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1 and parts[1] not in out:
                        out.append(parts[1])
    except OSError:
        return []
    return out


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _parse_arin_response(data: dict[str, Any]) -> str | None:
    net = data.get("net") or {}
    for key in ("orgRef", "registration", "org-name"):
        entry = net.get(key)
        if isinstance(entry, dict):
            owner = entry.get("@name") or entry.get("name")
            if owner:
                return owner
        elif isinstance(entry, str):
            return entry
    return None


def _get_arin_owner(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private:
        return None

    url = f"https://whois.arin.net/rest/ip/{ip}.json"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "my_DNS.py/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            if response.status != 200:
                return None
            data = json.load(response)
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
        return None

    return _parse_arin_response(data)


def _describe_dns_ip(ip: str) -> tuple[str, bool]:
    hostname = _reverse_dns(ip)
    owner = _get_arin_owner(ip)

    try:
        public = not ipaddress.ip_address(ip).is_private
    except ValueError:
        public = False

    if public:
        if hostname and owner:
            description = f"{hostname} (ARIN: {owner})"
        elif hostname:
            description = f"{hostname}"
        elif owner:
            description = f"ARIN: {owner}"
        else:
            description = "Unknown Public Provider"
    else:
        if hostname:
            description = f"ISP/Internal ({hostname})"
        else:
            description = "Private/Unknown Provider"

    return f"{ip} ({description})", public


def get_dns_info():
    dns_ips = []
    system = platform.system()
    final_score = 1  # Default clean score
    is_public_dns = False

    # --- Step 1: Get the IPs ---
    try:
        if system == "Linux":
            if is_wsl():
                # On WSL2, query Windows DNS settings instead of /etc/resolv.conf
                cmd = ["powershell.exe", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"]
                output = subprocess.check_output(cmd, text=True).strip()
                if output:
                    dns_ips = output.splitlines()
                else:
                    # Fallback to resolv.conf if powershell fails
                    dns_ips = _resolv_nameservers()
            elif os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) > 1:
                                dns_ips.append(parts[1])
        elif system == "Windows":
            cmd = ["powershell.exe", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"]
            output = subprocess.check_output(cmd, text=True).strip()
            if output: dns_ips = output.splitlines()
    except Exception as e:
        print(f"SCORE: 3")
        print(f"STATUS: Error detecting DNS: {e}")
        return

    # --- Step 2: Identify and Format ---
    dns_details_strings = []
    has_isp_lookup = False
    has_home_router_dns = False
    for raw_ip in dns_ips:
        ip = raw_ip.strip()
        description, public = _describe_dns_ip(ip)
        dns_details_strings.append(description)
        is_public_dns |= public
        if "ISP/Internal" in description:
            has_isp_lookup = True
        try:
            addr = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            addr = None
        if addr and addr == ipaddress.ip_address("192.168.1.1"):
            has_home_router_dns = True

    # Score: public resolver → 5; ISP-identifying PTR (ISP/Internal) → 5;
    # typical consumer gateway 192.168.1.1 → 4; else baseline 2.
    if is_public_dns:
        final_score = 5
        status_msg = f"Public DNS detected: {', '.join(dns_details_strings)}"
    elif has_isp_lookup:
        final_score = 5
        status_msg = f"System DNS (ISP-identified PTR): {', '.join(dns_details_strings)}"
    elif has_home_router_dns:
        final_score = 4
        status_msg = f"System DNS (192.168.1.1 gateway resolver): {', '.join(dns_details_strings)}"
    else:
        final_score = 2
        status_msg = f"System DNS: {', '.join(dns_details_strings)}"

    # --- Final Print Statements ---
    print(f"SCORE: {final_score}")
    print(f"STATUS: {status_msg}")

if __name__ == "__main__":
    print("--- System DNS Identification ---")
    get_dns_info()