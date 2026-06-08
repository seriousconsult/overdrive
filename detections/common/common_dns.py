"""Shared DNS resolver inspection helpers."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import socket
import subprocess
import urllib.error
import urllib.request
from typing import Any

from detections.common.common_local import is_wsl_local
from detections.common.common_utils import dedupe_preserve_order

KNOWN_PUBLIC_DNS: dict[str, tuple[str, str]] = {
    "8.8.8.8": ("Google Public DNS", "https://developers.google.com/speed/public-dns"),
    "8.8.4.4": ("Google Public DNS", "https://developers.google.com/speed/public-dns"),
    "1.1.1.1": ("Cloudflare DNS", "https://developers.cloudflare.com/1.1.1.1/"),
    "1.0.0.1": ("Cloudflare DNS", "https://developers.cloudflare.com/1.1.1.1/"),
    "9.9.9.9": ("Quad9", "https://www.quad9.net/"),
    "208.67.222.222": ("OpenDNS", "https://www.opendns.com/"),
    "208.67.220.220": ("OpenDNS", "https://www.opendns.com/"),
}


def resolv_nameservers(path: str = "/etc/resolv.conf") -> list[str]:
    """Return nameserver entries from a resolv.conf-style file."""
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


def first_resolv_nameserver(path: str = "/etc/resolv.conf") -> str | None:
    """Return the first nameserver from resolv.conf, or None."""
    nameservers = resolv_nameservers(path)
    return nameservers[0] if nameservers else None


def windows_dns_servers() -> list[str]:
    """Return Windows IPv4 DNS servers via PowerShell."""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Select-Object -ExpandProperty ServerAddresses",
    ]
    output = subprocess.check_output(cmd, text=True, timeout=25).strip()
    return dedupe_preserve_order(output.splitlines()) if output else []


def configured_dns_servers(system: str | None = None) -> tuple[list[str], str]:
    """Return configured IPv4 DNS servers and a source label."""
    system = system or platform.system()
    if system == "Linux":
        if is_wsl_local():
            dns_ips = windows_dns_servers()
            if dns_ips:
                return dns_ips, "Windows (Get-DnsClientServerAddress via PowerShell) - WSL2"
            return resolv_nameservers(), "Linux /etc/resolv.conf (PowerShell returned no IPv4 servers)"
        if os.path.exists("/etc/resolv.conf"):
            return dedupe_preserve_order(resolv_nameservers()), "Linux /etc/resolv.conf"
    if system == "Windows":
        return windows_dns_servers(), "Windows (Get-DnsClientServerAddress)"
    return [], "unknown"


def resolv_search_domains(path: str = "/etc/resolv.conf") -> list[str]:
    """Return search domains from a resolv.conf-style file."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("search "):
                    return line.split()[1:]
    except OSError:
        return []
    return []


def reverse_dns(ip: str) -> str | None:
    """Resolve PTR/reverse DNS for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def parse_arin_response(data: dict[str, Any]) -> str | None:
    """Extract owner/org text from ARIN REST JSON."""
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


def get_arin_owner(ip: str, *, timeout: float = 8, user_agent: str = "overdrive-dns/1.0") -> str | None:
    """Return ARIN owner/org for public IPs; private/invalid IPs return None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private:
        return None

    request = urllib.request.Request(
        f"https://whois.arin.net/rest/ip/{ip}.json",
        headers={"User-Agent": user_agent},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            data = json.load(response)
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError):
        return None
    return parse_arin_response(data)


def classify_resolver(ip: str) -> str:
    """Human-readable resolver address class."""
    base = ip.split("%", 1)[0]
    if base.startswith("10.255.255."):
        return (
            "WSL2 DNS tunnel to Windows - this IP is not your router; Windows forwards "
            "DNS using the host's current resolver list (router, VPN, or public DNS)."
        )
    try:
        addr = ipaddress.ip_address(base)
    except ValueError:
        return "Unrecognized address format."
    if addr.is_loopback:
        return "Loopback - a resolver running on this machine (e.g. dnsmasq, systemd-resolved stub)."
    if addr.is_private:
        return "Private (LAN) address - usually your home router, mesh node, or another DNS forwarder."
    return "Public Internet DNS - a third-party or ISP resolver reached over the wider Internet."


def model_and_urls_from_ptr(ptr: str | None, resolver_ip: str) -> tuple[str | None, list[tuple[str, str]]]:
    """Return a router model hint and useful URLs derived from a PTR hostname."""
    urls: list[tuple[str, str]] = []
    if not ptr:
        return None, urls

    pl = ptr.lower()
    model_hint: str | None = None
    if "g3100" in pl or "cr1000a" in pl or "mynetworksettings.com" in pl:
        if "g3100" in pl:
            model_hint = "Likely Verizon FiOS Quantum Gateway G3100 (heuristic: G3100 in PTR)."
        elif "cr1000a" in pl:
            model_hint = "Likely Verizon FiOS Router CR1000A-class hostname pattern."
        else:
            model_hint = "Hostname matches Verizon / FiOS mynetworksettings.com provisioning style."
        urls.append(("Router admin (this resolver IP, HTTP)", f"http://{resolver_ip}/"))
        urls.append(("Router admin (this resolver IP, HTTPS)", f"https://{resolver_ip}/"))
        urls.append(("Verizon FiOS / home network account portal", "https://www.mynetworksettings.com/"))

    if not model_hint and pl:
        model_hint = (
            "No built-in model table for this PTR. It is often the provisioning hostname "
            "the ISP or router registers in DNS."
        )
    return model_hint, urls


def describe_dns_ip(ip: str) -> tuple[str, bool]:
    """Return a one-line resolver description and whether the resolver is public."""
    hostname = reverse_dns(ip)
    owner = get_arin_owner(ip)
    try:
        public = not ipaddress.ip_address(ip.split("%", 1)[0]).is_private
    except ValueError:
        public = False

    if public:
        if hostname and owner:
            description = f"{hostname} (ARIN: {owner})"
        elif hostname:
            description = hostname
        elif owner:
            description = f"ARIN: {owner}"
        else:
            description = "Unknown Public Provider"
    else:
        description = f"ISP/Internal ({hostname})" if hostname else "Private/Unknown Provider"

    return f"{ip} ({description})", public
