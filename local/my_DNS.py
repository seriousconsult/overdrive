#!/usr/bin/env python3

"""
Which DNS resolvers this system uses, and what those IPs usually mean.

WSL2: Microsoft can use a DNS tunnel (often ``10.255.255.254`` in ``/etc/resolv.conf``) while
``Get-DnsClientServerAddress`` on Windows lists the *effective* resolvers (e.g. your router).
This script prefers Windows client DNS when running under WSL so the report matches what
actually resolves names on the host.
"""

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


def is_wsl() -> bool:
    if platform.system() != "Linux":
        return False
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def wsl_dns() -> str | None:
    """First nameserver in /etc/resolv.conf — on WSL2 often the DNS tunnel host."""
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


def _resolv_search_domains() -> list[str]:
    path = "/etc/resolv.conf"
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


def _classify_resolver(ip: str) -> str:
    base = ip.split("%", 1)[0]
    if base.startswith("10.255.255."):
        return (
            "WSL2 DNS tunnel to Windows — this IP is not your router; Windows forwards "
            "DNS using the host's current resolver list (router, VPN, or public DNS)."
        )
    try:
        a = ipaddress.ip_address(base)
    except ValueError:
        return "Unrecognized address format."
    if a.is_loopback:
        return "Loopback — a resolver running on this machine (e.g. dnsmasq, systemd-resolved stub)."
    if a.is_private:
        return (
            "Private (LAN) address — usually your home router, mesh node, or another "
            "DNS forwarder on your local network."
        )
    return "Public Internet DNS — a third-party or ISP resolver reached over the wider Internet."


# Common public resolvers: (short label, info URL for humans)
_KNOWN_PUBLIC_DNS: dict[str, tuple[str, str]] = {
    "8.8.8.8": ("Google Public DNS", "https://developers.google.com/speed/public-dns"),
    "8.8.4.4": ("Google Public DNS", "https://developers.google.com/speed/public-dns"),
    "1.1.1.1": ("Cloudflare DNS", "https://developers.cloudflare.com/1.1.1.1/"),
    "1.0.0.1": ("Cloudflare DNS", "https://developers.cloudflare.com/1.1.1.1/"),
    "9.9.9.9": ("Quad9", "https://www.quad9.net/"),
    "208.67.222.222": ("OpenDNS", "https://www.opendns.com/"),
    "208.67.220.220": ("OpenDNS", "https://www.opendns.com/"),
}


def _model_and_urls_from_ptr(ptr: str | None, resolver_ip: str) -> tuple[str | None, list[tuple[str, str]]]:
    """
    Heuristic device/model line + labeled (title, url) pairs for home routers.
    PTR names are provisioning hostnames — treat model as a hint, not a guarantee.
    """
    urls: list[tuple[str, str]] = []
    if not ptr:
        return None, urls

    pl = ptr.lower()
    model_hint: str | None = None

    # Verizon FiOS / Quantum Gateway style hostnames
    if "g3100" in pl or "cr1000a" in pl or "mynetworksettings.com" in pl:
        if "g3100" in pl:
            model_hint = (
                "Likely **Verizon FiOS Quantum Gateway G3100** (heuristic: `G3100` in PTR). "
                "Confirm on the device label or admin UI."
            )
        elif "cr1000a" in pl:
            model_hint = (
                "Likely **Verizon FiOS Router CR1000A**-class hostname pattern. "
                "Confirm on the device label or admin UI."
            )
        else:
            model_hint = (
                "Hostname matches **Verizon / FiOS `mynetworksettings.com`** provisioning style; "
                "exact model varies — check the router label or local admin page."
            )
        urls.append(("Router admin (this resolver IP, HTTP)", f"http://{resolver_ip}/"))
        urls.append(("Router admin (this resolver IP, HTTPS)", f"https://{resolver_ip}/"))
        urls.append(
            (
                "Verizon FiOS / home network account portal (branding from PTR)",
                "https://www.mynetworksettings.com/",
            )
        )

    if not model_hint and pl:
        model_hint = (
            "No built-in model table for this PTR. The name below is still useful: it is often "
            "the **provisioning hostname** the ISP or router registers in DNS."
        )

    return model_hint, urls


def _describe_dns_ip(ip: str) -> tuple[str, bool]:
    """Legacy one-line summary + public flag (for scoring)."""
    hostname = _reverse_dns(ip)
    owner = _get_arin_owner(ip)

    try:
        public = not ipaddress.ip_address(ip.split("%", 1)[0]).is_private
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


def _print_resolver_report(index: int, ip: str) -> None:
    ptr = _reverse_dns(ip)
    arin = _get_arin_owner(ip)
    try:
        public = not ipaddress.ip_address(ip.split("%", 1)[0]).is_private
    except ValueError:
        public = False

    print(f"\n--- Resolver #{index}: {ip} ---")
    print(f"  What this IP usually is: {_classify_resolver(ip)}")
    print(f"  Public Internet address: {'yes' if public else 'no (RFC1918 / special)'}")

    if ptr:
        print(f"  PTR (reverse DNS name for this IP): {ptr}")
    else:
        print("  PTR (reverse DNS): (none — common for consumer routers or blocked PTR)")

    if arin:
        print(f"  WHOIS (ARIN) organization: {arin}")

    if ip in _KNOWN_PUBLIC_DNS:
        label, doc_url = _KNOWN_PUBLIC_DNS[ip]
        print(f"  Known public service: {label}")
        print(f"  Reference: {doc_url}")

    model_hint, labeled_urls = _model_and_urls_from_ptr(ptr, ip)
    if model_hint:
        print(f"  Model / device hint: {model_hint}")
    if labeled_urls:
        print("  URLs to try (common for this PTR pattern):")
        for title, url in labeled_urls:
            print(f"    • {title}")
            print(f"      {url}")
    elif not public and ptr:
        print("  URLs to try:")
        print(f"    • Router / gateway admin (this IP): http://{ip}/")
        print(f"    • Router / gateway admin (this IP): https://{ip}/")


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        x = x.strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def get_dns_info() -> None:
    dns_ips: list[str] = []
    system = platform.system()
    final_score = 1
    is_public_dns = False
    detection_source = "unknown"

    try:
        if system == "Linux":
            if is_wsl():
                detection_source = "Windows (Get-DnsClientServerAddress via PowerShell) — WSL2"
                cmd = [
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "Get-DnsClientServerAddress -AddressFamily IPv4 | "
                    "Select-Object -ExpandProperty ServerAddresses",
                ]
                output = subprocess.check_output(cmd, text=True, timeout=25).strip()
                if output:
                    dns_ips = _dedupe_preserve_order(output.splitlines())
                else:
                    detection_source = "Linux /etc/resolv.conf (PowerShell returned no IPv4 servers)"
                    dns_ips = _resolv_nameservers()
            elif os.path.exists("/etc/resolv.conf"):
                detection_source = "Linux /etc/resolv.conf"
                with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) > 1:
                                dns_ips.append(parts[1])
                dns_ips = _dedupe_preserve_order(dns_ips)
        elif system == "Windows":
            detection_source = "Windows (Get-DnsClientServerAddress)"
            cmd = [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Get-DnsClientServerAddress -AddressFamily IPv4 | "
                "Select-Object -ExpandProperty ServerAddresses",
            ]
            output = subprocess.check_output(cmd, text=True, timeout=25).strip()
            if output:
                dns_ips = _dedupe_preserve_order(output.splitlines())
    except Exception as e:
        print(f"SCORE: 3")
        print(f"STATUS: Error detecting DNS: {e}")
        return

    print("\nHow this list was built")
    print(f"  Source: {detection_source}")
    if is_wsl():
        tunnel = wsl_dns()
        if tunnel:
            print(
                f"  WSL ``/etc/resolv.conf`` first nameserver (DNS tunnel / stub): {tunnel}\n"
                "    (Queries from the distro often go here first; Windows may still be the "
                "resolver that talks to your router or the Internet.)"
            )
        search = _resolv_search_domains()
        if search:
            print(f"  Search domains from resolv.conf: {', '.join(search)}")

    if not dns_ips:
        print("\nNo IPv4 DNS server addresses found.")
        print("SCORE: 1")
        print("STATUS: No resolvers detected.")
        return

    print(f"\nConfigured IPv4 DNS servers ({len(dns_ips)} unique, order preserved where possible):")
    for i, ip in enumerate(dns_ips, start=1):
        _print_resolver_report(i, ip)

    dns_details_strings: list[str] = []
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

    if is_public_dns:
        final_score = 5
        status_msg = (
            "Public DNS in use — at least one resolver is a public Internet address. "
            f"Summary: {', '.join(dns_details_strings)}"
        )
    elif has_isp_lookup:
        final_score = 5
        status_msg = (
            "Private resolver(s) with **ISP-style PTR** (reverse DNS gave a hostname on your LAN "
            "or ISP edge). That hostname often encodes the router **model family** (e.g. G3100), "
            "not a full SKU. "
            f"Summary: {', '.join(dns_details_strings)}"
        )
    elif has_home_router_dns:
        final_score = 4
        status_msg = (
            f"Resolver includes typical gateway **192.168.1.1** (your router may be answering DNS). "
            f"Summary: {', '.join(dns_details_strings)}"
        )
    else:
        final_score = 2
        status_msg = f"Private / unknown resolver pattern. Summary: {', '.join(dns_details_strings)}"

    print("\n--- Score (detection script heuristic) ---")
    print(f"SCORE: {final_score}")
    print(f"STATUS: {status_msg}")


if __name__ == "__main__":
    print("--- System DNS Identification ---")
    get_dns_info()
