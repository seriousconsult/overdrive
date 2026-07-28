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
    # Mullvad public DoT/DoH anycast (plain :53 is not a full recursive resolver).
    "194.242.2.2": ("Mullvad DNS (unfiltered DoT/DoH)", "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls"),
    "194.242.2.3": ("Mullvad DNS (adblock DoT/DoH)", "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls"),
    "194.242.2.4": ("Mullvad DNS (base DoT/DoH)", "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls"),
    "194.242.2.5": ("Mullvad DNS (extended DoT/DoH)", "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls"),
    "194.242.2.6": ("Mullvad DNS (family DoT/DoH)", "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls"),
    "194.242.2.9": ("Mullvad DNS (all blockers DoT/DoH)", "https://mullvad.net/en/help/dns-over-https-and-dns-over-tls"),
}

MULLVAD_DOT_IPV4: frozenset[str] = frozenset(
    {
        "194.242.2.2",
        "194.242.2.3",
        "194.242.2.4",
        "194.242.2.5",
        "194.242.2.6",
        "194.242.2.9",
    }
)

# Mullvad public DNS anycast → DoT endpoint used to discover the current PoP unicast.
MULLVAD_DOT_REF_IP = "194.242.2.2"
MULLVAD_DOT_REF_SNI = "dns.mullvad.net"


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


def is_mullvad_dot_ip(ip: str) -> bool:
    """True if IP is a known Mullvad public DoT/DoH anycast address."""
    return ip.split("%", 1)[0] in MULLVAD_DOT_IPV4


def _is_public_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return addr.version == 4 and not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def parse_public_ipv4_from_dns_output(text: str) -> str | None:
    """Last public IPv4 in dig/nslookup-style output (skip LAN/loopback answers)."""
    import re

    last: str | None = None
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or ""):
        ip = m.group(0)
        if _is_public_ipv4(ip):
            last = ip
    return last


def query_whoami_akamai(
    *,
    nameserver: str | None = None,
    timeout: float = 6.0,
) -> tuple[str | None, str]:
    """
    Resolve whoami.akamai.net via the system (or optional nameserver).

    Returns (upstream_ip_or_none, detail). The IP is the recursive resolver Akamai
    saw — for Mullvad anycast this is often the PoP unicast (e.g. 193.148.18.30),
    not 194.242.2.x.
    """
    dig = ["dig", "+time=3", "+tries=2", "+short"]
    if nameserver:
        dig.append(f"@{nameserver}")
    dig.extend(["whoami.akamai.net", "A"])
    try:
        out = subprocess.check_output(
            dig, text=True, timeout=timeout, stderr=subprocess.DEVNULL
        )
        ip = parse_public_ipv4_from_dns_output(out)
        if ip:
            return ip, f"dig{' @' + nameserver if nameserver else ''}"
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    ns = ["nslookup", "whoami.akamai.net"]
    if nameserver:
        ns.append(nameserver)
    try:
        out = subprocess.check_output(
            ns, text=True, timeout=timeout, stderr=subprocess.STDOUT
        )
        ip = parse_public_ipv4_from_dns_output(out)
        if ip:
            return ip, f"nslookup{' ' + nameserver if nameserver else ''}"
        return None, f"nslookup returned no public A: {out[-200:].strip()!r}"
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return None, f"whoami probe failed: {exc}"


def mullvad_dot_whoami_pop(*, timeout: float = 8.0) -> tuple[str | None, str]:
    """
    Query whoami.akamai.net over DoT to Mullvad anycast 194.242.2.2.

    Returns the PoP unicast IP Mullvad currently answers as (same IP Alpine
    dig +short whoami should show when using Mullvad DNS).
    """
    import re
    import ssl
    import struct

    def _dns_query_a(name: str) -> bytes:
        labels = name.encode().split(b".")
        qname = b"".join(bytes([len(lab)]) + lab for lab in labels) + b"\x00"
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        return header + qname + struct.pack("!HH", 1, 1)

    def _parse_a(data: bytes) -> list[str]:
        ips: list[str] = []
        # Answer rdata: TYPE A (1) CLASS IN (1) TTL(4) RDLEN 4 + 4 octets
        for m in re.finditer(rb"\x00\x01\x00\x01....\x00\x04(.{4})", data, re.DOTALL):
            cand = ".".join(str(b) for b in m.group(1))
            if _is_public_ipv4(cand) and cand not in ips:
                ips.append(cand)
        if not ips and len(data) >= 4:
            cand = ".".join(str(b) for b in data[-4:])
            if _is_public_ipv4(cand):
                ips.append(cand)
        return ips

    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((MULLVAD_DOT_REF_IP, 853), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=MULLVAD_DOT_REF_SNI) as ssock:
            q = _dns_query_a("whoami.akamai.net")
            ssock.sendall(struct.pack("!H", len(q)) + q)
            hdr = ssock.recv(2)
            if len(hdr) < 2:
                return None, "DoT short length header"
            (ln,) = struct.unpack("!H", hdr)
            data = b""
            while len(data) < ln:
                chunk = ssock.recv(ln - len(data))
                if not chunk:
                    break
                data += chunk
        ips = _parse_a(data)
        if ips:
            return ips[0], f"DoT {MULLVAD_DOT_REF_IP} SNI={MULLVAD_DOT_REF_SNI}"
        return None, "DoT whoami: no A record parsed"
    except OSError as exc:
        return None, f"DoT whoami failed: {exc}"


def classify_upstream_resolver(
    ip: str,
    *,
    mullvad_pop_reference: str | None = None,
) -> dict[str, Any]:
    """
    Classify a whoami.akamai.net answer IP as Mullvad / ISP / other.

    Mullvad anycast answers often show the PoP unicast (e.g. 193.148.18.30 =
    us-nyc-dns-601.mullvad.net), not 194.242.2.x. Matching the live DoT reference
    PoP is the reliable check when PTR is NXDOMAIN.
    """
    base = ip.split("%", 1)[0]
    ptr = reverse_dns(base)
    arin = get_arin_owner(base)
    kind = "other_public"
    note = "Public resolver; not identified as Mullvad public DNS."
    is_mullvad = False
    is_mullvad_public_dns = False

    if is_mullvad_dot_ip(base):
        kind = "mullvad_anycast"
        is_mullvad = True
        is_mullvad_public_dns = True
        note = "Mullvad public DNS anycast (194.242.2.x)."
    elif mullvad_pop_reference and base == mullvad_pop_reference:
        kind = "mullvad_pop"
        is_mullvad = True
        is_mullvad_public_dns = True
        note = (
            f"Matches live Mullvad DoT whoami PoP ({mullvad_pop_reference}). "
            "Anycast 194.242.2.x often answers as this unicast."
        )
    elif ptr and "mullvad" in ptr.lower() and "dns" in ptr.lower():
        kind = "mullvad_pop"
        is_mullvad = True
        is_mullvad_public_dns = True
        note = f"PTR {ptr} is a Mullvad public DNS hostname."
    elif ptr and "mullvad" in ptr.lower():
        kind = "mullvad_other"
        is_mullvad = True
        is_mullvad_public_dns = False
        note = f"PTR {ptr} is Mullvad-related (likely VPN DNS, not public DoT/DoH anycast)."
    elif base.startswith(("71.", "96.")) or (arin and "verizon" in arin.lower()):
        kind = "isp"
        note = "Looks like ISP resolver (e.g. Verizon) — not Mullvad DNS."
    elif not _is_public_ipv4(base):
        kind = "private_or_invalid"
        note = "Not a public recursive resolver IP."

    return {
        "ip": base,
        "kind": kind,
        "is_mullvad_dns": is_mullvad,
        "is_mullvad_public_doh_dot": is_mullvad_public_dns,
        "ptr": ptr,
        "arin": arin,
        "note": note,
    }


def mullvad_connection_check(*, timeout: float = 8.0) -> tuple[dict[str, Any] | None, str | None]:
    """
    Fetch https://am.i.mullvad.net/json — VPN *exit* identity, not DNS upstream.

    mullvad_exit_ip=false with an ISP organization is normal when using Mullvad
    DNS-only (DoT/DoH) without the VPN.
    """
    request = urllib.request.Request(
        "https://am.i.mullvad.net/json",
        headers={"User-Agent": "overdrive-dns/1.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.load(response)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        return None, str(exc)
    if not isinstance(data, dict):
        return None, "unexpected JSON shape"
    return data, None


def windows_doh_servers() -> list[dict[str, str]]:
    """Return Windows DoH server rows when PowerShell can query them."""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        "Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | "
        "Select-Object ServerAddress,DohTemplate,AllowFallbackToUdp | ConvertTo-Json -Compress",
    ]
    try:
        output = subprocess.check_output(cmd, text=True, timeout=25, stderr=subprocess.DEVNULL).strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []
    if not output:
        return []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    rows: list[dict[str, str]] = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        addr = str(item.get("ServerAddress") or "").strip()
        template = str(item.get("DohTemplate") or "").strip()
        if not addr and not template:
            continue
        rows.append(
            {
                "server": addr,
                "template": template,
                "allow_udp_fallback": str(item.get("AllowFallbackToUdp", "")),
            }
        )
    return rows


def mullvad_dns_leak_probe(
    *,
    samples: int = 4,
    timeout: float = 8.0,
    user_agent: str = "overdrive-dns/1.0",
) -> tuple[list[dict[str, Any]], str | None]:
    """
    Probe Mullvad's DNS-leak API (same idea as mullvad.net/check).

    Returns (unique server dicts, error_message_or_none).
    Each server may include: ip, hostname, mullvad_dns, mullvad_dns_hostname, country, organization.
    """
    import uuid

    collected: list[dict[str, Any]] = []
    last_err: str | None = None
    for _ in range(max(1, samples)):
        host = f"{uuid.uuid4()}.dnsleak.am.i.mullvad.net"
        request = urllib.request.Request(
            f"https://{host}/",
            headers={"User-Agent": user_agent, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            last_err = str(exc)
            continue
        if isinstance(payload, list):
            collected.extend(x for x in payload if isinstance(x, dict))
        elif isinstance(payload, dict):
            # Some responses wrap a list; otherwise treat as one server row.
            inner = payload.get("servers") or payload.get("dns") or payload.get("dns_servers")
            if isinstance(inner, list):
                collected.extend(x for x in inner if isinstance(x, dict))
            else:
                collected.append(payload)

    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in collected:
        ip = str(row.get("ip") or row.get("address") or "").strip()
        key = ip or json.dumps(row, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)
    if not unique and last_err:
        return [], last_err
    return unique, None


def classify_mullvad_dns_observation(servers: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize Mullvad leak-probe servers into upstream / encryption verdicts."""
    using_mullvad = False
    using_mullvad_doh_dot = False  # public encrypted DNS hostnames contain "dns"
    using_mullvad_vpn_dns = False
    third_party: list[str] = []
    mullvad_rows: list[str] = []

    for row in servers:
        ip = str(row.get("ip") or "").strip()
        host = str(
            row.get("mullvad_dns_hostname")
            or row.get("hostname")
            or row.get("mullvad_dns_host")
            or ""
        ).strip()
        is_mullvad = bool(row.get("mullvad_dns")) or ("mullvad" in host.lower())
        org = str(row.get("organization") or "").strip()
        label = host or org or ip or "(unknown)"
        if is_mullvad:
            using_mullvad = True
            mullvad_rows.append(label)
            # Public DoT/DoH anycast hostnames look like se-mma-dns-001.mullvad.net
            if "dns" in host.lower():
                using_mullvad_doh_dot = True
            else:
                using_mullvad_vpn_dns = True
        else:
            third_party.append(label)

    if using_mullvad_doh_dot and not third_party:
        encryption = "encrypted"
        encryption_note = (
            "Observed resolver hostname looks like Mullvad public DNS (DoT/DoH). "
            "Queries to Mullvad are encrypted; path to a local forwarder may still be plain DNS."
        )
    elif using_mullvad_doh_dot and third_party:
        encryption = "partial"
        encryption_note = (
            "Mixed resolvers: some Mullvad encrypted DNS, plus non-Mullvad upstream(s)."
        )
    elif using_mullvad_vpn_dns and not third_party:
        encryption = "tunnel"
        encryption_note = (
            "DNS appears to be Mullvad VPN resolver (inside the VPN tunnel), not the "
            "public DoT/DoH anycast service."
        )
    elif using_mullvad and third_party:
        encryption = "partial"
        encryption_note = "Some Mullvad DNS seen alongside other resolvers (possible leak)."
    elif third_party:
        encryption = "plaintext_or_other"
        encryption_note = (
            "No Mullvad DNS observed — upstream is ISP/router/public DNS "
            "(typically plain DNS on the wire unless the OS uses DoH/DoT to that provider)."
        )
    else:
        encryption = "unknown"
        encryption_note = "Could not classify upstream from leak probe."

    if using_mullvad_doh_dot and not third_party:
        upstream = "mullvad_public_doh_dot"
    elif using_mullvad_vpn_dns and not third_party:
        upstream = "mullvad_vpn_dns"
    elif using_mullvad and third_party:
        upstream = "mixed_mullvad_and_other"
    elif third_party:
        upstream = "other"
    else:
        upstream = "unknown"

    return {
        "using_mullvad_dns": using_mullvad,
        "using_mullvad_encrypted_public_dns": using_mullvad_doh_dot,
        "encryption": encryption,
        "encryption_note": encryption_note,
        "upstream_kind": upstream,
        "mullvad_servers": mullvad_rows,
        "other_servers": third_party,
        "server_count": len(servers),
    }
