"""UPnP, SSDP, and small router HTTP parsing helpers."""

from __future__ import annotations

import re
import socket
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any


def extract_realm(www_auth: str) -> str:
    """Extract realm from a WWW-Authenticate header."""
    m = re.search(r'realm\s*=\s*"([^"]*)"', www_auth, re.I)
    if m:
        return m.group(1)
    m = re.search(r"realm\s*=\s*'([^']*)'", www_auth, re.I)
    if m:
        return m.group(1)
    return www_auth[:200]


def upnp_description_urls(ip: str) -> list[str]:
    """Common UPnP device-description URLs for residential gateways."""
    return [
        f"http://{ip}:49152/description.xml",
        f"http://{ip}/description.xml",
        f"http://{ip}/rootDesc.xml",
        f"http://{ip}/igddesc.xml",
        f"http://{ip}:5000/rootDesc.xml",
        f"http://{ip}:8080/description.xml",
    ]


def parse_upnp_device_xml(xml_text: str) -> dict[str, str]:
    """Parse common fields from a UPnP device-description XML body."""
    fields: dict[str, str] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return fields
    interesting = {
        "friendlyname",
        "manufacturer",
        "modelname",
        "modelnumber",
        "modeldescription",
        "serialnumber",
        "presentationurl",
    }
    for el in root.iter():
        local = el.tag.split("}")[-1].lower()
        if local not in interesting:
            continue
        value = (el.text or "").strip()
        if value:
            fields[local] = value
    return fields


def fetch_upnp_device_info(ip: str, *, timeout: float = 6) -> tuple[str | None, dict[str, str]]:
    """Fetch common UPnP description URLs and return ``(raw_xml, parsed_fields)``."""
    try:
        import requests
    except ModuleNotFoundError:
        return None, {}
    headers = {"User-Agent": "overdrive-router-utils/1.0"}
    for url in upnp_description_urls(ip):
        try:
            response = requests.get(url, timeout=timeout, headers=headers)
        except requests.RequestException:
            continue
        if response.status_code != 200 or not (response.text or "").strip():
            continue
        body = response.text.strip()
        if not body.lstrip().startswith("<"):
            continue
        parsed = parse_upnp_device_xml(body)
        if parsed or "<device>" in body.lower() or "root xmlns" in body[:500].lower():
            return body, parsed
    return None, {}


def parse_ssdp_headers(raw: str) -> dict[str, str]:
    """Parse SSDP response headers."""
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        hdrs[k.strip().upper()] = v.strip()
    return hdrs


def send_msearch(sock: socket.socket, payload: bytes, unicast_targets: list[str]) -> None:
    """Send SSDP M-SEARCH packets."""
    sock.sendto(payload, ("239.255.255.250", 1900))
    for ip in unicast_targets:
        if not ip:
            continue
        try:
            sock.sendto(payload, (ip, 1900))
        except OSError:
            pass


def collect_ssdp(
    listen_s: float,
    unicast_targets: list[str],
) -> list[tuple[str, dict[str, str], str]]:
    """Collect SSDP responses. Returns list of ``(remote_ip, headers, raw_snippet)``."""
    out: list[tuple[str, dict[str, str], str]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        except OSError:
            pass
        sock.bind(("", 0))
        sock.settimeout(0.35)

        msearch_root = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: upnp:rootdevice\r\n"
            "\r\n"
        ).encode("ascii")

        msearch_all = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode("ascii")

        send_msearch(sock, msearch_root, unicast_targets)
        time.sleep(0.05)
        send_msearch(sock, msearch_all, unicast_targets)

        deadline = time.monotonic() + max(0.5, listen_s)
        seen: set[tuple[str, str]] = set()
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(min(0.45, remaining))
            try:
                data, addr = sock.recvfrom(16384)
            except socket.timeout:
                continue
            text = data.decode("utf-8", errors="replace")
            if not text.upper().startswith("HTTP/"):
                continue
            hdrs = parse_ssdp_headers(text)
            loc = hdrs.get("LOCATION", "")
            key = (addr[0], loc)
            if key in seen:
                continue
            seen.add(key)
            snippet = text[:500].replace("\r\n", " ")
            out.append((addr[0], hdrs, snippet))
    finally:
        sock.close()
    return out


def fetch_location(url: str, timeout: float, insecure: bool) -> tuple[str | None, str | None]:
    """Fetch content from a URL."""
    try:
        ctx = None
        if insecure and url.lower().startswith("https"):
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "overdrive-router-discovery/1.0"},
        )
        kwargs: dict[str, Any] = {"timeout": timeout}
        if ctx is not None:
            kwargs["context"] = ctx
        with urllib.request.urlopen(req, **kwargs) as resp:
            body = resp.read(256_000).decode("utf-8", errors="replace")
        return body, None
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as e:
        return None, str(e)


def xml_text_fields(xml: str) -> dict[str, str]:
    """Extract text fields from UPnP XML."""
    fields: dict[str, str] = {}
    for tag in ("friendlyName", "modelName", "modelNumber", "modelDescription", "manufacturer", "serialNumber"):
        m = re.findall(
            rf"<(?:[^/>]+:)?{tag}\s*>([^<]*)</(?:[^/>]+:)?{tag}\s*>",
            xml,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if m:
            fields[tag] = " / ".join(x.strip() for x in m if x.strip())[:400]
    if not fields:
        try:
            root = ET.fromstring(xml)
            for el in root.iter():
                tag = el.tag.split("}")[-1].lower()
                if tag in (
                    "friendlyname",
                    "modelname",
                    "modelnumber",
                    "modeldescription",
                    "manufacturer",
                    "serialnumber",
                ):
                    text = (el.text or "").strip()
                    if text:
                        fields[tag] = text[:400]
        except ET.ParseError:
            pass
    return fields
