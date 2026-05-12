#!/usr/bin/env python3
"""Shared router detection helper utilities for the router scripts."""

from __future__ import annotations

import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT = 10
DEFAULT_UA = {"User-Agent": "overdrive-router-utils/1.0"}


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
    mac = mac.strip().upper()
    mac = mac.replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 3:
        raise ValueError(f"Bad MAC format: {mac!r}")
    return f"{parts[0]}:{parts[1]}:{parts[2]}"


def try_ip_neigh(ip: str, iface: str | None = None) -> str | None:
    """Try to get MAC address from ip neigh command."""
    try:
        cmd = ["ip", "neigh", "show", "to", ip]
        if iface:
            cmd.extend(["dev", iface])
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
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
            f.readline()  # header
            for line in f:
                cols = line.split()
                if len(cols) < 4:
                    continue
                row_ip, _hwtype, flags, hw_addr = cols[0], cols[1], cols[2], cols[3]
                if row_ip != ip:
                    continue
                if flags == "0x0":
                    continue
                if hw_addr == "00:00:00:00:00:00":
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
    """
    Try to resolve MAC address for an IP.
    Returns (mac or None, error strings for diagnostics).
    """
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


def _extract_realm(www_auth: str) -> str:
    """Extract realm from WWW-Authenticate header."""
    m = re.search(r'realm\s*=\s*"([^"]*)"', www_auth, re.I)
    if m:
        return m.group(1)
    m = re.search(r"realm\s*=\s*'([^']*)'", www_auth, re.I)
    if m:
        return m.group(1)
    return www_auth[:200]


def _parse_ssdp_headers(raw: str) -> dict[str, str]:
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


def _send_msearch(sock: socket.socket, payload: bytes, unicast_targets: list[str]) -> None:
    """Send SSDP M-SEARCH packets."""
    sock.sendto(payload, ("239.255.255.250", 1900))
    for ip in unicast_targets:
        if not ip:
            continue
        try:
            sock.sendto(payload, (ip, 1900))
        except OSError:
            pass


def _collect_ssdp(
    listen_s: float,
    unicast_targets: list[str],
) -> list[tuple[str, dict[str, str], str]]:
    """Collect SSDP responses. Returns list of (remote_ip, headers, raw_snippet)."""
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

        # SSDP M-SEARCH payloads
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

        _send_msearch(sock, msearch_root, unicast_targets)
        time.sleep(0.05)
        _send_msearch(sock, msearch_all, unicast_targets)

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
            hdrs = _parse_ssdp_headers(text)
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


def _fetch_location(url: str, timeout: float, insecure: bool) -> tuple[str | None, str | None]:
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


def _xml_text_fields(xml: str) -> dict[str, str]:
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


def _reexec_to_repo_venv_python() -> None:
    """Re-execute script with repo virtual_env Python if available."""
    script = Path(__file__).resolve()
    vpy = script.parents[1] / "virtual_env" / "bin" / "python"
    if not vpy.is_file():
        return
    try:
        if Path(sys.executable).resolve() == vpy.resolve():
            return
    except OSError:
        return
    try:
        os.execv(str(vpy), [str(vpy), str(script), *sys.argv[1:]])
    except OSError:
        pass


def _print_sniff_permission_help() -> None:
    """Print help for packet capture permissions."""
    script = Path(__file__).resolve()
    repo = script.parents[1]
    vpy = repo / "virtual_env" / "bin" / "python"
    print("[!] Packet capture needs raw sockets (Linux: root or cap_net_raw+cap_net_admin on the venv Python).")
    print("    From repo root, for example:")
    print(f"        sudo -n {vpy} {script}")
    print("    Or grant capabilities once (then you can run without sudo):")
    print(f"        sudo setcap cap_net_raw,cap_net_admin+eip {vpy}")
    print("    See README: Passwordless sudo / capture scripts.")


def _background_probe_loop(stop: threading.Event, urls: tuple[str, ...], pause_s: float) -> None:
    """Background HTTP probe loop for packet capture."""
    n = 0
    while not stop.is_set():
        url = urls[n % len(urls)]
        n += 1
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "overdrive-router-probe/1.0", "Connection": "close"},
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                resp.read(8192)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            pass
        if stop.wait(pause_s):
            break