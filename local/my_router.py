#!/usr/bin/env python3
"""
Resolve the LAN default gateway, show router MAC + vendor and UPnP model info, then
run ``nmap -p- -A -T4 -v`` on the gateway and print a **forensic digest** (classification,
CPE inventory, attack surface, service fingerprints)—not raw nmap output (slow).

NOTE: run with  sudo <full path to >/virtual_env/bin/python ./my_router.py
(requires ``nmap`` on PATH).
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import requests
from scapy.all import ARP, Ether, srp

from common.common_local import (
    is_wsl_local,
    mac_oui_colon_prefix,
    normalize_mac_colon,
)

# First 3 octets (lowercase) -> organization. OUI names the *vendor*, not device model.
KNOWN_OUI: dict[str, str] = {
    "00:15:5d": "Microsoft — Hyper-V dynamic virtual NIC (typical WSL2 / vSwitch gateway)",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox (PCS / virtual NIC)",
    "52:54:00": "QEMU / KVM (common virtual NIC)",
    "00:1c:42": "Parallels",
    "00:16:3e": "Xen virtual NIC",
}


def vendor_from_mac(mac: str) -> str:
    """Resolve vendor from MAC: built-in OUI hints, then macvendors.com API."""
    oui = mac_oui_colon_prefix(mac)
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
        text = ar.stdout or ""
        m = re.search(
            rf"{re.escape(ip)}\s+([0-9A-Fa-f:-]{{17}})\s+(?:dynamic|dynamisch)",
            text,
            re.I,
        )
        if m:
            return normalize_mac_colon(m.group(1))
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
            return normalize_mac_colon(m.group(1))
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
                return normalize_mac_colon(hw)
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
    if is_wsl_local():
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


def _nmap_xml_for_etree(xml_text: str) -> str:
    """Drop default xmlns on ``<nmaprun>`` so ElementTree ``findall('host')`` works."""
    return re.sub(
        r'(<nmaprun\b[^>]*?)\s+xmlns="[^"]+"',
        r"\1",
        xml_text,
        count=1,
    )


def _xml_local_tag(tag: str) -> str:
    return tag.split("}")[-1]


def _collect_host_cpes(host: ET.Element) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for el in host.iter():
        if _xml_local_tag(el.tag) != "cpe":
            continue
        t = (el.text or "").strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


# Ports often seen on SOHO routers; anything else is called out for triage.
_COMMON_ROUTER_PORTS: frozenset[int] = frozenset(
    {
        21,
        22,
        23,
        25,
        53,
        80,
        111,
        139,
        443,
        445,
        554,
        631,
        853,
        1883,
        1900,
        2000,
        3000,
        3333,
        4567,
        49152,
        5000,
        5106,
        5353,
        8008,
        8080,
        8443,
        8888,
        9000,
        9100,
    }
)


def _nmap_script_forensic_fact(script_id: str, raw: str) -> str | None:
    """One synthesized line per script; no raw nmap script dumps."""
    o = raw.strip()
    if not o:
        return None
    sid = script_id.strip()

    if sid == "http-title":
        t = re.sub(r"\s+", " ", o)[:140]
        return f"HTTP title: {t}" if t else None

    if sid == "ssl-cert":
        subj = iss = None
        for line in o.splitlines():
            ls = line.strip()
            if ls.startswith("Subject:"):
                subj = ls[8:].strip()[:100]
            elif ls.startswith("Issuer:"):
                iss = ls[7:].strip()[:100]
        if subj and iss:
            return f"TLS cert: {subj} | CA: {iss}"
        if subj:
            return f"TLS cert subject: {subj}"
        return None

    if sid == "ssl-date":
        t = re.sub(r"\s+", " ", o)[:100]
        return f"TLS clock: {t}" if t else None

    if sid in ("ssh-hostkey", "ssh2-enum-algos"):
        for line in o.splitlines():
            ls = line.strip()
            if "fingerprint" in ls.lower() or ls.startswith("ssh-"):
                return f"SSH: {re.sub(r'\s+', ' ', ls)[:130]}"
        t = re.sub(r"\s+", " ", o)[:130]
        return f"SSH: {t}" if len(t) > 8 else None

    if sid == "snmp-info":
        t = re.sub(r"\s+", " ", o)[:120]
        return f"SNMP: {t}" if t else None

    if sid == "smb-os-discovery":
        t = re.sub(r"\s+", " ", o)[:120]
        return f"SMB/OS: {t}" if t else None

    return None


def _web_stack_hint(
    svc_el: ET.Element | None, svc_name: str, product: str, version: str
) -> str | None:
    if svc_el is None:
        return None
    name_l = svc_name.lower()
    prod_l = product.lower()
    if not (
        "http" in name_l
        or name_l in ("https", "http-proxy", "ssl/http")
        or any(
            k in prod_l
            for k in (
                "httpd",
                "apache",
                "nginx",
                "lighttpd",
                "thttpd",
                "mini_httpd",
                "uhttpd",
                "boa",
                "cherokee",
                "caddy",
                "tomcat",
            )
        )
    ):
        return None
    bits = [product or svc_name, version]
    extra = (svc_el.get("extrainfo") or "").strip()
    if extra and len(extra) < 40:
        bits.append(extra)
    return " ".join(x for x in bits if x).strip() or svc_name


def parse_nmap_forensic_digest(xml_text: str) -> list[str]:
    """
    Build a short **forensic digest** from nmap XML: classification, CPE inventory,
    attack surface, versioned services, and a few script-derived facts—no raw nmap text.
    """
    lines: list[str] = []
    cleaned = _nmap_xml_for_etree(xml_text)
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError as e:
        return [f"(nmap XML parse error: {e})"]

    nmap_ver = (root.get("version") or "").strip()
    start_s = (root.get("start") or "").strip()
    prov: list[str] = []
    if nmap_ver:
        prov.append(f"nmap {nmap_ver}")
    if start_s.isdigit():
        try:
            utc = datetime.fromtimestamp(int(start_s), tz=timezone.utc)
            prov.append(f"UTC {utc.strftime('%Y-%m-%d %H:%M:%S')}")
        except (ValueError, OSError):
            prov.append(f"start {start_s}")

    hosts = root.findall("host")
    if not hosts:
        tail = " · ".join(prov) if prov else ""
        return [f"(No host in XML){' · ' + tail if tail else ''}"]

    lines.append("--- Nmap digest (forensic) ---")
    if prov:
        lines.append("Provenance: " + " · ".join(prov))

    host = hosts[0]
    status_el = host.find("status")
    state = (status_el.get("state") or "").strip() if status_el is not None else ""

    ip = ""
    for addr in host.findall("address"):
        if addr.get("addrtype") == "ipv4":
            ip = (addr.get("addr") or "").strip()
            break

    head = "Target: " + (ip or "?")
    if state:
        head += f" | {state}"
    lines.append(head)

    device_types: list[str] = []
    seen_dt: set[str] = set()
    os_guess = ""
    os_acc = ""
    os_el = host.find("os")
    if os_el is not None:
        for osc in os_el.findall("osclass"):
            typ = (osc.get("type") or "").strip()
            if typ and typ not in seen_dt:
                seen_dt.add(typ)
                device_types.append(typ)
        for osmatch in os_el.findall("osmatch"):
            name = (osmatch.get("name") or "").strip()
            acc = (osmatch.get("accuracy") or "").strip()
            if name:
                os_guess, os_acc = name, acc
                break

    if device_types:
        lines.append("Device type: " + " · ".join(device_types))
    if os_guess:
        lines.append(
            "OS classification: " + os_guess + (f" (confidence {os_acc}%)" if os_acc else "")
        )

    cpes = sorted(_collect_host_cpes(host))
    if cpes:
        cpe_chunk = 10
        for i in range(0, len(cpes), cpe_chunk):
            chunk = " · ".join(cpes[i : i + cpe_chunk])
            label = f"CPE ({len(cpes)} total): " if i == 0 else "CPE (cont.): "
            lines.append(label + chunk)

    ports_el = host.find("ports")
    open_tcp: list[int] = []
    versioned: list[str] = []
    web_hints: list[str] = []
    script_facts: set[str] = set()

    if ports_el is not None:
        for port in ports_el.findall("port"):
            st = port.find("state")
            if st is None or (st.get("state") or "").lower() != "open":
                continue
            proto = (port.get("protocol") or "").strip()
            pid = (port.get("portid") or "").strip()
            if proto == "tcp" and pid.isdigit():
                open_tcp.append(int(pid))

            svc_el = port.find("service")
            name = product = version = extrainfo = ""
            if svc_el is not None:
                name = (svc_el.get("name") or "").strip() or "unknown"
                product = (svc_el.get("product") or "").strip()
                version = (svc_el.get("version") or "").strip()
                extrainfo = (svc_el.get("extrainfo") or "").strip()

            svc_bits = " ".join(x for x in (product, version, extrainfo) if x).strip()
            if svc_bits or (product or version):
                versioned.append(f"{pid}/{proto} {name}: {svc_bits}".rstrip(": "))
            elif name and name != "unknown":
                versioned.append(f"{pid}/{proto} {name}")

            wh = _web_stack_hint(svc_el, name, product, version)
            if wh:
                web_hints.append(f"{pid}/{proto} {wh}")

            for scr in port.findall("script"):
                sid = (scr.get("id") or "").strip()
                out = (scr.get("output") or "").strip()
                fact = _nmap_script_forensic_fact(sid, out)
                if fact:
                    script_facts.add(fact)
                elif sid == "http-server-header" and out:
                    t = re.sub(r"\s+", " ", out)[:100]
                    if t:
                        script_facts.add(f"Server header ({pid}/{proto}): {t}")

    for hs in host.findall("hostscript"):
        for scr in hs.findall("script"):
            sid = (scr.get("id") or "").strip()
            out = (scr.get("output") or "").strip()
            fact = _nmap_script_forensic_fact(sid, out)
            if fact:
                script_facts.add(fact)

    open_tcp.sort()
    if open_tcp:
        lines.append(f"Open TCP count: {len(open_tcp)} — {','.join(str(p) for p in open_tcp)}")
        odd = [p for p in open_tcp if p not in _COMMON_ROUTER_PORTS]
        if odd:
            lines.append(f"Non-typical router ports (triage): {','.join(str(p) for p in odd)}")
    else:
        lines.append("Open TCP: none in XML (filtered/closed or failed scan).")

    if versioned:
        lines.append("Services (fingerprints): " + " | ".join(versioned[:24]))
        if len(versioned) > 24:
            lines.append(f"… +{len(versioned) - 24} more fingerprinted rows omitted")

    if web_hints:
        lines.append("Web / admin stack: " + " | ".join(dict.fromkeys(web_hints)))

    if script_facts:
        for fact in sorted(script_facts)[:18]:
            lines.append(fact)
        if len(script_facts) > 18:
            lines.append(f"… +{len(script_facts) - 18} more script-derived facts omitted")

    rs = root.find("runstats")
    if rs is not None:
        finished = rs.find("finished")
        if finished is not None:
            elapsed = (finished.get("elapsed") or "").strip()
            if elapsed:
                lines.append(f"Scan duration: {elapsed}s")

    return lines


def run_router_nmap_summary(ip: str) -> None:
    """
    Run ``nmap -p- -A -T4 -v`` against ``ip``, parse ``-oX -``, print a **forensic digest**
    (classification, CPEs, attack surface, fingerprints)—not raw nmap script output.
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        print("nmap: not found in PATH; install nmap (e.g. apt install nmap).", file=sys.stderr)
        return

    cmd = [
        nmap_bin,
        "-p-",
        "-A",
        "-T4",
        "-v",
        "-oX",
        "-",
        ip,
    ]
    print(
        "\n--- nmap (full TCP, OS/service/scripts; can take many minutes) ---",
        file=sys.stderr,
    )
    print(f"Running: nmap -p- -A -T4 -v -oX - {ip}", file=sys.stderr)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=None,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as e:
        print(f"nmap failed to start: {e}", file=sys.stderr)
        return

    xml_out = (proc.stdout or "").strip()
    if proc.returncode != 0 and not xml_out.lstrip().startswith("<?xml"):
        err = (proc.stderr or "").strip().splitlines()
        err_tail = "\n".join(err[-8:]) if err else "(no stderr)"
        print(
            f"nmap exited {proc.returncode}. Last stderr lines:\n{err_tail}",
            file=sys.stderr,
        )
        if not xml_out:
            return

    for line in parse_nmap_forensic_digest(xml_out):
        print(line)


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
    if is_wsl_local() and via_windows:
        print(
            "MAC is read from Windows (Get-NetNeighbor / arp); "
            "WSL cannot ARP your LAN router directly."
        )
    if is_wsl_local() and _is_wsl2_style_nat_gateway(target_ip):
        print(
            "Warning: gateway looks like a 172.16–172.31 address (often virtual). "
            "Set MY_MORE_ROUTER_IP if this is not your FiOS / home router.",
            file=sys.stderr,
        )

    mac: str | None = None
    if is_wsl_local():
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
            mac = normalize_mac_colon(result[0][1].hwsrc) or str(result[0][1].hwsrc).lower()
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
            "Router model (UPnP): not available — tried :49152 and common paths on :80. ",
            file=sys.stderr
        )

    run_router_nmap_summary(target_ip)


if __name__ == "__main__":
    main()
