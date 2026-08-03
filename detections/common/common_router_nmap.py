"""Nmap XML parsing and compact router digest helpers."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

COMMON_ROUTER_PORTS: frozenset[int] = frozenset(
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


def nmap_xml_for_etree(xml_text: str) -> str:
    """Drop default xmlns on ``<nmaprun>`` so ElementTree findall works."""
    return re.sub(r'(<nmaprun\b[^>]*?)\s+xmlns="[^"]+"', r"\1", xml_text, count=1)


def xml_local_tag(tag: str) -> str:
    """Return an XML tag's local name."""
    return tag.split("}")[-1]


def collect_host_cpes(host: ET.Element) -> list[str]:
    """Collect unique CPE strings from an nmap host element."""
    seen: set[str] = set()
    out: list[str] = []
    for el in host.iter():
        if xml_local_tag(el.tag) != "cpe":
            continue
        text = (el.text or "").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def nmap_script_forensic_fact(script_id: str, raw: str) -> str | None:
    """Synthesize one compact fact from selected nmap script output."""
    output = raw.strip()
    if not output:
        return None
    sid = script_id.strip()
    if sid == "http-title":
        title = re.sub(r"\s+", " ", output)[:140]
        return f"HTTP title: {title}" if title else None
    if sid == "ssl-cert":
        subject = issuer = None
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Subject:"):
                subject = stripped[8:].strip()[:100]
            elif stripped.startswith("Issuer:"):
                issuer = stripped[7:].strip()[:100]
        if subject and issuer:
            return f"TLS cert: {subject} | CA: {issuer}"
        if subject:
            return f"TLS cert subject: {subject}"
        return None
    if sid == "ssl-date":
        text = re.sub(r"\s+", " ", output)[:100]
        return f"TLS clock: {text}" if text else None
    if sid in ("ssh-hostkey", "ssh2-enum-algos"):
        for line in output.splitlines():
            stripped = line.strip()
            if "fingerprint" in stripped.lower() or stripped.startswith("ssh-"):
                return f"SSH: {re.sub(r'\s+', ' ', stripped)[:130]}"
        text = re.sub(r"\s+", " ", output)[:130]
        return f"SSH: {text}" if len(text) > 8 else None
    if sid == "snmp-info":
        text = re.sub(r"\s+", " ", output)[:120]
        return f"SNMP: {text}" if text else None
    if sid == "smb-os-discovery":
        text = re.sub(r"\s+", " ", output)[:120]
        return f"SMB/OS: {text}" if text else None
    return None


def web_stack_hint(svc_el: ET.Element | None, svc_name: str, product: str, version: str) -> str | None:
    """Return a short web/admin stack hint from an nmap service element."""
    if svc_el is None:
        return None
    name_l = svc_name.lower()
    prod_l = product.lower()
    if not (
        "http" in name_l
        or name_l in ("https", "http-proxy", "ssl/http")
        or any(k in prod_l for k in ("httpd", "apache", "nginx", "lighttpd", "mini_httpd", "uhttpd", "boa"))
    ):
        return None
    extra = (svc_el.get("extrainfo") or "").strip()
    bits = [product or svc_name, version, extra if len(extra) < 40 else ""]
    return " ".join(x for x in bits if x).strip() or svc_name


def parse_nmap_forensic_digest(xml_text: str) -> list[str]:
    """Build a compact router forensic digest from nmap XML."""
    lines: list[str] = []
    try:
        root = ET.fromstring(nmap_xml_for_etree(xml_text))
    except ET.ParseError as exc:
        return [f"(nmap XML parse error: {exc})"]

    provenance: list[str] = []
    if root.get("version"):
        provenance.append(f"nmap {root.get('version')}")
    start_s = (root.get("start") or "").strip()
    if start_s.isdigit():
        try:
            utc = datetime.fromtimestamp(int(start_s), tz=timezone.utc)
            provenance.append(f"UTC {utc.strftime('%Y-%m-%d %H:%M:%S')}")
        except (ValueError, OSError):
            provenance.append(f"start {start_s}")

    hosts = root.findall("host")
    if not hosts:
        lines.append("--- Nmap digest (forensic) ---")
        if provenance:
            lines.append("Provenance: " + " - ".join(provenance))
        finished = root.find("runstats/finished")
        hosts_stats = root.find("runstats/hosts")
        if finished is not None:
            summary = (finished.get("summary") or "").strip()
            if summary:
                lines.append("Nmap summary: " + summary)
            if finished.get("exit"):
                lines.append("Nmap exit: " + (finished.get("exit") or "").strip())
        if hosts_stats is not None:
            stats = []
            for attr in ("up", "down", "total"):
                value = (hosts_stats.get(attr) or "").strip()
                if value:
                    stats.append(f"{attr}={value}")
            if stats:
                lines.append("Host stats: " + " ".join(stats))
        lines.append("No host element in nmap XML. Check firewall rules, route to target, and raw nmap stderr.")
        return lines

    lines.append("--- Nmap digest (forensic) ---")
    if provenance:
        lines.append("Provenance: " + " - ".join(provenance))

    host = hosts[0]
    status_el = host.find("status")
    state = (status_el.get("state") or "").strip() if status_el is not None else ""
    ip = ""
    for addr in host.findall("address"):
        if addr.get("addrtype") == "ipv4":
            ip = (addr.get("addr") or "").strip()
            break
    lines.append("Target: " + (ip or "?") + (f" | {state}" if state else ""))

    os_el = host.find("os")
    if os_el is not None:
        device_types = []
        seen_types: set[str] = set()
        for osc in os_el.findall("osclass"):
            typ = (osc.get("type") or "").strip()
            if typ and typ not in seen_types:
                seen_types.add(typ)
                device_types.append(typ)
        if device_types:
            lines.append("Device type: " + " - ".join(device_types))
        for osmatch in os_el.findall("osmatch"):
            name = (osmatch.get("name") or "").strip()
            acc = (osmatch.get("accuracy") or "").strip()
            if name:
                lines.append("OS classification: " + name + (f" (confidence {acc}%)" if acc else ""))
                break

    cpes = sorted(collect_host_cpes(host))
    if cpes:
        lines.append(f"CPE ({len(cpes)} total): " + " - ".join(cpes[:10]))

    open_tcp: list[int] = []
    versioned: list[str] = []
    web_hints: list[str] = []
    script_facts: set[str] = set()
    ports_el = host.find("ports")
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
            if svc_bits:
                versioned.append(f"{pid}/{proto} {name}: {svc_bits}")
            elif name and name != "unknown":
                versioned.append(f"{pid}/{proto} {name}")
            hint = web_stack_hint(svc_el, name, product, version)
            if hint:
                web_hints.append(f"{pid}/{proto} {hint}")
            for script in port.findall("script"):
                sid = (script.get("id") or "").strip()
                out = (script.get("output") or "").strip()
                fact = nmap_script_forensic_fact(sid, out)
                if fact:
                    script_facts.add(fact)
                elif sid == "http-server-header" and out:
                    script_facts.add(f"Server header ({pid}/{proto}): {re.sub(r'\s+', ' ', out)[:100]}")

    open_tcp.sort()
    if open_tcp:
        lines.append(f"Open TCP count: {len(open_tcp)} - {','.join(str(p) for p in open_tcp)}")
        odd = [p for p in open_tcp if p not in COMMON_ROUTER_PORTS]
        if odd:
            lines.append(f"Non-typical router ports (triage): {','.join(str(p) for p in odd)}")
    else:
        lines.append("Open TCP: none in XML (filtered/closed or failed scan).")
    if versioned:
        lines.append("Services (fingerprints): " + " | ".join(versioned[:24]))
    if web_hints:
        lines.append("Web / admin stack: " + " | ".join(dict.fromkeys(web_hints)))
    for fact in sorted(script_facts)[:18]:
        lines.append(fact)
    return lines


def run_router_nmap_summary(ip: str) -> None:
    """Run nmap against a router IP and print a compact forensic digest."""
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        print("nmap: not found in PATH; install nmap (e.g. apt install nmap).", file=sys.stderr)
        return
    cmd = [nmap_bin, "--unprivileged", "-Pn", "-p-", "-A", "-T4", "-oX", "-", ip]
    print("\n--- nmap (no ping, full TCP, OS/service/scripts; can take many minutes) ---", file=sys.stderr)
    print(f"Running: nmap --unprivileged -Pn -p- -A -T4 {ip}", file=sys.stderr)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=None, encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"nmap failed to start: {exc}", file=sys.stderr)
        return
    xml_out = (proc.stdout or "").strip()
    if proc.returncode != 0 and not xml_out.lstrip().startswith("<?xml"):
        err = (proc.stderr or "").strip().splitlines()
        print(f"nmap exited {proc.returncode}. Last stderr lines:\n{chr(10).join(err[-8:]) or '(no stderr)'}", file=sys.stderr)
        if not xml_out:
            return
    for line in parse_nmap_forensic_digest(xml_out):
        print(line)
