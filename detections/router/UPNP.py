#!/usr/bin/env python3
"""
(Layer 7)
UPnP (SSDP) discovery — residential routers and CPE often advertise model / firmware 
via SSDP + device description XML.
Technique: SSDP M-SEARCH to 239.255.255.250:1900 (like gssdp-discover),
parse SERVER / LOCATION, then GET URLs that look like device descriptions
(often *.xml).

Host-authenticity score: 1 = residential/home-router evidence, 3 = ambiguous,
5 = definitely artificial host.
"""

from __future__ import annotations

import argparse
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_router_gateway import default_ipv4_gateway
from detections.common.common_router_upnp import collect_ssdp, fetch_location, xml_text_fields

# Multicast SSDP
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

MSEARCH_ROOT = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: upnp:rootdevice\r\n"
    "\r\n"
).encode("ascii")

MSEARCH_ALL = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")

ROUTER_XML_HINTS = (
    "router",
    "gateway",
    "wrt",
    "asus",
    "netgear",
    "tp-link",
    "tplink",
    "linksys",
    "fritz",
    "sagem",
    "arris",
    "ubiquiti",
    "mikrotik",
    "httpd",
    "igd",
    "internetgateway",
)


def _status_ident_line(
    responses: list[tuple[str, dict[str, str], str]],
    xml_bodies: list[tuple[str, str, dict[str, str]]],
) -> str:
    """
    One line for STATUS: after SCORE (detections/run_detections HTML comment) — model, manufacturer, or SSDP SERVER.
    """
    if not responses:
        return "No SSDP"
    lim = 220
    for ip, loc, fields in xml_bodies:
        manu = (fields.get("manufacturer") or "").strip()
        mname = (fields.get("modelName") or "").strip()
        mnum = (fields.get("modelNumber") or "").strip()
        mdesc = (fields.get("modelDescription") or "").strip()
        model = mname or mnum
        fname = (fields.get("friendlyName") or "").strip()
        serial = (fields.get("serialNumber") or "").strip()
        parts = [p for p in (manu, model, mdesc, fname, serial) if p]
        if parts:
            s = " | ".join(parts[:5])
            if len(s) > lim:
                return s[: lim - 1] + "…"
            return s
        if loc:
            s = f"{ip} device @ {loc}"
            return s[:lim] + ("…" if len(s) > lim else s)

    for ip, hdrs, _ in responses:
        srv = (hdrs.get("SERVER") or "").strip()
        if srv:
            s = f"{ip} SERVER={srv}"
            if len(s) > lim:
                return s[: lim - 1] + "…"
            return s

    for ip, hdrs, _ in responses:
        loc = (hdrs.get("LOCATION") or "").strip()
        if loc:
            s = f"{ip} LOCATION={loc}"
            if len(s) > lim:
                return s[: lim - 1] + "…"
            return s

    return "No identifying XML"


def _score_evidence(
    responses: list[tuple[str, dict[str, str], str]],
    xml_bodies: list[tuple[str, str, dict[str, str]]],
) -> tuple[int, str]:
    """
    1 - Explicit/strong home router or CPE evidence.
    2 - Weak but home-like SSDP evidence.
    3 - No SSDP evidence or ambiguous network visibility.
    4/5 are reserved for artificial-host evidence, which this probe does not produce.
    """
    if not responses:
        return 3, "No SSDP replies; ambiguous because normal routers may suppress SSDP."

    has_location = any(h.get("LOCATION") for _, h, _ in responses)
    if not has_location:
        srv = " ".join(h.get("SERVER", "") for _, h, _ in responses).lower()
        if any(k in srv for k in ROUTER_XML_HINTS):
            return 2, "SSDP SERVER looks like CPE; no LOCATION."
        return 2, "Generic SSDP response without LOCATION."

    if not xml_bodies:
        return 2, "SSDP LOCATION present but not fetched or not XML."

    cpe_confidence = 0
    notes: list[str] = []

    for _ip, loc, fields in xml_bodies:
        blob = " ".join(fields.values()).lower()

        manu = fields.get("manufacturer", "")
        model = fields.get("modelName", "") or fields.get("modelNumber", "")
        fname = fields.get("friendlyName", "")

        if manu and model:
            cpe_confidence = max(cpe_confidence, 5)
            notes.append(f"{manu} {model}".strip())
        elif manu and len(manu) > 2:
            cpe_confidence = max(cpe_confidence, 4)
            notes.append(manu.strip())
        elif model and len(model) > 2:
            cpe_confidence = max(cpe_confidence, 4)
            notes.append(model.strip())
        elif fname and any(x in fname.lower() for x in ("router", "gateway", "wifi", "wlan", "fritz", "orbi")):
            cpe_confidence = max(cpe_confidence, 4)
            notes.append(fname.strip())
        elif any(h in blob for h in ROUTER_XML_HINTS):
            cpe_confidence = max(cpe_confidence, 3)
            notes.append("vendor-ish XML")
        elif fields:
            cpe_confidence = max(cpe_confidence, 3)
            notes.append("generic XML fields")

    if cpe_confidence == 0 and xml_bodies:
        return 2, "XML without model/manufacturer."

    tail = "; ".join(notes[:3]) if notes else "LOCATION only"
    if cpe_confidence >= 4:
        return 1, f"Strong residential router/CPE evidence: {tail}"
    return 2, f"Weak residential network evidence: {tail}"


def main() -> None:
    ap = argparse.ArgumentParser(description="SSDP / UPnP discovery and device-description leak heuristics.")
    ap.add_argument(
        "--listen",
        type=float,
        default=3.0,
        help="Seconds to listen for SSDP responses after M-SEARCH (default 3).",
    )
    ap.add_argument(
        "--no-fetch-xml",
        action="store_true",
        help="SSDP only; do not HTTP-fetch LOCATION device descriptions (default is to fetch).",
    )
    ap.add_argument("--fetch-timeout", type=float, default=3.0, help="Per-URL timeout for device XML.")
    ap.add_argument(
        "--insecure",
        action="store_true",
        help="Allow TLS verification to be skipped for https LOCATION (self-signed CPE certs).",
    )
    ap.add_argument("--out-json", default=None, help="Optional JSON path for structured evidence.")
    ap.add_argument(
        "--ip",
        default=None,
        help="Extra LAN IP for unicast M-SEARCH (default route gateway is always included when known).",
    )
    ap.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print every SSDP response and XML field (default: compact).",
    )
    args = ap.parse_args()

    do_fetch = not args.no_fetch_xml
    gw = default_ipv4_gateway()
    unicast: list[str] = []
    if args.ip and args.ip.strip():
        unicast.append(args.ip.strip())
    if gw and gw not in unicast:
        unicast.append(gw)

    responses = collect_ssdp(args.listen, unicast)
    print(
        f"UPnP/SSDP listen={args.listen}s unicast={','.join(unicast) or 'multicast-only'} "
        f"fetch_xml={do_fetch} replies={len(responses)}"
    )

    xml_bodies: list[tuple[str, str, dict[str, str]]] = []
    for ip, hdrs, snip in responses:
        loc = hdrs.get("LOCATION", "")
        srv = hdrs.get("SERVER", "")
        st = hdrs.get("ST", "")
        if args.verbose:
            print(f"\n-- from {ip}")
            if srv:
                print(f"   SERVER: {srv}")
            if st:
                print(f"   ST: {st}")
            if loc:
                print(f"   LOCATION: {loc}")
            else:
                print(f"   (raw) {snip[:220]}…")

        if do_fetch and loc.lower().startswith(("http://", "https://")):
            body, err = fetch_location(loc, args.fetch_timeout, args.insecure)
            if body:
                fields = xml_text_fields(body)
                xml_bodies.append((ip, loc, fields))
                if args.verbose and fields:
                    print("   Device XML (selected fields):")
                    for k, v in sorted(fields.items()):
                        print(f"      {k}: {v}")
            elif args.verbose and err:
                print(f"   XML fetch failed: {err[:200]}")

    score, note = _score_evidence(responses, xml_bodies)
    status_line = _status_ident_line(responses, xml_bodies)

    evidence: dict[str, Any] = {
        "unicast_targets": unicast,
        "responses": [
            {"ip": ip, "headers": hdrs, "snippet": snip[:800]} for ip, hdrs, snip in responses
        ],
        "xml_summaries": [
            {"ip": ip, "location": loc, "fields": fields} for ip, loc, fields in xml_bodies
        ],
        "score": score,
        "note": note,
        "status_ident": status_line,
    }
    if args.out_json:
        import json

        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)
        print(f"[+] JSON → {args.out_json}")

    if not responses:
        if unicast:
            status_line = (
                f"No SSDP replies from {', '.join(unicast)}; "
                "normal routers may suppress discovery"
            )
        else:
            status_line = "No SSDP replies; normal routers may suppress discovery"

    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {status_line}")
    if args.verbose and note:
        print(f"Note: {note}")


if __name__ == "__main__":
    main()
