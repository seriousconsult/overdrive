#!/usr/bin/env python3
"""
(Layer 7)
UPnP (SSDP) discovery — residential routers and CPE often advertise model / firmware 
via SSDP + device description XML.
Technique: SSDP M-SEARCH to 239.255.255.250:1900 (like gssdp-discover), 
parse SERVER / LOCATION, then GET URLs that look
like device descriptions (often *.xml).
Unified score **1–5** : **higher** = stronger, more specific 
CPE / router identification leaked.
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

from common.common_router import (
    default_ipv4_gateway,
    _parse_ssdp_headers,
    _send_msearch,
    _collect_ssdp,
    _fetch_location,
    _xml_text_fields,
)

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
    One line for STATUS: after SCORE (run_all_detections / HTML comment) — model, manufacturer, or SSDP SERVER.
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
    5 — Explicit manufacturer + model (+ optional version) in XML or very router-specific SERVER.
    4 — Strong device description (model or friendlyName clearly CPE-like).
    3 — SSDP LOCATION / SERVER suggests UPnP device; XML thin or generic.
    2 — SSDP replies but no usable LOCATION / fetch failed.
    1 — No SSDP responses (or nothing parseable).
    """
    if not responses:
        return 1, "No SSDP replies."

    has_location = any(h.get("LOCATION") for _, h, _ in responses)
    if not has_location:
        srv = " ".join(h.get("SERVER", "") for _, h, _ in responses).lower()
        if any(k in srv for k in ROUTER_XML_HINTS):
            return 3, "SSDP SERVER looks like CPE; no LOCATION."
        return 2, "SSDP without LOCATION."

    if not xml_bodies:
        return 2, "LOCATION not fetched or not XML."

    best = 1
    notes: list[str] = []

    for _ip, loc, fields in xml_bodies:
        blob = " ".join(fields.values()).lower()

        manu = fields.get("manufacturer", "")
        model = fields.get("modelName", "") or fields.get("modelNumber", "")
        fname = fields.get("friendlyName", "")

        if manu and model:
            best = max(best, 5)
            notes.append(f"{manu} {model}".strip())
        elif manu and len(manu) > 2:
            best = max(best, 4)
            notes.append(manu.strip())
        elif model and len(model) > 2:
            best = max(best, 4)
            notes.append(model.strip())
        elif fname and any(x in fname.lower() for x in ("router", "gateway", "wifi", "wlan", "fritz", "orbi")):
            best = max(best, 4)
            notes.append(fname.strip())
        elif any(h in blob for h in ROUTER_XML_HINTS):
            best = max(best, 3)
            notes.append("vendor-ish XML")
        elif fields:
            best = max(best, 3)
            notes.append("generic XML fields")

    if best == 1 and xml_bodies:
        return 2, "XML without model/manufacturer."

    tail = "; ".join(notes[:3]) if notes else "LOCATION only"
    return best, tail


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
        help="LAN IP to M-SEARCH unicast (e.g. 192.168.1.1:1900). Use with WSL2; default route IP is often not your router.",
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

    responses = _collect_ssdp(args.listen, unicast)
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
            body, err = _fetch_location(loc, args.fetch_timeout, args.insecure)
            if body:
                fields = _xml_text_fields(body)
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
        if args.ip and args.ip.strip():
            status_line = f"No SSDP to {args.ip.strip()}"
        else:
            status_line = "No SSDP (add --ip <LAN gateway>)"

    print("-" * 30)
    print(f"SCORE: {score}")
    print(f"STATUS: {status_line}")
    if args.verbose and note:
        print(f"Note: {note}")


if __name__ == "__main__":
    main()
