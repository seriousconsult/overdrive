"""Compatibility facade for shared router helpers.

New code should import from the focused modules:
``common_router_gateway``, ``common_router_upnp``, ``common_router_nmap``,
and ``common_router_capture``.
"""

from __future__ import annotations

from detections.common.common_router_capture import (
    background_probe_loop,
    print_sniff_permission_help,
)
from detections.common.common_router_gateway import (
    KNOWN_VIRTUAL_OUI,
    default_ipv4_gateway,
    default_ipv4_gateway_linux,
    is_wsl2_style_nat_gateway,
    linux_ping_once,
    mac_from_linux_neigh,
    mac_from_proc_net_arp,
    mac_from_windows,
    normalize_oui,
    ping_first,
    powershell_exes,
    resolve_mac,
    resolve_router_ipv4_and_iface,
    run_powershell_first_ipv4,
    try_ip_neigh,
    valid_ipv4,
    vendor_from_mac,
    windows_home_router_ipv4,
    windows_ping_once,
)
from detections.common.common_router_nmap import (
    COMMON_ROUTER_PORTS,
    collect_host_cpes,
    nmap_script_forensic_fact,
    nmap_xml_for_etree,
    parse_nmap_forensic_digest,
    run_router_nmap_summary,
    web_stack_hint,
    xml_local_tag,
)
from detections.common.common_router_upnp import (
    collect_ssdp,
    extract_realm,
    fetch_location,
    fetch_upnp_device_info,
    parse_ssdp_headers,
    parse_upnp_device_xml,
    send_msearch,
    upnp_description_urls,
    xml_text_fields,
)

__all__ = [
    "COMMON_ROUTER_PORTS",
    "KNOWN_VIRTUAL_OUI",
    "background_probe_loop",
    "collect_host_cpes",
    "collect_ssdp",
    "default_ipv4_gateway",
    "default_ipv4_gateway_linux",
    "extract_realm",
    "fetch_location",
    "fetch_upnp_device_info",
    "is_wsl2_style_nat_gateway",
    "linux_ping_once",
    "mac_from_linux_neigh",
    "mac_from_proc_net_arp",
    "mac_from_windows",
    "nmap_script_forensic_fact",
    "nmap_xml_for_etree",
    "normalize_oui",
    "parse_nmap_forensic_digest",
    "parse_ssdp_headers",
    "parse_upnp_device_xml",
    "ping_first",
    "powershell_exes",
    "print_sniff_permission_help",
    "resolve_mac",
    "resolve_router_ipv4_and_iface",
    "run_powershell_first_ipv4",
    "run_router_nmap_summary",
    "send_msearch",
    "try_ip_neigh",
    "upnp_description_urls",
    "valid_ipv4",
    "vendor_from_mac",
    "web_stack_hint",
    "windows_home_router_ipv4",
    "windows_ping_once",
    "xml_local_tag",
    "xml_text_fields",
]

# Backward-compatible aliases for older underscore-prefixed private names.
_background_probe_loop = background_probe_loop
_collect_ssdp = collect_ssdp
_extract_realm = extract_realm
_fetch_location = fetch_location
_parse_ssdp_headers = parse_ssdp_headers
_print_sniff_permission_help = print_sniff_permission_help
_send_msearch = send_msearch
_xml_text_fields = xml_text_fields
