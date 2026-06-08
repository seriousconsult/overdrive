#!/usr/bin/env python3
"""Report the system DNS resolvers and score how home-like they look."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_dns import (
    KNOWN_PUBLIC_DNS,
    classify_resolver,
    configured_dns_servers,
    describe_dns_ip,
    first_resolv_nameserver,
    get_arin_owner,
    model_and_urls_from_ptr,
    resolv_nameservers,
    resolv_search_domains,
    reverse_dns,
)
from detections.common.common_local import is_wsl_local


def wsl_dns() -> str | None:
    """First nameserver in /etc/resolv.conf; on WSL2 often the DNS tunnel host."""
    return first_resolv_nameserver()


def _print_resolver_report(index: int, ip: str) -> None:
    ptr = reverse_dns(ip)
    arin = get_arin_owner(ip)
    try:
        public = not ipaddress.ip_address(ip.split("%", 1)[0]).is_private
    except ValueError:
        public = False

    print(f"\n--- Resolver #{index}: {ip} ---")
    print(f"  What this IP usually is: {classify_resolver(ip)}")
    print(f"  Public Internet address: {'yes' if public else 'no (RFC1918 / special)'}")
    print(f"  PTR (reverse DNS): {ptr or '(none - common for consumer routers or blocked PTR)'}")

    if arin:
        print(f"  WHOIS (ARIN) organization: {arin}")

    if ip in KNOWN_PUBLIC_DNS:
        label, doc_url = KNOWN_PUBLIC_DNS[ip]
        print(f"  Known public service: {label}")
        print(f"  Reference: {doc_url}")

    model_hint, labeled_urls = model_and_urls_from_ptr(ptr, ip)
    if model_hint:
        print(f"  Model / device hint: {model_hint}")
    if labeled_urls:
        print("  URLs to try:")
        for title, url in labeled_urls:
            print(f"    - {title}: {url}")
    elif not public and ptr:
        print("  URLs to try:")
        print(f"    - Router / gateway admin (this IP): http://{ip}/")
        print(f"    - Router / gateway admin (this IP): https://{ip}/")


def get_dns_info() -> None:
    try:
        dns_ips, detection_source = configured_dns_servers()
    except Exception as exc:
        print("SCORE: 3")
        print(f"STATUS: Error detecting DNS: {exc}")
        return

    print(f"Source: {detection_source}")
    if is_wsl_local():
        tunnel = wsl_dns()
        if tunnel:
            print(
                f"WSL /etc/resolv.conf first nameserver (DNS tunnel / stub): {tunnel}\n"
                "(Queries from the distro often go here first; Windows may still be the "
                "resolver that talks to your router or the Internet.)"
            )
        search = resolv_search_domains()
        if search:
            print(f"Search domains from resolv.conf: {', '.join(search)}")

    if not dns_ips:
        print("\nNo IPv4 DNS server addresses found.")
        print("SCORE: 3")
        print("STATUS: No resolvers detected; cannot confirm residential DNS pattern.")
        return

    print(f"\nConfigured IPv4 DNS servers ({len(dns_ips)} unique, order preserved where possible):")
    for i, ip in enumerate(dns_ips, start=1):
        _print_resolver_report(i, ip)

    details: list[str] = []
    is_public_dns = False
    has_isp_lookup = False
    has_home_router_dns = False
    for raw_ip in dns_ips:
        ip = raw_ip.strip()
        description, public = describe_dns_ip(ip)
        details.append(description)
        is_public_dns |= public
        has_isp_lookup |= "ISP/Internal" in description
        try:
            addr = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            addr = None
        has_home_router_dns |= addr == ipaddress.ip_address("192.168.1.1")

    if is_public_dns:
        final_score = 2
        status_msg = (
            "Public DNS in use - common on home machines but mildly atypical versus ISP/router DNS. "
            f"Summary: {', '.join(details)}"
        )
    elif has_isp_lookup:
        final_score = 1
        status_msg = (
            "Private resolver(s) with ISP-style PTR; hostname often encodes router model family. "
            f"Summary: {', '.join(details)}"
        )
    elif has_home_router_dns:
        final_score = 1
        status_msg = f"Resolver includes typical gateway 192.168.1.1. Summary: {', '.join(details)}"
    else:
        final_score = 2
        status_msg = f"Private / unknown resolver pattern. Summary: {', '.join(details)}"

    print("\n--- Score (detection script heuristic) ---")
    print(f"SCORE: {final_score}")
    print(f"STATUS: {status_msg}")


if __name__ == "__main__":
    print("--- System DNS Identification ---")
    get_dns_info()
