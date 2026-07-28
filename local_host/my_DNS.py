#!/usr/bin/env python3
"""Report configured DNS, observed upstream resolver, and Mullvad DNS vs VPN exit."""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_dns import (
    KNOWN_PUBLIC_DNS,
    classify_mullvad_dns_observation,
    classify_resolver,
    classify_upstream_resolver,
    configured_dns_servers,
    describe_dns_ip,
    first_resolv_nameserver,
    get_arin_owner,
    is_mullvad_dot_ip,
    model_and_urls_from_ptr,
    mullvad_connection_check,
    mullvad_dns_leak_probe,
    mullvad_dot_whoami_pop,
    query_whoami_akamai,
    resolv_nameservers,
    resolv_search_domains,
    reverse_dns,
    windows_doh_servers,
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
    print(f"  Mullvad public DoT/DoH anycast IP: {'yes' if is_mullvad_dot_ip(ip) else 'no'}")
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


def _print_configured_encryption_hints(dns_ips: list[str]) -> None:
    """Local config hints (DoH on Windows, Mullvad IP, LAN forwarder)."""
    print("\n--- Configured path (what this OS sends queries to first) ---")
    mullvad_configured = any(is_mullvad_dot_ip(ip) for ip in dns_ips)
    lan_forwarder = False
    loopback_stub = False
    for ip in dns_ips:
        base = ip.split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(base)
        except ValueError:
            continue
        if addr.is_loopback:
            loopback_stub = True
        if addr.is_private and not addr.is_loopback:
            lan_forwarder = True

    if mullvad_configured:
        print(
            "Configured nameserver includes a Mullvad DoT/DoH anycast IP (194.242.2.x).\n"
            "  Plain UDP/53 to these IPs is not a full recursive service — the OS must use DoT/DoH."
        )
    if lan_forwarder:
        print(
            "Configured nameserver is on the LAN (e.g. OpenWrt 192.168.1.1).\n"
            "  Client→router DNS is usually plain UDP/53 on the lab LAN.\n"
            "  Encryption only applies if the router forwards upstream with DoT/DoH (e.g. stubby→Mullvad).\n"
            "  Proof of upstream is whoami.akamai.net (next section), not am.i.mullvad.net."
        )
    if loopback_stub:
        print(
            "Configured nameserver is loopback (systemd-resolved / dnsmasq stub).\n"
            "  Encryption depends on what that stub forwards to (see upstream whoami below)."
        )

    doh_rows = windows_doh_servers()
    if doh_rows:
        print("Windows DNS-over-HTTPS (DoH) templates:")
        for row in doh_rows:
            print(
                f"  - server={row.get('server') or '(n/a)'}  "
                f"template={row.get('template') or '(n/a)'}  "
                f"udp_fallback={row.get('allow_udp_fallback')}"
            )
            tmpl = (row.get("template") or "").lower()
            if "mullvad" in tmpl:
                print("    → DoH template points at Mullvad (encrypted to Mullvad).")
    elif is_wsl_local() or sys.platform == "win32":
        print("Windows DoH templates: none reported (Get-DnsClientDohServerAddress empty/unavailable).")


def _print_upstream_whoami_report(dns_ips: list[str]) -> dict:
    """Primary upstream check: whoami.akamai.net vs live Mullvad DoT PoP."""
    print("\n--- Observed upstream (whoami.akamai.net) ---")
    print(
        "whoami.akamai.net returns the recursive resolver IP that contacted Akamai.\n"
        "Mullvad publishes anycast 194.242.2.x; the answer is often the PoP unicast\n"
        "(e.g. 193.148.18.30 = us-nyc-dns-601.mullvad.net), not 194.242.2.x itself."
    )

    pop_ip, pop_detail = mullvad_dot_whoami_pop()
    if pop_ip:
        print(f"Mullvad DoT reference PoP (direct DoT to 194.242.2.2): {pop_ip}")
        print(f"  via {pop_detail}")
    else:
        print(f"Mullvad DoT reference PoP: unavailable ({pop_detail})")

    who_ip, who_detail = query_whoami_akamai()
    if not who_ip:
        print(f"System whoami: failed ({who_detail})")
        print("USING_MULLVAD_DNS: unknown")
        print("UPSTREAM: unknown")
        return {
            "whoami_ip": None,
            "using_mullvad_dns": None,
            "kind": "unknown",
            "note": who_detail,
        }

    info = classify_upstream_resolver(who_ip, mullvad_pop_reference=pop_ip)
    print(f"System whoami: {who_ip}  ({who_detail})")
    if info.get("ptr"):
        print(f"  PTR: {info['ptr']}")
    else:
        print("  PTR: (none / NXDOMAIN — common for Mullvad PoP unicast)")
    if info.get("arin"):
        print(f"  ARIN: {info['arin']}")
    print(f"  Classification: {info['kind']}")
    print(f"  {info['note']}")

    # Optional: query via LAN gateway if configured (lab OpenWrt path).
    for ip in dns_ips:
        base = ip.split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(base)
        except ValueError:
            continue
        if addr.is_private and not addr.is_loopback:
            gw_ip, gw_detail = query_whoami_akamai(nameserver=base)
            if gw_ip:
                gw_info = classify_upstream_resolver(gw_ip, mullvad_pop_reference=pop_ip)
                print(f"whoami via configured LAN DNS {base}: {gw_ip}  ({gw_detail})")
                print(f"  Classification: {gw_info['kind']} — {gw_info['note']}")
            break

    using = bool(info["is_mullvad_dns"])
    print(f"USING_MULLVAD_DNS: {'yes' if using else 'no'}")
    print(
        "MULLVAD_PUBLIC_DOT_DOH: "
        f"{'yes' if info['is_mullvad_public_doh_dot'] else 'no'}"
    )
    print(f"UPSTREAM: {info['kind']}")
    return {
        "whoami_ip": who_ip,
        "using_mullvad_dns": using,
        "kind": info["kind"],
        "note": info["note"],
        "is_mullvad_public_doh_dot": info["is_mullvad_public_doh_dot"],
    }


def _print_mullvad_leak_probe_report() -> None:
    print("\n--- Secondary: Mullvad dnsleak.am.i.mullvad.net probe ---")
    print(
        "Same family of check as https://mullvad.net/check DNS box. "
        "Can fail or NXDOMAIN on some networks; whoami above is authoritative for upstream IP."
    )
    servers, err = mullvad_dns_leak_probe(samples=4)
    if err and not servers:
        print(f"Probe failed: {err}")
        return
    if not servers:
        print("Probe returned no servers.")
        return

    print(f"Unique resolvers seen ({len(servers)}):")
    for i, row in enumerate(servers, start=1):
        ip = row.get("ip") or "?"
        host = row.get("mullvad_dns_hostname") or row.get("hostname") or ""
        org = row.get("organization") or ""
        country = row.get("country") or ""
        is_mv = bool(row.get("mullvad_dns"))
        print(
            f"  [{i}] ip={ip}  mullvad_dns={is_mv}  host={host or '(none)'}  "
            f"org={org or '(none)'}  country={country or '(n/a)'}"
        )

    summary = classify_mullvad_dns_observation(servers)
    print(f"Leak-probe USING_MULLVAD_DNS: {'yes' if summary['using_mullvad_dns'] else 'no'}")
    print(f"Leak-probe UPSTREAM: {summary['upstream_kind']}")
    print(f"Leak-probe NOTE: {summary['encryption_note']}")


def _print_vpn_exit_report() -> None:
    print("\n--- VPN exit IP (NOT a DNS check) ---")
    print(
        "https://am.i.mullvad.net/json reports where *HTTPS* egress appears from.\n"
        "mullvad_exit_ip=false + ISP org (e.g. Verizon) is expected for Mullvad DNS-only "
        "(DoT/DoH without the VPN)."
    )
    data, err = mullvad_connection_check()
    if err or not data:
        print(f"Connection check failed: {err or 'empty'}")
        return
    print(f"  egress_ip: {data.get('ip')}")
    print(f"  organization: {data.get('organization')}")
    print(f"  country/city: {data.get('country')}/{data.get('city')}")
    print(f"  mullvad_exit_ip (VPN): {data.get('mullvad_exit_ip')}")
    if data.get("mullvad_exit_ip"):
        print("  → Traffic is exiting via Mullvad VPN.")
    else:
        print("  → Not on Mullvad VPN (normal for DNS-only lab).")


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
        upstream = _print_upstream_whoami_report([])
        _print_mullvad_leak_probe_report()
        _print_vpn_exit_report()
        return

    print(f"\nConfigured IPv4 DNS servers ({len(dns_ips)} unique, order preserved where possible):")
    for i, ip in enumerate(dns_ips, start=1):
        _print_resolver_report(i, ip)

    _print_configured_encryption_hints(dns_ips)
    upstream = _print_upstream_whoami_report(dns_ips)
    _print_mullvad_leak_probe_report()
    _print_vpn_exit_report()

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

    print("\n--- Verdict ---")
    if upstream.get("using_mullvad_dns"):
        print("DNS_UPSTREAM: Mullvad public DNS (DoT/DoH path or matching PoP)")
        print(f"DNS_UPSTREAM_IP: {upstream.get('whoami_ip')}")
        print(f"DNS_ENCRYPTED_TO_MULLVAD: {'yes' if upstream.get('is_mullvad_public_doh_dot') else 'unknown'}")
        print(
            "NOTE: Client→LAN forwarder may still be plain UDP/53; "
            "encryption is on the router→Mullvad (or OS→Mullvad) leg."
        )
    elif upstream.get("whoami_ip"):
        print(f"DNS_UPSTREAM: not Mullvad ({upstream.get('kind')})")
        print(f"DNS_UPSTREAM_IP: {upstream.get('whoami_ip')}")
        print(f"NOTE: {upstream.get('note')}")
    else:
        print("DNS_UPSTREAM: unknown (whoami probe failed)")

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
