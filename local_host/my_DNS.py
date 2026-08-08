#!/usr/bin/env python3
"""Report configured DNS and observed upstream resolver (Mullvad DNS / DoT/DoH)."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

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
    mullvad_dns_leak_probe,
    mullvad_dot_whoami_pop,
    query_whoami_akamai,
    resolv_nameservers,
    resolv_search_domains,
    reverse_dns,
    windows_doh_servers,
)
from detections.common.common_local import is_wsl_local

AKAHELP_WHOAMI_TXT = "whoami.ds.akahelp.net"


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


def _print_configured_encryption_hints(dns_ips: list[str]) -> dict[str, Any]:
    """Local config hints (DoH on Windows, Mullvad IP, LAN forwarder)."""
    print("\n--- Configured path (what this OS sends queries to first) ---")
    mullvad_configured_ips = [ip for ip in dns_ips if is_mullvad_dot_ip(ip)]
    mullvad_configured = bool(mullvad_configured_ips)
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
            "  Proof of upstream is whoami.akamai.net (next section)."
        )
    if loopback_stub:
        print(
            "Configured nameserver is loopback (systemd-resolved / dnsmasq stub).\n"
            "  Encryption depends on what that stub forwards to (see upstream whoami below)."
        )

    if is_wsl_local():
        doh_rows = []
        print("Windows DoH templates: skipped (using WSL /etc/resolv.conf only).")
    else:
        doh_rows = windows_doh_servers()
    doh_mullvad_rows = []
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
                doh_mullvad_rows.append(row)
                print("    → DoH template points at Mullvad (encrypted to Mullvad).")
    elif sys.platform == "win32":
        print("Windows DoH templates: none reported (Get-DnsClientDohServerAddress empty/unavailable).")

    return {
        "mullvad_configured_ips": mullvad_configured_ips,
        "lan_forwarder": lan_forwarder,
        "loopback_stub": loopback_stub,
        "windows_doh_rows": doh_rows,
        "windows_doh_mullvad_rows": doh_mullvad_rows,
    }


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
        print("USING_DOT_OR_DOH_DNS: unknown")
        print("UPSTREAM: unknown")
        return {
            "whoami_ip": None,
            "using_mullvad_dns": None,
            "using_dot_or_doh_dns": None,
            "kind": "unknown",
            "note": who_detail,
            "mullvad_dot_reference_ip": pop_ip,
            "mullvad_dot_reference_detail": pop_detail,
            "lan_checks": [],
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
    lan_checks: list[dict[str, Any]] = []
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
                lan_checks.append(
                    {
                        "configured_dns": base,
                        "whoami_ip": gw_ip,
                        "detail": gw_detail,
                        "info": gw_info,
                        "using_mullvad_dns": bool(gw_info["is_mullvad_dns"]),
                        "using_dot_or_doh_dns": bool(gw_info["is_mullvad_public_doh_dot"]),
                    }
                )
            else:
                print(f"whoami via configured LAN DNS {base}: failed ({gw_detail})")
                lan_checks.append(
                    {
                        "configured_dns": base,
                        "whoami_ip": None,
                        "detail": gw_detail,
                        "info": None,
                        "using_mullvad_dns": None,
                        "using_dot_or_doh_dns": None,
                    }
                )
            break

    using = bool(info["is_mullvad_dns"])
    using_dot_or_doh = bool(info["is_mullvad_public_doh_dot"])
    print(f"USING_MULLVAD_DNS: {'yes' if using else 'no'}")
    print(f"USING_DOT_OR_DOH_DNS: {'yes' if using_dot_or_doh else 'no'}")
    print(
        "MULLVAD_PUBLIC_DOT_DOH: "
        f"{'yes' if info['is_mullvad_public_doh_dot'] else 'no'}"
    )
    print(f"UPSTREAM: {info['kind']}")
    return {
        "whoami_ip": who_ip,
        "using_mullvad_dns": using,
        "using_dot_or_doh_dns": using_dot_or_doh,
        "kind": info["kind"],
        "note": info["note"],
        "is_mullvad_public_doh_dot": info["is_mullvad_public_doh_dot"],
        "mullvad_dot_reference_ip": pop_ip,
        "mullvad_dot_reference_detail": pop_detail,
        "info": info,
        "lan_checks": lan_checks,
    }


def _public_ipv4s_from_text(text: str) -> list[str]:
    out: list[str] = []
    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or ""):
        ip = match.group(0)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if (
            addr.version == 4
            and not addr.is_private
            and not addr.is_loopback
            and not addr.is_link_local
            and not addr.is_multicast
            and not addr.is_reserved
            and not addr.is_unspecified
            and ip not in out
        ):
            out.append(ip)
    return out


def _dig_akahelp_txt(*, nameserver: str | None = None, timeout: float = 6.0) -> tuple[str | None, str]:
    cmd = ["dig"]
    if nameserver:
        cmd.append(f"@{nameserver}")
    cmd.extend(["+time=3", "+tries=2", "+short", "TXT", AKAHELP_WHOAMI_TXT])
    try:
        out = subprocess.check_output(
            cmd,
            text=True,
            timeout=timeout,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return None, f"dig TXT failed: {exc}"
    if not out:
        return None, "dig TXT returned no records"
    return out, f"dig{' @' + nameserver if nameserver else ''} +short TXT {AKAHELP_WHOAMI_TXT}"


def _classify_akahelp_txt(raw_txt: str, *, mullvad_pop_reference: str | None) -> dict[str, Any]:
    normalized = raw_txt.replace('\\"', '"').replace('"', "").strip()
    lower = normalized.lower()
    infos = [
        classify_upstream_resolver(ip, mullvad_pop_reference=mullvad_pop_reference)
        for ip in _public_ipv4s_from_text(normalized)
    ]
    mullvad_infos = [info for info in infos if info.get("is_mullvad_dns")]

    contains_mullvad = "mullvad" in lower
    contains_dns = "dns" in lower
    if mullvad_infos:
        best = mullvad_infos[0]
        return {
            "raw": raw_txt,
            "normalized": normalized,
            "ips": [info["ip"] for info in infos],
            "info": best,
            "kind": best["kind"],
            "using_mullvad_dns": True,
            "using_dot_or_doh_dns": bool(best["is_mullvad_public_doh_dot"]),
            "note": best["note"],
        }
    if infos:
        best = infos[-1]
        return {
            "raw": raw_txt,
            "normalized": normalized,
            "ips": [info["ip"] for info in infos],
            "info": best,
            "kind": best["kind"],
            "using_mullvad_dns": False,
            "using_dot_or_doh_dns": False,
            "note": best["note"],
        }
    if contains_mullvad:
        return {
            "raw": raw_txt,
            "normalized": normalized,
            "ips": [],
            "info": None,
            "kind": "mullvad_txt",
            "using_mullvad_dns": True,
            "using_dot_or_doh_dns": contains_dns,
            "note": "Akahelp TXT contains a Mullvad resolver hostname.",
        }
    return {
        "raw": raw_txt,
        "normalized": normalized,
        "ips": [],
        "info": None,
        "kind": "other_or_unknown_txt",
        "using_mullvad_dns": False,
        "using_dot_or_doh_dns": False,
        "note": "Akahelp TXT did not identify Mullvad.",
    }


def _print_akahelp_txt_report(
    dns_ips: list[str],
    *,
    mullvad_pop_reference: str | None,
) -> dict[str, Any]:
    print("\n--- Observed upstream (Akamai akahelp TXT) ---")
    print(
        f"Runs: dig +short TXT {AKAHELP_WHOAMI_TXT}\n"
        "This often returns resolver/debug TXT data that can expose the upstream DNS server name."
    )

    checks: list[dict[str, Any]] = []

    raw, detail = _dig_akahelp_txt()
    if raw:
        result = _classify_akahelp_txt(raw, mullvad_pop_reference=mullvad_pop_reference)
        print(f"System akahelp TXT ({detail}):")
        for line in raw.splitlines():
            print(f"  {line}")
        print(f"  Classification: {result['kind']} — {result['note']}")
        checks.append({"scope": "system", "detail": detail, **result})
    else:
        print(f"System akahelp TXT: failed ({detail})")
        checks.append(
            {
                "scope": "system",
                "detail": detail,
                "raw": None,
                "normalized": "",
                "kind": "unknown",
                "using_mullvad_dns": None,
                "using_dot_or_doh_dns": None,
                "note": detail,
            }
        )

    for ip in dns_ips:
        base = ip.split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(base)
        except ValueError:
            continue
        if addr.is_private and not addr.is_loopback:
            raw, detail = _dig_akahelp_txt(nameserver=base)
            if raw:
                result = _classify_akahelp_txt(raw, mullvad_pop_reference=mullvad_pop_reference)
                print(f"Akahelp TXT via configured LAN DNS {base} ({detail}):")
                for line in raw.splitlines():
                    print(f"  {line}")
                print(f"  Classification: {result['kind']} — {result['note']}")
                checks.append({"scope": f"lan:{base}", "detail": detail, **result})
            else:
                print(f"Akahelp TXT via configured LAN DNS {base}: failed ({detail})")
                checks.append(
                    {
                        "scope": f"lan:{base}",
                        "detail": detail,
                        "raw": None,
                        "normalized": "",
                        "kind": "unknown",
                        "using_mullvad_dns": None,
                        "using_dot_or_doh_dns": None,
                        "note": detail,
                    }
                )
            break

    using_values = [check.get("using_mullvad_dns") for check in checks]
    dot_values = [check.get("using_dot_or_doh_dns") for check in checks]
    using_mullvad = True if True in using_values else (None if None in using_values else False)
    using_dot_or_doh = True if True in dot_values else (None if None in dot_values else False)
    print(f"Akahelp USING_MULLVAD_DNS: {_yes_no_unknown(using_mullvad)}")
    print(f"Akahelp USING_DOT_OR_DOH_DNS: {_yes_no_unknown(using_dot_or_doh)}")
    return {
        "checks": checks,
        "using_mullvad_dns": using_mullvad,
        "using_dot_or_doh_dns": using_dot_or_doh,
    }


def _print_mullvad_leak_probe_report() -> dict[str, Any]:
    print("\n--- Secondary: Mullvad dnsleak.am.i.mullvad.net probe ---")
    print(
        "Same family of check as https://mullvad.net/check DNS box. "
        "Can fail or NXDOMAIN on some networks; whoami above is authoritative for upstream IP."
    )
    servers, err = mullvad_dns_leak_probe(samples=4)
    if err and not servers:
        print(f"Probe failed: {err}")
        return {
            "using_mullvad_dns": None,
            "using_mullvad_encrypted_public_dns": None,
            "upstream_kind": "unknown",
            "error": err,
        }
    if not servers:
        print("Probe returned no servers.")
        return {
            "using_mullvad_dns": None,
            "using_mullvad_encrypted_public_dns": None,
            "upstream_kind": "unknown",
            "error": "no servers returned",
        }

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
    print(
        "Leak-probe USING_DOT_OR_DOH_DNS: "
        f"{'yes' if summary['using_mullvad_encrypted_public_dns'] else 'no'}"
    )
    print(f"Leak-probe UPSTREAM: {summary['upstream_kind']}")
    print(f"Leak-probe NOTE: {summary['encryption_note']}")
    return summary


def _yes_no_unknown(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


def _print_dns_path_summary(
    configured: dict[str, Any],
    upstream: dict[str, Any],
    akahelp: dict[str, Any],
    leak_probe: dict[str, Any],
) -> None:
    """Combine configured, upstream, Akahelp TXT, LAN-forwarder, and leak-probe evidence."""
    print("\n--- DNS Path Summary ---")

    mullvad_evidence: list[str] = []
    dot_or_doh_evidence: list[str] = []
    dot_specific_evidence: list[str] = []
    unknown_evidence: list[str] = []

    for ip in configured.get("mullvad_configured_ips", []):
        mullvad_evidence.append(f"configured resolver {ip} is Mullvad public DNS")
        dot_or_doh_evidence.append(
            f"configured resolver {ip} is Mullvad public encrypted DNS (DoT/DoH endpoint)"
        )

    for row in configured.get("windows_doh_rows", []):
        server = row.get("server") or "(n/a)"
        tmpl = row.get("template") or "(n/a)"
        dot_or_doh_evidence.append(f"Windows DoH template configured for {server}: {tmpl}")
    for row in configured.get("windows_doh_mullvad_rows", []):
        server = row.get("server") or "(n/a)"
        tmpl = row.get("template") or "(n/a)"
        mullvad_evidence.append(f"Windows DoH template points at Mullvad for {server}: {tmpl}")

    if upstream.get("using_mullvad_dns") is True:
        mullvad_evidence.append(
            f"system whoami upstream {upstream.get('whoami_ip')} is {upstream.get('kind')}"
        )
    elif upstream.get("using_mullvad_dns") is None:
        unknown_evidence.append("system whoami upstream could not be classified")

    if upstream.get("using_dot_or_doh_dns") is True:
        dot_or_doh_evidence.append(
            f"system whoami upstream {upstream.get('whoami_ip')} is Mullvad public DoT/DoH DNS"
        )
        if upstream.get("whoami_ip") == upstream.get("mullvad_dot_reference_ip"):
            dot_specific_evidence.append(
                "system upstream matches the live Mullvad DoT reference PoP"
            )

    for check in upstream.get("lan_checks", []):
        base = check.get("configured_dns")
        who_ip = check.get("whoami_ip")
        if check.get("using_mullvad_dns") is True:
            mullvad_evidence.append(f"LAN DNS {base} forwards upstream to Mullvad ({who_ip})")
        elif check.get("using_mullvad_dns") is None:
            unknown_evidence.append(f"LAN DNS {base} upstream whoami failed")
        if check.get("using_dot_or_doh_dns") is True:
            dot_or_doh_evidence.append(
                f"LAN DNS {base} forwards to Mullvad public DoT/DoH upstream ({who_ip})"
            )
            if who_ip == upstream.get("mullvad_dot_reference_ip"):
                dot_specific_evidence.append(
                    f"LAN DNS {base} upstream matches the live Mullvad DoT reference PoP"
                )

    for check in akahelp.get("checks", []):
        scope = check.get("scope") or "akahelp"
        raw = check.get("normalized") or check.get("raw") or ""
        if check.get("using_mullvad_dns") is True:
            mullvad_evidence.append(f"Akahelp TXT {scope} identifies Mullvad DNS: {raw}")
        elif check.get("using_mullvad_dns") is None:
            unknown_evidence.append(f"Akahelp TXT {scope} inconclusive: {check.get('note')}")
        if check.get("using_dot_or_doh_dns") is True:
            dot_or_doh_evidence.append(
                f"Akahelp TXT {scope} identifies Mullvad public encrypted DNS: {raw}"
            )

    if leak_probe.get("using_mullvad_dns") is True:
        mullvad_evidence.append("Mullvad leak probe observed Mullvad DNS resolver(s)")
    elif leak_probe.get("using_mullvad_dns") is None:
        unknown_evidence.append(f"Mullvad leak probe inconclusive: {leak_probe.get('error')}")
    if leak_probe.get("using_mullvad_encrypted_public_dns") is True:
        dot_or_doh_evidence.append(
            "Mullvad leak probe observed Mullvad public encrypted DNS hostname(s)"
        )

    mullvad_anywhere = True if mullvad_evidence else (None if unknown_evidence else False)
    dot_or_doh_anywhere = True if dot_or_doh_evidence else (None if unknown_evidence else False)
    dot_specific_anywhere = True if dot_specific_evidence else (
        None if dot_or_doh_evidence or unknown_evidence else False
    )

    print(f"DOT_USED_ANY_DNS: {_yes_no_unknown(dot_specific_anywhere)}")
    if dot_specific_anywhere is None and dot_or_doh_evidence:
        print(
            "  Note: encrypted public DNS was observed, but this script cannot always "
            "distinguish DoT from DoH without packet capture."
        )
    for item in dot_specific_evidence:
        print(f"  - {item}")

    print(f"DOT_OR_DOH_USED_ANY_DNS: {_yes_no_unknown(dot_or_doh_anywhere)}")
    for item in dot_or_doh_evidence:
        print(f"  - {item}")

    print(f"MULLVAD_DNS_USED_ANYWHERE: {_yes_no_unknown(mullvad_anywhere)}")
    for item in mullvad_evidence:
        print(f"  - {item}")

    if unknown_evidence:
        print("Inconclusive checks:")
        for item in unknown_evidence:
            print(f"  - {item}")


def get_dns_info() -> None:
    if is_wsl_local():
        dns_ips = resolv_nameservers()
        detection_source = "Linux /etc/resolv.conf - WSL"
        if not dns_ips:
            print("SCORE: 3")
            print("STATUS: No WSL /etc/resolv.conf nameservers detected.")
            return
    else:
        try:
            dns_ips, detection_source = configured_dns_servers()
        except Exception as exc:
            dns_ips = resolv_nameservers()
            detection_source = (
                "Linux /etc/resolv.conf fallback "
                f"(primary configured-DNS lookup failed: {exc})"
            )
            if not dns_ips:
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
        akahelp = _print_akahelp_txt_report(
            [],
            mullvad_pop_reference=upstream.get("mullvad_dot_reference_ip"),
        )
        leak_probe = _print_mullvad_leak_probe_report()
        _print_dns_path_summary(
            {
                "mullvad_configured_ips": [],
                "lan_forwarder": False,
                "loopback_stub": False,
                "windows_doh_rows": [],
                "windows_doh_mullvad_rows": [],
            },
            upstream,
            akahelp,
            leak_probe,
        )
        return

    print(f"\nConfigured IPv4 DNS servers ({len(dns_ips)} unique, order preserved where possible):")
    for i, ip in enumerate(dns_ips, start=1):
        _print_resolver_report(i, ip)

    configured = _print_configured_encryption_hints(dns_ips)
    upstream = _print_upstream_whoami_report(dns_ips)
    akahelp = _print_akahelp_txt_report(
        dns_ips,
        mullvad_pop_reference=upstream.get("mullvad_dot_reference_ip"),
    )
    leak_probe = _print_mullvad_leak_probe_report()
    _print_dns_path_summary(configured, upstream, akahelp, leak_probe)

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
