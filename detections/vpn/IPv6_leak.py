#!/usr/bin/env python3
"""
IPv6 Leak Detection

Many VPNs tunnel only IPv4. If the host still has working IPv6 to the Internet,
traffic or DNS can bypass the VPN. This script reports both:

  - External IPv4/IPv6 egress observed by HTTPS endpoints.
  - Local IPv6 interface, route, DNS, and sysctl evidence.

Linux note: ``ip -6 addr`` labels ULA addresses such as ``fd00::/8`` as
``scope global``. That means "not link-local" to the kernel; it does not mean
the address is public Internet-routable. This probe separates ULA/private IPv6
from public global unicast IPv6.

Score (1-5):
  5 = Strong signs of IPv6 taking a different exit than IPv4 (likely leak)
  4 = IPv6 egress works; could not fully validate or only soft mismatch
  3 = Inconclusive (partial failures, broken route, odd local vs egress)
  2 = No working public IPv6 egress / low IPv6 leak surface
  1 = IPv4 and IPv6 exits look consistent
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import requests

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_config import IPIFY_IPV6_URL, USER_AGENTS
from detections.common.common_dns import resolv_nameservers
from detections.common.common_vpn import fetch_ip_api, public_ipv4

TIMEOUT = 10
UA = {"User-Agent": USER_AGENTS["ipv6_leak"]}
IPV6_PROBES: tuple[tuple[str, str, str], ...] = (
    ("ipify6", "json", IPIFY_IPV6_URL),
    ("icanhazip6", "text", "https://ipv6.icanhazip.com/"),
    ("identme6", "text", "https://v6.ident.me/"),
)
PUBLIC_V6_ROUTE_TARGET = "2606:4700:4700::1111"


def _run(cmd: list[str], timeout: float = 6.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", f"{type(exc).__name__}: {exc}"


def _parse_ip(value: str | None) -> ipaddress._BaseAddress | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return None


def _parse_ipv6(value: str | None) -> str | None:
    addr = _parse_ip(value)
    if addr and addr.version == 6:
        return str(addr)
    return None


def _ipv6_kind(value: str) -> str:
    addr = _parse_ip(value)
    if not addr or addr.version != 6:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        if str(addr).lower().startswith(("fc", "fd")):
            return "ula-private"
        return "private/special"
    if addr.is_reserved:
        return "reserved"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_global:
        return "public-global"
    return "special"


def _is_public_global_v6(value: str) -> bool:
    return _ipv6_kind(value) == "public-global"


def _read_sysctl(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def fetch_ipv6_probe(name: str, mode: str, url: str) -> dict[str, Any]:
    try:
        response = requests.get(url, headers=UA, timeout=TIMEOUT)
        response.raise_for_status()
        if mode == "json":
            data = response.json()
            ip = _parse_ipv6(str(data.get("ip") or ""))
        else:
            ip = _parse_ipv6(response.text.strip().split()[0] if response.text else "")
        if not ip:
            return {
                "name": name,
                "url": url,
                "ip": None,
                "ok": False,
                "error": "response did not contain a valid IPv6 address",
            }
        return {"name": name, "url": url, "ip": ip, "ok": True, "error": ""}
    except (requests.RequestException, ValueError, KeyError, json.JSONDecodeError) as exc:
        return {"name": name, "url": url, "ip": None, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


def public_ipv6_observations() -> list[dict[str, Any]]:
    return [fetch_ipv6_probe(name, mode, url) for name, mode, url in IPV6_PROBES]


def select_external_ipv6(observations: list[dict[str, Any]]) -> tuple[str | None, bool, str]:
    ips = [str(obs["ip"]) for obs in observations if obs.get("ok") and obs.get("ip")]
    if not ips:
        return None, False, "all IPv6 HTTPS probes failed"
    by_ip: dict[str, list[str]] = {}
    for obs in observations:
        if obs.get("ok") and obs.get("ip"):
            by_ip.setdefault(str(obs["ip"]), []).append(str(obs["name"]))
    if len(by_ip) > 1:
        parts = [f"{ip} ({', '.join(names)})" for ip, names in sorted(by_ip.items())]
        return next(iter(by_ip)), False, "IPv6 probes disagree: " + "; ".join(parts)
    ip = next(iter(by_ip))
    strong = len(by_ip[ip]) >= 2
    note = "" if strong else f"only one IPv6 probe succeeded ({by_ip[ip][0]})"
    return ip, strong, note


def local_ipv6_addresses() -> tuple[list[dict[str, Any]], str | None]:
    """Return local IPv6 address rows from ``ip -o -6 addr`` or /proc fallback."""
    code, out, err = _run(["ip", "-o", "-6", "addr", "show"], timeout=6)
    rows: list[dict[str, Any]] = []
    if code == 0 and out.strip():
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[2] != "inet6":
                continue
            iface = parts[1].rstrip(":")
            address_prefix = parts[3]
            address = address_prefix.split("/", 1)[0]
            scope = ""
            if "scope" in parts:
                idx = parts.index("scope")
                if idx + 1 < len(parts):
                    scope = parts[idx + 1]
            flags_start = parts.index(scope) + 1 if scope and scope in parts else 4
            flags = " ".join(parts[flags_start:])
            rows.append(
                {
                    "iface": iface,
                    "address": address,
                    "prefix": address_prefix,
                    "kernel_scope": scope or "?",
                    "kind": _ipv6_kind(address),
                    "flags": flags,
                    "source": "ip",
                }
            )
        return rows, None

    proc = Path("/proc/net/if_inet6")
    try:
        raw = proc.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], (err.strip() or "ip command unavailable and /proc/net/if_inet6 unreadable")

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        hexaddr, _idx, plen, scope_hex, flags_hex, iface = parts[:6]
        hextets = [hexaddr[i : i + 4] for i in range(0, len(hexaddr), 4)]
        try:
            addr = str(ipaddress.IPv6Address(":".join(hextets)))
        except ValueError:
            continue
        rows.append(
            {
                "iface": iface,
                "address": addr,
                "prefix": f"{addr}/{int(plen, 16)}",
                "kernel_scope": f"0x{scope_hex}",
                "kind": _ipv6_kind(addr),
                "flags": f"0x{flags_hex}",
                "source": "/proc/net/if_inet6",
            }
        )
    return rows, None


def ipv6_route_info() -> dict[str, Any]:
    default_code, default_out, default_err = _run(["ip", "-6", "route", "show", "default"], timeout=6)
    all_code, all_out, all_err = _run(["ip", "-6", "route", "show"], timeout=6)
    get_code, get_out, get_err = _run(["ip", "-6", "route", "get", PUBLIC_V6_ROUTE_TARGET], timeout=6)
    proc_routes, proc_defaults, proc_error = _proc_ipv6_routes()
    default_routes = [line.strip() for line in default_out.splitlines() if line.strip()]
    route_sample = [line.strip() for line in all_out.splitlines() if line.strip()][:12]
    if not default_routes and proc_defaults:
        default_routes = proc_defaults
    if not route_sample and proc_routes:
        route_sample = proc_routes[:12]
    usable_defaults = [route for route in default_routes if _usable_default_route(route)]
    return {
        "default_routes": default_routes,
        "usable_default_routes": usable_defaults,
        "default_error": default_err.strip() if default_code != 0 else "",
        "route_sample": route_sample,
        "route_error": all_err.strip() if all_code != 0 else "",
        "route_get_target": PUBLIC_V6_ROUTE_TARGET,
        "route_get": get_out.strip(),
        "route_get_error": get_err.strip() if get_code != 0 else "",
        "route_get_ok": get_code == 0 and bool(get_out.strip()),
        "proc_route_error": proc_error,
    }


def _usable_default_route(route: str) -> bool:
    lower = route.lower()
    if "unreachable" in lower or "prohibit" in lower or "throw" in lower:
        return False
    if " dev lo " in lower and " via ::" in lower:
        return False
    if " metric 4294967295 " in lower and " flags 0x200200 " in lower:
        return False
    return True


def _hex_ipv6(value: str) -> str:
    hextets = [value[i : i + 4] for i in range(0, len(value), 4)]
    return str(ipaddress.IPv6Address(":".join(hextets)))


def _proc_ipv6_routes() -> tuple[list[str], list[str], str]:
    path = Path("/proc/net/ipv6_route")
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [], f"{type(exc).__name__}: {exc}"
    rows: list[str] = []
    defaults: list[str] = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        dest_hex, dest_plen_hex, _src_hex, _src_plen_hex, next_hop_hex = parts[:5]
        metric_hex, _refcnt_hex, _use_hex, flags_hex, iface = parts[5:10]
        try:
            dest_plen = int(dest_plen_hex, 16)
            metric = int(metric_hex, 16)
            flags = int(flags_hex, 16)
            dest = _hex_ipv6(dest_hex)
            via = _hex_ipv6(next_hop_hex)
        except ValueError:
            continue
        label = f"{dest}/{dest_plen} via {via} dev {iface} metric {metric} flags 0x{flags:x} (/proc)"
        rows.append(label)
        if dest_hex == "0" * 32 and dest_plen == 0:
            defaults.append(f"default via {via} dev {iface} metric {metric} flags 0x{flags:x} (/proc)")
    return rows, defaults, ""


def ipv6_dns_nameservers() -> list[str]:
    return [ns for ns in resolv_nameservers() if _parse_ipv6(ns)]


def ipv6_sysctl_info(address_rows: list[dict[str, Any]]) -> dict[str, str]:
    info = {
        "all.disable_ipv6": _read_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6"),
        "default.disable_ipv6": _read_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6"),
    }
    for iface in sorted({str(row["iface"]) for row in address_rows}):
        value = _read_sysctl(f"/proc/sys/net/ipv6/conf/{iface}/disable_ipv6")
        if value:
            info[f"{iface}.disable_ipv6"] = value
    return {k: v for k, v in info.items() if v != ""}


def ip_metadata(ip: str) -> dict[str, Any]:
    return fetch_ip_api(ip)


def _norm_org(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"\s+", " ", s)
    return s


def _orgs_consistent(a: str, b: str) -> bool:
    a, b = _norm_org(a), _norm_org(b)
    if not a or not b:
        return True
    if a == b:
        return True
    if a in b or b in a:
        return True
    ta, tb = a.split()[:1], b.split()[:1]
    return bool(ta and tb and ta == tb)


def build_ipv6_report() -> dict[str, Any]:
    v4 = public_ipv4()
    v6_observations = public_ipv6_observations()
    v6, v6_strong, v6_note = select_external_ipv6(v6_observations)
    address_rows, address_error = local_ipv6_addresses()
    routes = ipv6_route_info()
    sysctls = ipv6_sysctl_info(address_rows)
    dns_v6 = ipv6_dns_nameservers()

    public_local = [row for row in address_rows if _is_public_global_v6(str(row["address"]))]
    ula_local = [row for row in address_rows if row.get("kind") == "ula-private"]
    link_local = [row for row in address_rows if row.get("kind") == "link-local"]
    kernel_global = [row for row in address_rows if row.get("kernel_scope") == "global"]

    return {
        "ipv4": v4,
        "ipv6": v6,
        "ipv6_consensus_strong": v6_strong,
        "ipv6_probe_note": v6_note,
        "ipv6_observations": v6_observations,
        "addresses": address_rows,
        "address_error": address_error,
        "public_local_addresses": public_local,
        "ula_local_addresses": ula_local,
        "link_local_addresses": link_local,
        "kernel_global_addresses": kernel_global,
        "routes": routes,
        "sysctls": sysctls,
        "dns_ipv6_nameservers": dns_v6,
    }


def score_ipv6_report(report: dict[str, Any]) -> tuple[int, str]:
    v4 = report.get("ipv4")
    v6 = report.get("ipv6")
    public_local = report.get("public_local_addresses") or []
    ula_local = report.get("ula_local_addresses") or []
    kernel_global = report.get("kernel_global_addresses") or []
    routes = report.get("routes") or {}
    has_default_v6 = bool(routes.get("usable_default_routes"))
    route_get_ok = bool(routes.get("route_get_ok"))

    if v4 is None and v6 is None:
        if public_local or has_default_v6 or route_get_ok:
            return 3, "IPv6 is configured locally, but public IPv4/IPv6 HTTPS probes failed."
        return 3, "Could not reach public IPv4 or IPv6 probes (offline, DNS blocked, or captive network)."

    if v6 is None:
        if public_local and (has_default_v6 or route_get_ok):
            return (
                3,
                "Public global IPv6 is configured locally, but all IPv6 HTTPS egress probes failed "
                "(broken route, firewall, or split stack).",
            )
        if public_local:
            return (
                3,
                "Public global IPv6 address exists locally, but no default IPv6 route and no IPv6 HTTPS egress were observed.",
            )
        if ula_local and kernel_global:
            return (
                2,
                "Only ULA/private IPv6 is present locally; no public IPv6 egress observed. "
                "Low Internet IPv6 leak surface.",
            )
        if has_default_v6 or route_get_ok:
            return (
                3,
                "IPv6 route exists but no public IPv6 address/egress was confirmed.",
            )
        return 2, "No public IPv6 address or IPv6 egress observed."

    if v4 is None:
        return 3, "IPv6 egress works but IPv4 check failed; cannot compare VPN paths."

    if not public_local:
        return (
            4,
            f"IPv6 egress works as {v6}, but no public global IPv6 address was found locally "
            "(possible proxy/tunnel/NAT66 or incomplete local inspection).",
        )

    m4, m6 = ip_metadata(str(v4)), ip_metadata(str(v6))
    ok4 = m4.get("status") == "success"
    ok6 = m6.get("status") == "success"
    if not ok4 or not ok6:
        return (
            4,
            f"IPv6 egress works ({v6}) but ISP/geolocation lookup was incomplete; verify manually.",
        )

    cc4 = (m4.get("countryCode") or "").upper()
    cc6 = (m6.get("countryCode") or "").upper()
    isp4 = m4.get("isp") or m4.get("org") or ""
    isp6 = m6.get("isp") or m6.get("org") or ""

    if cc4 and cc6 and cc4 != cc6:
        return 5, f"Likely IPv6 leak: IPv4 in {cc4}, IPv6 in {cc6} ({v4} vs {v6})."

    if cc4 and cc6 and cc4 == cc6 and isp4 and isp6 and not _orgs_consistent(isp4, isp6):
        return (
            5,
            f"Same country but different ISP labels (IPv4: {isp4[:50]} vs IPv6: {isp6[:50]}) - possible v6 bypass.",
        )

    if cc4 and cc6 and cc4 == cc6 and _orgs_consistent(isp4, isp6):
        return 1, f"IPv4/IPv6 agree ({cc4}); ISP metadata similar - no obvious split exit."

    return 4, f"IPv6 egress works ({v6}); metadata is partial, so leak status needs manual confirmation."


def print_report(report: dict[str, Any]) -> None:
    print("\n[Observed public addresses]")
    print(f"  IPv4 (ipify): {report.get('ipv4') or '(unavailable)'}")
    print(f"  IPv6 selected: {report.get('ipv6') or '(unavailable)'}")
    if report.get("ipv6_probe_note"):
        print(f"  IPv6 probe note: {report['ipv6_probe_note']}")

    print("\n[IPv6 egress probes]")
    for obs in report.get("ipv6_observations") or []:
        status = obs.get("ip") if obs.get("ok") else f"failed: {obs.get('error')}"
        print(f"  {obs.get('name')}: {status}")

    print("\n[Local IPv6 interface addresses]")
    rows = report.get("addresses") or []
    if not rows:
        print(f"  (none found) {report.get('address_error') or ''}".rstrip())
    else:
        for row in rows:
            print(
                "  "
                f"{row['iface']}: {row['prefix']}  kind={row['kind']}  "
                f"kernel_scope={row['kernel_scope']}  flags={row.get('flags') or '-'}"
            )
    print(
        "  Counts: "
        f"public_global={len(report.get('public_local_addresses') or [])}, "
        f"ula_private={len(report.get('ula_local_addresses') or [])}, "
        f"link_local={len(report.get('link_local_addresses') or [])}, "
        f"kernel_scope_global={len(report.get('kernel_global_addresses') or [])}"
    )

    print("\n[IPv6 routes]")
    routes = report.get("routes") or {}
    defaults = routes.get("default_routes") or []
    if defaults:
        print("  Default route(s):")
        for line in defaults:
            print(f"    {line}")
    else:
        print(f"  Default route(s): none {routes.get('default_error') or ''}".rstrip())
    route_get = routes.get("route_get")
    if route_get:
        print(f"  Route to {routes.get('route_get_target')}: {route_get}")
    else:
        print(
            f"  Route to {routes.get('route_get_target')}: unavailable "
            f"{routes.get('route_get_error') or ''}".rstrip()
        )
    sample = routes.get("route_sample") or []
    if sample:
        print("  Route table sample:")
        for line in sample:
            print(f"    {line}")
    elif routes.get("route_error") or routes.get("proc_route_error"):
        print(
            "  Route table sample: unavailable "
            f"{routes.get('route_error') or routes.get('proc_route_error')}"
        )

    print("\n[IPv6 DNS configuration]")
    dns_v6 = report.get("dns_ipv6_nameservers") or []
    if dns_v6:
        for ns in dns_v6:
            print(f"  nameserver {ns}  kind={_ipv6_kind(ns)}")
    else:
        print("  No IPv6 nameservers found in /etc/resolv.conf.")

    print("\n[IPv6 sysctl]")
    sysctls = report.get("sysctls") or {}
    if sysctls:
        for key, value in sysctls.items():
            print(f"  {key}={value}")
    else:
        print("  (not available)")

    if report.get("ipv4") and report.get("ipv6"):
        print("\n[IPv4 / IPv6 metadata]")
        for label, ip in (("IPv4", report["ipv4"]), ("IPv6", report["ipv6"])):
            meta = ip_metadata(str(ip))
            if meta.get("status") == "success":
                print(
                    f"  {label} {ip}: country={meta.get('countryCode') or '?'} "
                    f"isp={meta.get('isp') or meta.get('org') or '?'} "
                    f"as={meta.get('as') or '?'}"
                )
            else:
                print(f"  {label} {ip}: metadata unavailable ({meta.get('message') or 'request failed'})")


def check_ipv6_leak() -> tuple[int, str]:
    return score_ipv6_report(build_ipv6_report())


def main() -> int:
    print("=" * 60)
    print("IPv6 Leak Detection")
    print("=" * 60)

    report = build_ipv6_report()
    print_report(report)
    score, description = score_ipv6_report(report)

    print("\n" + "-" * 40)
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print("-" * 40)
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
