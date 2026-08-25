#!/usr/bin/env python3
"""MTU / path-MTU observation.

This detector reports three different things:

  - Local link MTU: what the visible Linux interfaces advertise.
  - TCP MSS over IPv4/TCP/443: ICMP-free active signal for MSS clamping.
  - Optional IPv4 path MTU: the largest DF-set ICMP packet that reaches a target.

The old detector only used local link MTU. That often stays 1500 with or without
VPNs, especially in VMs/WSL or when a router/VPN clamps TCP MSS instead of
lowering the visible interface MTU.

Score (1-5):
  1 = no visible MTU reduction; weak/non-discriminating VPN signal
  2 = slight path/link reduction
  3 = moderate path/link reduction
  4 = strong tunnel-like MTU reduction
  5 = very small MTU / heavy encapsulation
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_utils import run_output


TCP_MSS_TARGETS: tuple[tuple[str, str, int], ...] = (
    ("cloudflare", "1.1.1.1", 443),
    ("google-dns", "8.8.8.8", 443),
    ("quad9", "9.9.9.9", 443),
)
IPV4_PING_TARGETS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
IPV4_HEADER_AND_TCP_BYTES = 40
IPV4_HEADER_AND_ICMP_BYTES = 28
MAX_ETHERNET_IPV4_PAYLOAD = 1500 - IPV4_HEADER_AND_ICMP_BYTES


def _run(cmd: list[str], timeout: float = 6.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, f"{type(exc).__name__}: {exc}"


def _is_tunnelish_iface(name: str) -> bool:
    n = (name or "").lower()
    if not n or n == "lo":
        return False
    tunnel_prefixes = (
        "tun",
        "tap",
        "wg",
        "ipsec",
        "ppp",
        "l2tp",
        "gtp",
        "gre",
        "gretap",
        "erspan",
        "tailscale",
        "zt",
        "veth",
        "docker",
        "br-",
        "virbr",
    )
    return n.startswith(tunnel_prefixes) or "vpn" in n


def _is_wsl() -> bool:
    try:
        version = Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower()
        return "microsoft" in version
    except OSError:
        return bool(os.environ.get("WSL_DISTRO_NAME"))


def get_link_mtu_info() -> dict[str, Any]:
    """Parse local interface MTUs from ``ip -o link show``."""
    out = run_output(["ip", "-o", "link", "show"])
    interfaces: list[dict[str, Any]] = []

    for line in out.splitlines():
        m_if = re.match(r"^\d+:\s*(\S+)@", line) or re.match(r"^\d+:\s*(\S+):", line)
        iface = m_if.group(1) if m_if else ""
        if iface == "lo":
            continue

        m_mtu = re.search(r"\bmtu\s+(\d+)\b", line)
        if not iface or not m_mtu:
            continue
        mtu = int(m_mtu.group(1))
        interfaces.append(
            {
                "name": iface,
                "mtu": mtu,
                "tunnelish": _is_tunnelish_iface(iface),
                "raw": line.strip(),
            }
        )

    mtus = [int(row["mtu"]) for row in interfaces]
    tunnel = [(str(row["name"]), int(row["mtu"])) for row in interfaces if row["tunnelish"]]
    return {
        "interfaces": interfaces,
        "min_mtu": min(mtus) if mtus else None,
        "tunnel_ifaces": tunnel,
        "error": "" if out.strip() else "ip -o link show returned no usable interfaces",
    }


def get_min_mtu() -> int:
    info = get_link_mtu_info()
    return int(info.get("min_mtu") or 1500)


def _ping_df_payload(target: str, payload_size: int) -> tuple[bool, str]:
    cmd = [
        "ping",
        "-4",
        "-n",
        "-c",
        "1",
        "-W",
        "2",
        "-M",
        "do",
        "-s",
        str(payload_size),
        target,
    ]
    code, out = _run(cmd, timeout=5.0)
    return code == 0, " ".join(out.split())[-240:]


def _ping_supports_df() -> tuple[bool, str]:
    ok, detail = _ping_df_payload("127.0.0.1", 0)
    lower = detail.lower()
    if ok:
        return True, ""
    if "invalid option" in lower or "usage:" in lower or "bad address" in lower:
        return False, detail
    # Some restricted namespaces may refuse local ping; still try real probes.
    return True, detail


def _tracepath_pmtu(target: str) -> tuple[int | None, str]:
    for cmd in (["tracepath", "-n", "-4", target], ["tracepath", "-n", target]):
        code, out = _run(cmd, timeout=8.0)
        if code == 127 and "FileNotFoundError" in out:
            continue
        matches = re.findall(r"\bpmtu\s+(\d+)\b", out, flags=re.I)
        if matches:
            return int(matches[-1]), " ".join(out.split())[-240:]
        if code != 127:
            return None, " ".join(out.split())[-240:]
    return None, "tracepath not available"


def _connect_ipv4_tcp(host: str, port: int, timeout: float = 5.0) -> socket.socket:
    last_exc: OSError | None = None
    for family, socktype, proto, _canon, sockaddr in socket.getaddrinfo(
        host,
        port,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
    ):
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_exc = exc
            sock.close()
    raise OSError(str(last_exc) if last_exc else f"no IPv4 TCP address for {host}:{port}")


def _probe_tcp_mss(label: str, host: str, port: int) -> dict[str, Any]:
    try:
        with _connect_ipv4_tcp(host, port) as sock:
            mss = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    except (OSError, socket.gaierror) as exc:
        return {
            "label": label,
            "host": host,
            "port": port,
            "ok": False,
            "mss": None,
            "inferred_mtu": None,
            "note": f"{type(exc).__name__}: {exc}",
        }
    if not isinstance(mss, int) or mss <= 0:
        return {
            "label": label,
            "host": host,
            "port": port,
            "ok": False,
            "mss": mss,
            "inferred_mtu": None,
            "note": "TCP_MAXSEG returned no usable MSS",
        }
    return {
        "label": label,
        "host": host,
        "port": port,
        "ok": True,
        "mss": mss,
        "inferred_mtu": mss + IPV4_HEADER_AND_TCP_BYTES,
        "note": "TCP_MAXSEG after IPv4 TCP connect; inferred MTU = MSS + 40 bytes",
    }


def get_tcp_mss_info(targets: tuple[tuple[str, str, int], ...] = TCP_MSS_TARGETS) -> dict[str, Any]:
    results = [_probe_tcp_mss(label, host, port) for label, host, port in targets]
    ok_results = [row for row in results if row.get("ok") and row.get("inferred_mtu")]
    mtus = [int(row["inferred_mtu"]) for row in ok_results]
    return {
        "results": results,
        "selected_inferred_mtu": min(mtus) if mtus else None,
        "ok_count": len(ok_results),
    }


def _probe_target_path_mtu(target: str) -> dict[str, Any]:
    small_ok, small_detail = _ping_df_payload(target, 0)
    if not small_ok:
        trace_mtu, trace_detail = _tracepath_pmtu(target)
        return {
            "target": target,
            "ok": trace_mtu is not None,
            "method": "tracepath" if trace_mtu is not None else "ping/tracepath",
            "path_mtu": trace_mtu,
            "note": trace_detail if trace_mtu is not None else f"small ping failed: {small_detail}",
        }

    max_ok, max_detail = _ping_df_payload(target, MAX_ETHERNET_IPV4_PAYLOAD)
    if max_ok:
        return {
            "target": target,
            "ok": True,
            "method": "ping -M do",
            "path_mtu": 1500,
            "note": "1472-byte ICMP payload succeeded with DF set",
        }

    lo = 0
    hi = MAX_ETHERNET_IPV4_PAYLOAD
    best = 0
    last_fail = max_detail
    while lo <= hi:
        mid = (lo + hi) // 2
        ok, detail = _ping_df_payload(target, mid)
        if ok:
            best = mid
            lo = mid + 1
        else:
            last_fail = detail
            hi = mid - 1

    return {
        "target": target,
        "ok": True,
        "method": "ping -M do",
        "path_mtu": best + IPV4_HEADER_AND_ICMP_BYTES,
        "note": f"largest DF payload={best}; next failure: {last_fail}",
    }


def get_path_mtu_info(targets: tuple[str, ...] = IPV4_PING_TARGETS) -> dict[str, Any]:
    supported, support_detail = _ping_supports_df()
    results: list[dict[str, Any]] = []
    if not supported:
        for target in targets:
            mtu, detail = _tracepath_pmtu(target)
            results.append(
                {
                    "target": target,
                    "ok": mtu is not None,
                    "method": "tracepath",
                    "path_mtu": mtu,
                    "note": detail,
                }
            )
    else:
        for target in targets:
            results.append(_probe_target_path_mtu(target))

    ok_results = [row for row in results if row.get("ok") and row.get("path_mtu")]
    mtus = [int(row["path_mtu"]) for row in ok_results]
    return {
        "supported": supported,
        "support_note": support_detail,
        "results": results,
        "selected_path_mtu": min(mtus) if mtus else None,
        "ok_count": len(ok_results),
    }


def calculate_mtu_score(mtu: int | None) -> int:
    """Score by the smallest observed local/path MTU."""
    if mtu is None:
        return 3
    if mtu >= 1500:
        return 1
    if mtu > 1450:
        return 2
    if mtu > 1420:
        return 3
    if mtu > 1350:
        return 4
    return 5


def build_mtu_report() -> dict[str, Any]:
    link = get_link_mtu_info()
    tcp = get_tcp_mss_info()
    path = get_path_mtu_info()
    observed = [
        value
        for value in (
            link.get("min_mtu"),
            tcp.get("selected_inferred_mtu"),
            path.get("selected_path_mtu"),
        )
        if isinstance(value, int)
    ]
    selected = min(observed) if observed else None
    return {
        "link": link,
        "tcp": tcp,
        "path": path,
        "selected_mtu": selected,
        "score": calculate_mtu_score(selected),
        "wsl": _is_wsl(),
    }


def _format_iface_rows(interfaces: list[dict[str, Any]]) -> str:
    if not interfaces:
        return "  (none parsed)"
    rows = []
    for row in sorted(interfaces, key=lambda r: str(r["name"]).lower()):
        marker = " tunnel-name" if row.get("tunnelish") else ""
        rows.append(f"  {row['name']}: mtu={row['mtu']}{marker}")
    return "\n".join(rows)


def print_mtu_report(report: dict[str, Any]) -> None:
    link = report["link"]
    tcp = report["tcp"]
    path = report["path"]

    print("\n[Local interface MTU]")
    print(f"  Minimum visible link MTU: {link.get('min_mtu') or '(unavailable)'}")
    if link.get("error"):
        print(f"  Note: {link['error']}")
    print(_format_iface_rows(link.get("interfaces") or []))
    tunnel_ifaces = link.get("tunnel_ifaces") or []
    if tunnel_ifaces:
        tshow = ", ".join(f"{name}={mtu}" for name, mtu in tunnel_ifaces[:20])
        more = "" if len(tunnel_ifaces) <= 20 else f" ... (+{len(tunnel_ifaces) - 20} more)"
        print(f"  Tunnel/VPN-ish interface names: {tshow}{more}")

    print("\n[TCP MSS probes over IPv4/TCP/443 (ICMP-free)]")
    selected_tcp = tcp.get("selected_inferred_mtu")
    print(f"  Selected inferred MTU: {selected_tcp or '(unavailable)'}")
    for row in tcp.get("results") or []:
        mss = row.get("mss") if row.get("ok") else "(failed)"
        mtu = row.get("inferred_mtu") if row.get("ok") else "(failed)"
        print(
            f"  {row.get('label')}: {row.get('host')}:{row.get('port')} "
            f"mss={mss} inferred_mtu={mtu}"
        )
        if row.get("note"):
            print(f"      note: {row['note']}")

    print("\n[Optional ICMP DF path MTU probes]")
    selected = path.get("selected_path_mtu")
    print(f"  Selected path MTU: {selected or '(unavailable)'}")
    if path.get("support_note"):
        print(f"  Probe support note: {path['support_note']}")
    for row in path.get("results") or []:
        mtu = row.get("path_mtu") if row.get("ok") else "(failed)"
        print(f"  {row.get('target')}: mtu={mtu} via {row.get('method')}")
        if row.get("note"):
            print(f"      note: {row['note']}")

    print("\n[Plain-English MTU result]")
    selected_mtu = report.get("selected_mtu")
    score = int(report.get("score") or 3)
    if selected_mtu is None:
        print("  RESULT: INCONCLUSIVE - no local, TCP MSS, or optional ICMP MTU could be measured.")
        print("  Meaning: required tools may be missing or outbound probes may be blocked.")
    elif selected_mtu >= 1500:
        print("  RESULT: NON-DISCRIMINATING - visible MTU/TCP MSS-derived MTU are 1500.")
        print(
            "  Meaning: this is normal with VPN off, but many VPN setups also preserve "
            "a visible 1500 MTU or hide the tunnel from this namespace."
        )
    elif score >= 4:
        print("  RESULT: STRONG MTU REDUCTION - tunnel/encapsulation overhead is likely visible.")
    else:
        print("  RESULT: SOME MTU REDUCTION - possible tunnel, VM, router, or provider overhead.")

    if report.get("wsl"):
        print("  Environment note: WSL2 can hide host VPN/tunnel interfaces.")
    print(
        "  Note: MTU alone is a weak VPN detector. Compare this output with "
        "ASN/egress IP, tunnel-interface, DNS, and timing detections."
    )


def _status_for_report(report: dict[str, Any]) -> str:
    selected_mtu = report.get("selected_mtu")
    path = report.get("path") or {}
    tcp = report.get("tcp") or {}
    link = report.get("link") or {}
    tunnel_ifaces = link.get("tunnel_ifaces") or []

    if selected_mtu is None:
        return (
            "Inconclusive: could not measure TCP MSS, optional ICMP path MTU, or visible link MTU. "
            "Outbound probes may be blocked or required tools may be missing."
        )
    if selected_mtu >= 1500:
        if tcp.get("ok_count"):
            return (
                "MTU is 1500 locally and via TCP MSS probes. This is non-discriminating: it can "
                "happen with VPN off or with VPNs that preserve/hide MTU."
            )
        if path.get("ok_count"):
            return (
                "MTU is 1500 locally and on optional ICMP path probes. This is non-discriminating: "
                "it can happen with VPN off or with VPNs that preserve/hide MTU."
            )
        return (
            "Visible local MTU is 1500, but TCP MSS / active path MTU was not confirmed. "
            "Treat as weak/non-discriminating for VPN detection."
        )
    if tunnel_ifaces:
        return (
            f"Reduced MTU ({selected_mtu}) plus tunnel-like interface name(s) observed; "
            "stronger tunnel/encapsulation signal."
        )
    return (
        f"Reduced MTU ({selected_mtu}) observed on link, TCP MSS, or optional path probes; "
        "possible tunnel, VM, router, or provider encapsulation."
    )


def main() -> int:
    report = build_mtu_report()
    print("=" * 60)
    print("MTU / Path-MTU Analysis")
    print("=" * 60)
    print_mtu_report(report)
    print("\n" + "-" * 40)
    print(f"SCORE: {report['score']}")
    print("Measured via: local link MTU, TCP MSS over IPv4/TCP/443, and optional ICMP DF probes")
    print(f"Minimum observed MTU: {report.get('selected_mtu') or '(unavailable)'}")
    print(f"STATUS: {_status_for_report(report)}")
    print("-" * 40)
    return 0


if __name__ == "__main__":
    sys.exit(main())
