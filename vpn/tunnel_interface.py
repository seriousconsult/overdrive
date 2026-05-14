#!/usr/bin/env python3
"""VPN/tunnel virtual interface detection via Linux ``ip link``.

Purpose: Name-pattern scan for tun/tap/wg-style NICs common when VPN software installs a tunnel.

Score (1–5): **1** = no tunnel-pattern interface names seen on this namespace (quiet). **5** =
multiple tunnel-pattern interfaces (strong tunnel-environment signal). **3** = ambiguous (many
NICs, no name match).

Environment: **Linux / WSL** where ``ip -o link show`` exists; Windows-native Python without ``ip``
will enumerate nothing useful.

Exit code: **0** always after analysis completes.
"""

from __future__ import annotations

import re
import sys
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from common.common_vpn import run


TUNNEL_PATTERNS = [
    r"^tun",
    r"^tap",
    r"^wg",
    r"^ppp",
    r"^ipsec",
    r"^vti",
    r"^gre",
    r"^tailscale",
    r"^utun",
    r"^zt",
    r"^as0t",
]


def get_interfaces() -> list[str]:
    out = run(["ip", "-o", "link", "show"])
    ifaces: list[str] = []
    for line in out.splitlines():
        match = re.match(r"^\d+:\s+([^:]+):", line)
        if match:
            ifaces.append(match.group(1).strip())
    return ifaces


def is_tunnel_iface(name: str) -> bool:
    return any(re.match(p, name) for p in TUNNEL_PATTERNS)


def calculate_tunnel_score() -> tuple[int, str]:
    ifaces = get_interfaces()
    if not ifaces:
        return 3, "No network interfaces enumerated (need `ip link` — e.g. Linux/WSL)."

    active_ifaces = [i for i in ifaces if i != "lo"]
    detected_tunnels = [i for i in active_ifaces if is_tunnel_iface(i)]

    if len(detected_tunnels) > 1:
        score = 5
        status = f"Multiple tunnel interfaces: {', '.join(detected_tunnels)}"
    elif len(detected_tunnels) == 1:
        score = 4
        status = f"Tunnel interface detected: '{detected_tunnels[0]}'"
    elif len(active_ifaces) > 4:
        score = 3
        status = (
            f"No tunnel name patterns matched, but many interfaces ({len(active_ifaces)}) — "
            "possible VM/container or complex routing."
        )
    else:
        score = 1
        status = "No tunnel-pattern interfaces found (tun/tap/wg/…); no VPN-style virtual iface names."

    return score, status


def main() -> int:
    print("=" * 50)
    print("TUNNEL INTERFACE ANALYSIS (MTU IGNORED)")
    print("Scale: 1 = no tunnel-pattern NICs · 5 = tunnel(s) detected")
    print("=" * 50)

    score, message = calculate_tunnel_score()

    print(f"\nSCORE: {score}")
    print(f"STATUS: {message}")
    print("\n" + "=" * 50)
    return 0


if __name__ == "__main__":
    sys.exit(main())
