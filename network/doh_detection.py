#!/usr/bin/env python3
"""
DNS-over-HTTPS (DoH) Detection

Best-effort detection from local configuration (no packet capture):
  - Windows: Get-DnsClientDohServerAddress
  - Firefox: network.trr.mode in prefs.js
  - Chrome / Edge: dns_over_https in Local State JSON
  - Linux: cloudflared config with HTTPS DNS upstream (common pattern)

Score (1–5), higher = stronger evidence of DoH / encrypted DNS in use:
  5 — Clear DoH configuration (OS DoH servers, Firefox TRR-only, Chrome secure, etc.)
  4 — Likely DoH (Firefox TRR race/prefers TRR, Chrome automatic, cloudflared DoH upstream)
  3 — Inconclusive (could not read settings or mixed errors)
  2 — Weak / ambiguous signal (e.g. cloudflared without clear DoH URL)
  1 — No DoH signals found in checked locations (typical plain DNS / OS resolver)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


def _firefox_trr_mode() -> int | None:
    """Return network.trr.mode if found in any Firefox profile prefs.js (0–5)."""
    candidates: list[Path] = []
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.extend(Path(appdata).joinpath("Mozilla", "Firefox", "Profiles").glob("*/prefs.js"))
    else:
        home = Path.home()
        candidates.extend(home.joinpath(".mozilla", "firefox").glob("*/prefs.js"))

    pat = re.compile(r'user_pref\s*\(\s*["\']network\.trr\.mode["\']\s*,\s*(\d+)\s*\)')
    modes: list[int] = []
    for p in candidates:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in pat.finditer(text):
            modes.append(int(m.group(1)))
    if not modes:
        return None
    return max(modes)


def _chromium_dns_over_https(local_state_path: Path) -> tuple[str | None, Any]:
    """
    Parse Chromium Local State for dns_over_https block.
    Returns (mode_string_or_none, raw_block_or_none).
    """
    if not local_state_path.is_file():
        return None, None
    try:
        data = json.loads(local_state_path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return None, None

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            if "dns_over_https" in o:
                return o["dns_over_https"]
            for v in o.values():
                r = walk(v)
                if r is not None:
                    return r
        elif isinstance(o, list):
            for v in o:
                r = walk(v)
                if r is not None:
                    return r
        return None

    block = walk(data)
    if not isinstance(block, dict):
        return None, block
    mode = block.get("mode")
    if isinstance(mode, str):
        return mode.lower(), block
    if mode is not None:
        return str(mode).lower(), block
    return None, block


def _chromium_local_state_paths() -> list[Path]:
    paths: list[Path] = []
    if sys.platform == "win32":
        lad = os.environ.get("LOCALAPPDATA")
        if lad:
            base = Path(lad)
            paths.extend(
                [
                    base / "Google" / "Chrome" / "User Data" / "Local State",
                    base / "Microsoft" / "Edge" / "User Data" / "Local State",
                    base / "BraveSoftware" / "Brave-Browser" / "User Data" / "Local State",
                ]
            )
    else:
        home = Path.home()
        paths.extend(
            [
                home / ".config" / "google-chrome" / "Local State",
                home / ".config" / "chromium" / "Local State",
                home / ".var" / "app" / "com.google.Chrome" / "config" / "google-chrome" / "Local State",
            ]
        )
    return paths


def _windows_doh_servers() -> tuple[list[dict[str, Any]] | None, str | None]:
    ps = (
        "$e=$null; try { "
        "$e = Get-DnsClientDohServerAddress -ErrorAction Stop | "
        "Select-Object ServerAddress, DohTemplate, AutoUpgrade | ConvertTo-Json -Compress "
        "} catch { }; if ($e) { $e } else { '[]' }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as ex:
        return None, str(ex)

    raw = (out.stdout or "").strip()
    if not raw:
        return [], None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None, "powershell json"

    if isinstance(parsed, dict):
        return [parsed], None
    if isinstance(parsed, list):
        return parsed, None
    return None, "unexpected shape"


def _cloudflared_doh_hint() -> bool:
    """True if /etc/cloudflared/config.yml mentions HTTPS DNS upstream."""
    p = Path("/etc/cloudflared/config.yml")
    if not p.is_file():
        return False
    try:
        text = p.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False
    if "https://" not in text:
        return False
    return any(
        k in text
        for k in (
            "dns-query",
            "cloudflare-dns.com",
            "dns.google",
            "application/dns",
            "doh",
        )
    )


def check_doh_usage() -> tuple[int, str]:
    reasons: list[str] = []
    signals: list[int] = []

    if sys.platform == "win32":
        servers, err = _windows_doh_servers()
        if err:
            signals.append(3)
            reasons.append(f"Windows DoH query failed ({err})")
        elif servers is not None and len(servers) > 0:
            signals.append(5)
            addrs = [str(s.get("ServerAddress") or s.get("serverAddress") or "") for s in servers]
            reasons.append(f"Windows encrypted DNS / DoH servers: {', '.join(a for a in addrs if a) or 'configured'}")
        else:
            signals.append(1)
            reasons.append("No DnsClientDohServerAddress entries (or none configured).")

    if sys.platform != "win32" and Path("/etc/cloudflared/config.yml").exists():
        if _cloudflared_doh_hint():
            signals.append(4)
            reasons.append("cloudflared config suggests HTTPS DNS upstream.")
        else:
            signals.append(2)
            reasons.append("cloudflared config present; no clear DoH URL pattern.")

    mode = _firefox_trr_mode()
    if mode is not None:
        if mode in (3,):
            signals.append(5)
            reasons.append(f"Firefox network.trr.mode={mode} (TRR-only / strong DoH).")
        elif mode in (2,):
            signals.append(4)
            reasons.append(f"Firefox network.trr.mode={mode} (prefers TRR / race).")
        elif mode == 5:
            signals.append(2)
            reasons.append("Firefox TRR off by default (mode 5).")
        elif mode == 0:
            signals.append(1)
            reasons.append("Firefox TRR off (mode 0).")
        else:
            signals.append(3)
            reasons.append(f"Firefox network.trr.mode={mode} (unusual).")

    for ls in _chromium_local_state_paths():
        m, block = _chromium_dns_over_https(ls)
        if m is None and block is None:
            continue
        browser = ls.parts[-3] if len(ls.parts) >= 3 else ls.name
        if m == "secure":
            signals.append(5)
            reasons.append(f"{browser} dns_over_https mode=secure.")
        elif m in ("automatic", "auto"):
            signals.append(4)
            reasons.append(f"{browser} dns_over_https mode=automatic.")
        elif m == "off" or m == "disabled":
            signals.append(1)
            reasons.append(f"{browser} explicit secure DNS off.")
        else:
            signals.append(3)
            reasons.append(f"{browser} dns_over_https present: {str(block)[:200]}")

    if not reasons:
        return (
            3,
            "No Firefox/Chromium Local State paths found and no platform DoH probe; inconclusive.",
        )

    if max(signals) >= 5:
        return 5, " | ".join(reasons[:4])
    if max(signals) >= 4:
        return 4, " | ".join(reasons[:4])
    if 3 in signals:
        return 3, " | ".join(reasons[:4])
    if max(signals) == 2:
        return 2, " | ".join(reasons[:4])
    if min(signals) <= 1 and max(signals) <= 1:
        return 1, " | ".join(reasons[:4])

    return 3, " | ".join(reasons[:4])


def main():
    print("=" * 60)
    print("DNS-over-HTTPS (DoH) Detection")
    print("=" * 60)

    score, description = check_doh_usage()

    print("\n" + "-" * 40)
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print("-" * 40)
    print("=" * 60)


if __name__ == "__main__":
    main()
