#!/usr/bin/env python3
"""
Tor exit / relay, open-proxy blocklists, and AbuseIPDB-style egress checks.

Uses the host's public **IPv4** (or **OVERDRIVE_IP** for tests). Sources:

1. **Onionoo** (Tor Project) — running relays whose OR address matches the IP.
   Truncated responses are refetched with a higher limit; if still truncated with no
   match, the “no relay” result is **not** treated as definitive (reduces false 1s).
2. **FireHOL blocklist-ipsets** (cached under ``~/.cache/overdrive``; respect license / ToS).
   - ``firehol_proxies.netset`` — open proxy aggregation
   - ``tor_exits_1d.ipset`` and ``tor_exits_7d.ipset`` — Tor exits (dual window)
3. **AbuseIPDB** v2 ``check`` — optional; set **ABUSEIPDB_API_KEY**.

**Egress IPv4** is taken from multiple HTTPS probes; **two or more must agree** for a
*strong* consensus (single successful probe → weak consensus, never score **1**).

Score (1–5):
  **5** — Strong evidence of Tor **or** open proxy / anonymizer context on this IP.
  **4** — Elevated AbuseIPDB signals without meeting the bar for 5.
  **3** — Inconclusive (no IPv4, probes disagree, Onionoo truncated/empty, critical list failure).
  **2** — No positive Tor/proxy hits on what ran, but verification is partial (weak IP consensus,
       one Tor list missing, lists unavailable with only Onionoo clean, AbuseIPDB failed, etc.).
  **1** — Strong IPv4 consensus; Onionoo **definitively** shows no relay; proxy list loaded and miss;
        **both** Tor exit feeds loaded and miss; AbuseIPDB if configured reports low risk.

Environment:

  ABUSEIPDB_API_KEY — optional AbuseIPDB API key
  OVERDRIVE_IP      — optional IPv4 override for testing (always strong consensus)
"""

from __future__ import annotations

import ipaddress
import os
import time
from pathlib import Path
from typing import Any

import requests

IPIFY = "https://api.ipify.org?format=json"
IPV4_ICANHAZIP = "https://ipv4.icanhazip.com/"
IPV4_IFCONFIGME = "https://ifconfig.me/ip"
ONIONOO_DETAILS = "https://onionoo.torproject.org/details"
FIREHOL_PROXIES = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_proxies.netset"
)
FIREHOL_TOR_EXITS_1D = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits_1d.ipset"
)
FIREHOL_TOR_EXITS_7D = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits_7d.ipset"
)
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"

TIMEOUT = 15
UA = {"User-Agent": "overdrive-tor-proxy-reputation/1.0"}
CACHE_DIR = Path.home() / ".cache" / "overdrive"
REFRESH_IF_OLDER_SEC = 6 * 3600
ONIONOO_LIMITS = ("100", "500")


def _parse_ipv4(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip().split()[0]
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.version != 4:
        return None
    return str(a)


def _probe_ipify() -> str | None:
    try:
        r = requests.get(IPIFY, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        return _parse_ipv4(str(r.json().get("ip")) if r.json().get("ip") else None)
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return None


def _probe_plain_ipv4(url: str) -> str | None:
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        return _parse_ipv4(r.text)
    except (requests.RequestException, ValueError, TypeError):
        return None


def resolve_egress_ipv4() -> tuple[str | None, bool, str]:
    """
    Returns ``(ip, strong_consensus, note)``.
    ``strong_consensus`` is True for ``OVERDRIVE_IP`` or when at least two probes return the same IPv4.
    """
    override = _parse_ipv4(os.environ.get("OVERDRIVE_IP"))
    if override:
        return override, True, ""

    probes: list[tuple[str, str | None]] = [
        ("ipify", _probe_ipify()),
        ("icanhazip", _probe_plain_ipv4(IPV4_ICANHAZIP)),
        ("ifconfig.me", _probe_plain_ipv4(IPV4_IFCONFIGME)),
    ]
    successes = [(name, ip) for name, ip in probes if ip]
    if not successes:
        return None, False, "all IPv4 probes failed"

    by_ip: dict[str, list[str]] = {}
    for name, ip in successes:
        by_ip.setdefault(ip, []).append(name)

    if len(by_ip) > 1:
        parts = [f"{ip} ({', '.join(names)})" for ip, names in sorted(by_ip.items())]
        return None, False, "IPv4 probes disagree: " + "; ".join(parts)

    ip = next(iter(by_ip))
    if len(successes) >= 2:
        return ip, True, ""

    lone = successes[0][0]
    return ip, False, f"only one IPv4 probe succeeded ({lone}); need 2+ agreeing for strong consensus"


def _or_address_host(or_addr: str) -> str:
    """Host part of Onionoo ``or_addresses`` entry (IPv4 ``a.b.c.d:port`` or bracketed IPv6)."""
    s = or_addr.strip()
    if s.startswith("["):
        end = s.find("]")
        if end > 0:
            return s[1:end]
    if s.count(":") == 1:
        return s.rsplit(":", 1)[0]
    if "." in s and s.rsplit(":", 1)[-1].isdigit():
        return s.rsplit(":", 1)[0]
    return s


def _onionoo_truncated(data: dict[str, Any]) -> bool:
    t = data.get("relays_truncated")
    if t is None or t is False:
        return False
    if isinstance(t, (int, float)):
        return t != 0
    if isinstance(t, str):
        return t.strip().lower() not in ("0", "false", "")
    return bool(t)


def onionoo_relays_exact(
    ip: str,
) -> tuple[list[dict[str, Any]] | None, str | None, bool]:
    """
    Returns ``(matches, error, unreliable_empty)``.
    ``unreliable_empty`` is True when there was no exact match but the response indicated
    truncated relay rows (so “no relay” is not definitive).
    """
    unreliable_empty = False
    for lim in ONIONOO_LIMITS:
        try:
            r = requests.get(
                ONIONOO_DETAILS,
                params={"search": ip, "running": "true", "limit": lim},
                headers=UA,
                timeout=TIMEOUT,
            )
            r.raise_for_status()
            data = r.json()
        except (requests.RequestException, ValueError) as e:
            return None, str(e), False

        relays = data.get("relays")
        if not isinstance(relays, list):
            return None, "unexpected Onionoo JSON", False

        truncated = _onionoo_truncated(data)
        matched: list[dict[str, Any]] = []
        for relay in relays:
            if not isinstance(relay, dict):
                continue
            for addr in relay.get("or_addresses") or []:
                if not isinstance(addr, str):
                    continue
                if _or_address_host(addr) == ip:
                    matched.append(relay)
                    break

        if matched:
            return matched, None, False
        if not truncated:
            return [], None, False
        unreliable_empty = True

    return [], None, unreliable_empty


def _load_cached_text(url: str, cache_name: str) -> tuple[str | None, str]:
    """
    Download ``url`` or use cache. Returns (text, note). ``text is None`` if unavailable.
    ``note`` is non-empty for stale-cache fallback or refresh failures.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / cache_name
    now = time.time()
    if path.is_file():
        age = now - path.stat().st_mtime
        if age < REFRESH_IF_OLDER_SEC:
            try:
                return path.read_text(encoding="utf-8", errors="replace"), ""
            except OSError as e:
                return None, str(e)

    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        text = r.text
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
        return text, ""
    except (requests.RequestException, OSError, ValueError) as e:
        if path.is_file():
            try:
                return (
                    path.read_text(encoding="utf-8", errors="replace"),
                    f"using stale cache ({e})",
                )
            except OSError as e2:
                return None, f"{e}; stale read failed: {e2}"
        return None, str(e)


def netset_contains(ip: str, body: str) -> bool:
    """Return True if ``ip`` matches a line in a netset/ipset (IPv4 CIDR or single address)."""
    addr = ipaddress.ip_address(ip)
    for line in body.splitlines():
        raw = line.split("#", 1)[0].strip()
        if not raw:
            continue
        try:
            if "/" in raw:
                if addr in ipaddress.ip_network(raw, strict=False):
                    return True
            elif addr == ipaddress.ip_address(raw):
                return True
        except ValueError:
            continue
    return False


def _usage_proxy_vpn(usage_type: str) -> bool:
    u = usage_type.lower()
    return "proxy" in u or "vpn" in u or "anonymizing" in u


def _usage_hosting(usage_type: str) -> bool:
    u = usage_type.lower()
    return "hosting" in u or "data center" in u or "datacenter" in u


def abuseipdb_check(ip: str, api_key: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        r = requests.get(
            ABUSEIPDB_CHECK,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=TIMEOUT,
        )
        if r.status_code == 401:
            return None, "401 Unauthorized (check ABUSEIPDB_API_KEY)"
        if r.status_code == 429:
            return None, "429 Too Many Requests"
        r.raise_for_status()
        payload = r.json()
        data = payload.get("data")
        if not isinstance(data, dict):
            return None, "unexpected AbuseIPDB JSON"
        return data, None
    except (requests.RequestException, ValueError) as e:
        return None, str(e)


def check_tor_proxy_reputation() -> tuple[int, str]:
    ip, ip_strong, ip_note = resolve_egress_ipv4()
    if not ip:
        return 3, f"Could not determine public IPv4. {ip_note}"

    notes: list[str] = []
    if ip_note:
        notes.append(ip_note)

    def _clean_tail_msg(base: str) -> str:
        if notes:
            return base + " Notes: " + "; ".join(notes)
        return base

    positives: list[str] = []

    matched, onionoo_err, onionoo_unreliable_empty = onionoo_relays_exact(ip)
    onionoo_ok = matched is not None
    if onionoo_err:
        notes.append(f"Onionoo error: {onionoo_err}")
    elif matched:
        flags = matched[0].get("flags") or []
        nick = matched[0].get("nickname", "?")
        exit_part = "Exit" if isinstance(flags, list) and "Exit" in flags else "non-Exit relay"
        positives.append(f"Tor relay at this IP (Onionoo {nick!r}, {exit_part})")
    elif onionoo_unreliable_empty:
        notes.append(
            "Onionoo relay list truncated with no match — cannot rule out Tor relay at this IP"
        )

    proxy_body, proxy_note = _load_cached_text(FIREHOL_PROXIES, "firehol_proxies.netset")
    tor_1d_body, tor_1d_note = _load_cached_text(FIREHOL_TOR_EXITS_1D, "tor_exits_1d.ipset")
    tor_7d_body, tor_7d_note = _load_cached_text(FIREHOL_TOR_EXITS_7D, "tor_exits_7d.ipset")
    if proxy_note:
        notes.append(f"FireHOL proxies: {proxy_note}")
    if tor_1d_note:
        notes.append(f"FireHOL tor_exits_1d: {tor_1d_note}")
    if tor_7d_note:
        notes.append(f"FireHOL tor_exits_7d: {tor_7d_note}")

    in_proxy = False
    if proxy_body is not None:
        in_proxy = netset_contains(ip, proxy_body)
        if in_proxy:
            positives.append("Listed on FireHOL open-proxy netset")

    in_tor_1d = bool(tor_1d_body is not None and netset_contains(ip, tor_1d_body))
    in_tor_7d = bool(tor_7d_body is not None and netset_contains(ip, tor_7d_body))
    if in_tor_1d:
        positives.append("Listed on FireHOL tor_exits_1d ipset")
    if in_tor_7d:
        positives.append("Listed on FireHOL tor_exits_7d ipset")

    abuse_key = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()
    abuse_data: dict[str, Any] | None = None
    abuse_err: str | None = None
    if abuse_key:
        abuse_data, abuse_err = abuseipdb_check(ip, abuse_key)
        if abuse_err:
            notes.append(f"AbuseIPDB: {abuse_err}")
        elif abuse_data:
            if abuse_data.get("isTor") is True:
                positives.append("AbuseIPDB isTor=true")
            ut = str(abuse_data.get("usageType") or "")
            conf = int(abuse_data.get("abuseConfidenceScore") or 0)
            if _usage_proxy_vpn(ut):
                positives.append(f"AbuseIPDB usageType={ut!r} ({conf}%)")
            elif conf >= 85 and _usage_hosting(ut):
                positives.append(f"AbuseIPDB very high confidence {conf}% with hosting/datacenter usage")

    if positives:
        return 5, "; ".join(positives)

    if abuse_key and abuse_data is not None and abuse_err is None:
        conf = int(abuse_data.get("abuseConfidenceScore") or 0)
        ut = str(abuse_data.get("usageType") or "")
        if conf >= 40 or _usage_hosting(ut):
            return (
                4,
                _clean_tail_msg(
                    f"Elevated AbuseIPDB signals (confidence {conf}%, usageType={ut!r}) — not classified as Tor/proxy."
                ),
            )

    proxy_list_ok = proxy_body is not None and not in_proxy
    onionoo_definitive_clean = (
        onionoo_ok and not matched and not onionoo_unreliable_empty
    )
    tor_both_loaded = tor_1d_body is not None and tor_7d_body is not None
    tor_either_loaded = tor_1d_body is not None or tor_7d_body is not None

    if onionoo_unreliable_empty:
        detail = "; ".join(notes) if notes else "Onionoo truncated"
        return 3, f"Inconclusive: {detail}"

    if onionoo_definitive_clean and proxy_list_ok:
        if abuse_key:
            if abuse_err or abuse_data is None:
                return (
                    2,
                    _clean_tail_msg(
                        "No Tor/proxy hits on completed checks; AbuseIPDB query failed — likely clean, not fully verified."
                    ),
                )
            conf = int(abuse_data.get("abuseConfidenceScore") or 0)
            if conf < 30 and not abuse_data.get("isTor") and not _usage_proxy_vpn(
                str(abuse_data.get("usageType") or "")
            ):
                if not ip_strong:
                    return (
                        2,
                        _clean_tail_msg(
                            "Lists and Onionoo look clean and AbuseIPDB low risk, but IPv4 consensus is weak — not scoring as definitive clean."
                        ),
                    )
                if not tor_both_loaded:
                    return (
                        2,
                        _clean_tail_msg(
                            "Lists/Onionoo/AbuseIPDB look clean, but both Tor exit feeds were not loaded — not scoring as definitive clean."
                        ),
                    )
                extra = f" AbuseIPDB: {conf}% confidence."
                return 1, _clean_tail_msg(
                    "Strong IPv4 consensus; no Tor relay on Onionoo; not on FireHOL proxy or Tor-exit lists;"
                    f" AbuseIPDB reports low risk.{extra}"
                )
            return (
                4,
                _clean_tail_msg(
                    f"AbuseIPDB still shows notable risk (confidence {conf}%) — review usageType."
                ),
            )

        if not ip_strong:
            return (
                2,
                _clean_tail_msg(
                    "Onionoo and FireHOL proxy list show no Tor/proxy signals, but IPv4 consensus is weak — not scoring as definitive clean."
                ),
            )
        if not tor_both_loaded:
            if tor_either_loaded and not in_tor_1d and not in_tor_7d:
                return (
                    2,
                    _clean_tail_msg(
                        "Onionoo and loaded Tor exit list(s) show no match; second Tor exit feed missing — not scoring as definitive clean (AbuseIPDB not configured)."
                    ),
                )
            return (
                2,
                _clean_tail_msg(
                    "Onionoo clean but Tor exit feeds unavailable or incomplete — not scoring as definitive clean (AbuseIPDB not configured)."
                ),
            )

        return 2, _clean_tail_msg(
            "Strong IPv4 consensus; Onionoo and dual Tor-exit lists show no match; not on proxy list; "
            "AbuseIPDB not configured — likely clean, not fully verified."
        )

    detail = "; ".join(notes) if notes else "incomplete remote data"
    if not onionoo_ok and proxy_body is None:
        return 3, f"Inconclusive: {detail}"
    if not onionoo_ok:
        return 3, f"Onionoo unavailable; cannot confirm Tor relay status. {detail}"
    if proxy_body is None:
        return 3, f"Could not load FireHOL proxy list; cannot rule out open proxies. {detail}"

    return 3, f"Inconclusive: {detail}"


def main() -> None:
    print("=" * 60)
    print("Tor / Proxy / Abuse IP Reputation")
    print("=" * 60)
    print()
    score, description = check_tor_proxy_reputation()
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
