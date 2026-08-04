#!/usr/bin/env python3
"""
Tor exit / relay, open-proxy blocklists, and AbuseIPDB-style egress checks.

Uses the host's public **IPv4** (or **OVERDRIVE_IP** for tests). Sources:

1. **Onionoo** (Tor Project) - running relays whose OR address matches the IP.
   Truncated responses are refetched with a higher limit; if still truncated with no
   match, the "no relay" result is **not** treated as definitive (reduces false 1s).
2. **FireHOL blocklist-ipsets** (cached under ``~/.cache/overdrive``; respect license / ToS).
   - ``firehol_proxies.netset`` - open proxy aggregation
   - ``firehol_anonymous.netset`` - anonymizer / VPN / proxy aggregation
   - ``tor_exits_1d.ipset`` and ``tor_exits_7d.ipset`` - Tor exits (dual window)
3. **Tor Project bulk exit list** - official current exit-address feed.
4. **ip-api** lightweight proxy/hosting/mobile flags.
5. **AbuseIPDB** v2 ``check`` - optional; set **ABUSEIPDB_API_KEY**.

**Egress IPv4** is taken from multiple HTTPS probes; **two or more must agree** for a
*strong* consensus (single successful probe -> weak consensus, never score **1**).

Score (1-5):
  **5** - Strong evidence of Tor **or** open proxy / anonymizer context on this IP.
  **4** - Elevated AbuseIPDB signals without meeting the bar for 5.
  **3** - Inconclusive (no IPv4, probes disagree, Onionoo truncated/empty, critical list failure).
  **2** - No positive Tor/proxy hits on what ran, but verification is partial (weak IP consensus,
       one Tor list missing, lists unavailable with only Onionoo clean, AbuseIPDB failed, etc.).
  **1** - Strong IPv4 consensus; Onionoo **definitively** shows no relay; proxy list loaded and miss;
        **both** Tor exit feeds loaded and miss; AbuseIPDB if configured reports low risk.

Environment:

  ABUSEIPDB_API_KEY - optional AbuseIPDB API key
  OVERDRIVE_IP      - optional IPv4 override for testing (always strong consensus)
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import requests

from detections.common.common_config import (
    ABUSEIPDB_CHECK_URL,
    IP_API_URL_WITH_FIELDS,
    FIREHOL_PROXIES_URL,
    FIREHOL_TOR_EXITS_1D_URL,
    FIREHOL_TOR_EXITS_7D_URL,
    ONIONOO_DETAILS_URL,
    OVERDRIVE_CACHE_DIR,
    TOR_PROXY_TIMEOUT,
    USER_AGENTS,
)
from detections.common.common_network import (
    ipv4_listed_in_netset,
    resolve_egress_ipv4 as resolve_egress_ipv4_common,
)

ONIONOO_DETAILS = ONIONOO_DETAILS_URL
FIREHOL_PROXIES = FIREHOL_PROXIES_URL
FIREHOL_TOR_EXITS_1D = FIREHOL_TOR_EXITS_1D_URL
FIREHOL_TOR_EXITS_7D = FIREHOL_TOR_EXITS_7D_URL
ABUSEIPDB_CHECK = ABUSEIPDB_CHECK_URL
TOR_BULK_EXIT_LIST = "https://check.torproject.org/torbulkexitlist"
FIREHOL_ANONYMOUS = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset"

TIMEOUT = TOR_PROXY_TIMEOUT
UA = {"User-Agent": USER_AGENTS["tor_proxy"]}
CACHE_DIR = OVERDRIVE_CACHE_DIR
REFRESH_IF_OLDER_SEC = 6 * 3600
ONIONOO_LIMITS = ("100", "500")


@dataclass
class ReputationEvidence:
    source: str
    severity: int
    status: str
    detail: str


def _short(text: str, width: int = 180) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def resolve_egress_ipv4() -> tuple[str | None, bool, str]:
    """Compatibility wrapper for existing call sites/tests in this module."""
    return resolve_egress_ipv4_common(
        user_agent=UA["User-Agent"],
        timeout=TIMEOUT,
        override_env="OVERDRIVE_IP",
    )


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
    truncated relay rows (so "no relay" is not definitive).
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
            if relay in matched:
                continue
            for addr in relay.get("exit_addresses") or []:
                if isinstance(addr, str) and addr == ip:
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


def _ipv4_in_plain_list(ip: str, body: str) -> bool:
    for line in body.splitlines():
        raw = line.split("#", 1)[0].strip()
        if raw == ip:
            return True
    return False


def ip_api_reputation(ip: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        r = requests.get(
            IP_API_URL_WITH_FIELDS.format(ip=ip),
            headers=UA,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            return None, "unexpected ip-api JSON"
        if data.get("status") == "fail":
            return None, str(data.get("message") or "ip-api failed")
        return data, None
    except (requests.RequestException, ValueError) as e:
        return None, str(e)


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


def collect_reputation_evidence(ip: str, ip_strong: bool, ip_note: str) -> list[ReputationEvidence]:
    evidence: list[ReputationEvidence] = []
    if ip_note:
        evidence.append(ReputationEvidence("egress-ip", 2 if ip_strong else 3, "weak-consensus", ip_note))
    else:
        evidence.append(ReputationEvidence("egress-ip", 1, "strong-consensus", f"public IPv4={ip}"))

    matched, onionoo_err, onionoo_unreliable_empty = onionoo_relays_exact(ip)
    if onionoo_err:
        evidence.append(ReputationEvidence("Onionoo", 3, "error", onionoo_err))
    elif matched:
        relay = matched[0]
        flags = relay.get("flags") or []
        nick = relay.get("nickname", "?")
        is_exit = isinstance(flags, list) and "Exit" in flags
        sev = 5 if is_exit else 4
        status = "tor-exit-relay" if is_exit else "tor-non-exit-relay"
        evidence.append(
            ReputationEvidence(
                "Onionoo",
                sev,
                status,
                f"matched running relay {nick!r}; flags={','.join(flags) if isinstance(flags, list) else flags}",
            )
        )
    elif onionoo_unreliable_empty:
        evidence.append(ReputationEvidence("Onionoo", 3, "truncated", "relay result truncated; no exact match but clean result is not definitive"))
    else:
        evidence.append(ReputationEvidence("Onionoo", 1, "clean", "no exact running relay or exit-address match"))

    lists = [
        ("FireHOL proxies", FIREHOL_PROXIES, "firehol_proxies.netset", "open-proxy", True),
        ("FireHOL anonymous", FIREHOL_ANONYMOUS, "firehol_anonymous.netset", "anonymous-proxy/vpn", True),
        ("FireHOL tor 1d", FIREHOL_TOR_EXITS_1D, "tor_exits_1d.ipset", "tor-exit-1d", True),
        ("FireHOL tor 7d", FIREHOL_TOR_EXITS_7D, "tor_exits_7d.ipset", "tor-exit-7d", True),
    ]
    for label, url, cache_name, hit_status, is_netset in lists:
        body, note = _load_cached_text(url, cache_name)
        if body is None:
            evidence.append(ReputationEvidence(label, 3, "unavailable", note or "list unavailable"))
            continue
        listed = ipv4_listed_in_netset(ip, body) if is_netset else _ipv4_in_plain_list(ip, body)
        if listed:
            sev = 5 if "tor" in hit_status or "proxy" in hit_status else 4
            detail = f"IP listed in {cache_name}"
            if note:
                detail += f" ({note})"
            evidence.append(ReputationEvidence(label, sev, hit_status, detail))
        else:
            detail = f"not listed in {cache_name}"
            if note:
                detail += f" ({note})"
            evidence.append(ReputationEvidence(label, 1, "clean", detail))

    bulk_body, bulk_note = _load_cached_text(TOR_BULK_EXIT_LIST, "tor_bulk_exit_list.txt")
    if bulk_body is None:
        evidence.append(ReputationEvidence("Tor bulk exit list", 3, "unavailable", bulk_note or "list unavailable"))
    elif _ipv4_in_plain_list(ip, bulk_body):
        evidence.append(ReputationEvidence("Tor bulk exit list", 5, "tor-exit", "IP listed in Tor Project bulk exit list"))
    else:
        detail = "not listed in Tor Project bulk exit list"
        if bulk_note:
            detail += f" ({bulk_note})"
        evidence.append(ReputationEvidence("Tor bulk exit list", 1, "clean", detail))

    ipapi, ipapi_err = ip_api_reputation(ip)
    if ipapi_err:
        evidence.append(ReputationEvidence("ip-api", 3, "error", ipapi_err))
    elif ipapi:
        flags = []
        if ipapi.get("proxy") is True:
            flags.append("proxy=true")
        if ipapi.get("hosting") is True:
            flags.append("hosting=true")
        if ipapi.get("mobile") is True:
            flags.append("mobile=true")
        org = ipapi.get("org") or ipapi.get("isp") or ipapi.get("as") or "unknown org"
        if ipapi.get("proxy") is True:
            evidence.append(ReputationEvidence("ip-api", 4, "proxy-flag", f"{', '.join(flags)}; org={org}"))
        elif ipapi.get("hosting") is True:
            evidence.append(ReputationEvidence("ip-api", 2, "hosting", f"{', '.join(flags)}; org={org}"))
        else:
            evidence.append(ReputationEvidence("ip-api", 1, "clean", f"no proxy/hosting flag; org={org}"))

    abuse_key = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()
    if abuse_key:
        abuse_data, abuse_err = abuseipdb_check(ip, abuse_key)
        if abuse_err:
            evidence.append(ReputationEvidence("AbuseIPDB", 3, "error", abuse_err))
        elif abuse_data:
            conf = int(abuse_data.get("abuseConfidenceScore") or 0)
            usage = str(abuse_data.get("usageType") or "")
            if abuse_data.get("isTor") is True:
                evidence.append(ReputationEvidence("AbuseIPDB", 5, "tor", f"isTor=true; confidence={conf}%; usageType={usage!r}"))
            elif _usage_proxy_vpn(usage):
                evidence.append(ReputationEvidence("AbuseIPDB", 5, "proxy-vpn-usage", f"confidence={conf}%; usageType={usage!r}"))
            elif conf >= 85 and _usage_hosting(usage):
                evidence.append(ReputationEvidence("AbuseIPDB", 4, "high-risk-hosting", f"confidence={conf}%; usageType={usage!r}"))
            elif conf >= 40:
                evidence.append(ReputationEvidence("AbuseIPDB", 4, "elevated-risk", f"confidence={conf}%; usageType={usage!r}"))
            else:
                evidence.append(ReputationEvidence("AbuseIPDB", 1, "low-risk", f"confidence={conf}%; usageType={usage!r}"))
    else:
        evidence.append(ReputationEvidence("AbuseIPDB", 2, "not-configured", "ABUSEIPDB_API_KEY not set; skipping optional reputation check"))

    return evidence


def score_reputation_evidence(evidence: list[ReputationEvidence]) -> tuple[int, str]:
    hits5 = [e for e in evidence if e.severity >= 5]
    hits4 = [e for e in evidence if e.severity == 4]
    errors = [e for e in evidence if e.severity == 3]
    partial = [e for e in evidence if e.severity == 2]
    clean_sources = [e for e in evidence if e.severity == 1 and e.status in {"clean", "low-risk", "strong-consensus"}]

    if hits5:
        return 5, "; ".join(f"{e.source}: {e.status} ({_short(e.detail, 120)})" for e in hits5[:4])
    if hits4:
        return 4, "; ".join(f"{e.source}: {e.status} ({_short(e.detail, 120)})" for e in hits4[:4])

    critical_clean = {
        "Onionoo",
        "FireHOL proxies",
        "FireHOL anonymous",
        "FireHOL tor 1d",
        "FireHOL tor 7d",
        "Tor bulk exit list",
    }
    clean_names = {e.source for e in clean_sources}
    strong_ip = any(e.source == "egress-ip" and e.status == "strong-consensus" for e in evidence)

    hard_errors = [
        e for e in errors
        if e.source in critical_clean or e.source in {"egress-ip", "ip-api"}
    ]
    if hard_errors and not (critical_clean <= clean_names):
        return 3, "Inconclusive reputation data: " + "; ".join(f"{e.source}: {_short(e.detail, 110)}" for e in hard_errors[:4])

    if strong_ip and critical_clean <= clean_names:
        if any(e.source == "AbuseIPDB" and e.status == "low-risk" for e in clean_sources):
            return 1, "Strong clean result: consensus IPv4, Onionoo clean, Tor/proxy lists clean, AbuseIPDB low risk."
        return 2, "Likely clean: consensus IPv4 and Tor/proxy lists clean; optional AbuseIPDB not configured or incomplete."

    if clean_names & critical_clean:
        reasons = "; ".join(f"{e.source}: {e.status}" for e in (partial + errors)[:4])
        return 2, f"No positive Tor/proxy hits, but verification is partial. {reasons}".strip()

    return 3, "Inconclusive: no positive hits, but too few reputation sources completed."


def print_reputation_evidence(ip: str, evidence: list[ReputationEvidence]) -> None:
    print(f"Public IPv4: {ip}")
    print()
    print(f"{'SEV':<3} {'SOURCE':<22} {'STATUS':<22} DETAIL")
    print("-" * 95)
    for item in sorted(evidence, key=lambda e: (-e.severity, e.source, e.status)):
        print(f"{item.severity:<3} {_short(item.source, 22):<22} {_short(item.status, 22):<22} {_short(item.detail, 220)}")


def check_tor_proxy_reputation() -> tuple[int, str]:
    ip, ip_strong, ip_note = resolve_egress_ipv4()
    if not ip:
        return 3, f"Could not determine public IPv4. {ip_note}"
    evidence = collect_reputation_evidence(ip, ip_strong, ip_note)
    return score_reputation_evidence(evidence)


def main() -> None:
    print("=" * 60)
    print("Tor / Proxy / Abuse IP Reputation")
    print("=" * 60)
    print()
    ip, ip_strong, ip_note = resolve_egress_ipv4()
    if not ip:
        score, description = 3, f"Could not determine public IPv4. {ip_note}"
    else:
        evidence = collect_reputation_evidence(ip, ip_strong, ip_note)
        print_reputation_evidence(ip, evidence)
        print()
        score, description = score_reputation_evidence(evidence)
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
