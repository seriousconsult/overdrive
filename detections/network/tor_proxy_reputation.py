#!/usr/bin/env python3
"""
Tor exit / relay, open-proxy blocklists, and AbuseIPDB-style egress checks.

Uses the host's public **IPv4** (or **OVERDRIVE_IP** for tests). Sources:

1. **Onionoo** (Tor Project) - running relays whose OR/exit address matches the IP.
   Truncated responses are refetched with a higher limit; if still truncated with no
   match, the "no relay" result is **not** treated as definitive (reduces false 1s).
2. **check.torproject.org/api/ip** - authoritative IsTor for the current egress when the
   API-reported IP matches our consensus address.
3. **FireHOL blocklist-ipsets** (cached under ``~/.cache/overdrive``; respect license / ToS).
   - ``firehol_proxies.netset`` - open proxy aggregation
   - ``firehol_anonymous.netset`` - anonymizer / VPN / proxy aggregation
   - ``tor_exits_1d.ipset`` and ``tor_exits_7d.ipset`` - Tor exits (dual window)
4. **Tor Project bulk exit list** - official current exit-address feed.
5. **ip-api** lightweight proxy/hosting/mobile flags.
6. **AbuseIPDB** v2 ``check`` - optional; set **ABUSEIPDB_API_KEY**.

**Egress IPv4** is taken from multiple HTTPS probes; **two or more must agree** for a
*strong* consensus (single successful probe -> weak consensus, never score **1**).

Score (1-5):
  **5** - Strong evidence of Tor **or** open proxy / anonymizer context on this IP
        (Tor Project sources preferred; FireHOL Tor hits need corroboration).
  **4** - Elevated AbuseIPDB / proxy flags / uncorroborated FireHOL Tor signals.
  **3** - Inconclusive (no IPv4, probes disagree, Onionoo truncated/empty, critical list failure).
  **2** - No positive Tor/proxy hits on what ran, but verification is partial (weak IP consensus,
        stale lists, one Tor list missing, etc.).
  **1** - Strong IPv4 consensus; Onionoo definitive miss; Tor check (when IP matches) not Tor;
        proxy + both Tor exit feeds + bulk list loaded and miss. AbuseIPDB is optional.

Environment:

  ABUSEIPDB_API_KEY - optional AbuseIPDB API key
  OVERDRIVE_IP      - optional IPv4 override for testing (always strong consensus)
  OVERDRIVE_TOR_PROXY_NO_CACHE=1 - skip short result cache
  OVERDRIVE_TOR_PROXY_CACHE_TTL - result cache seconds (default 120)
"""

from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    from requests.packages.urllib3.util.retry import Retry  # type: ignore[no-redef]

from detections.common.common_config import (
    ABUSEIPDB_CHECK_URL,
    FIREHOL_PROXIES_URL,
    FIREHOL_TOR_EXITS_1D_URL,
    FIREHOL_TOR_EXITS_7D_URL,
    IP_API_URL_WITH_FIELDS,
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
TOR_CHECK_API = "https://check.torproject.org/api/ip"
FIREHOL_ANONYMOUS = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_anonymous.netset"
)

TIMEOUT = TOR_PROXY_TIMEOUT
UA = {"User-Agent": USER_AGENTS["tor_proxy"]}
CACHE_DIR = OVERDRIVE_CACHE_DIR
REFRESH_IF_OLDER_SEC = 6 * 3600
STALE_MAX_AGE_SEC = 7 * 24 * 3600
ONIONOO_LIMITS = ("100", "500", "2500")
MIN_LIST_LINES = 20
_RESULT_CACHE_NAME = "tor_proxy_reputation.json"
_DEFAULT_RESULT_CACHE_TTL_S = 120

_SESSION: requests.Session | None = None


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


def _build_retry() -> Retry:
    kwargs: dict[str, Any] = {
        "total": 3,
        "connect": 3,
        "read": 3,
        "backoff_factor": 0.4,
        "status_forcelist": (429, 500, 502, 503, 504),
        "raise_on_status": False,
    }
    try:
        return Retry(**kwargs, allowed_methods=frozenset({"GET", "HEAD"}))
    except TypeError:  # pragma: no cover - older urllib3
        return Retry(**kwargs, method_whitelist=frozenset({"GET", "HEAD"}))


def _session() -> requests.Session:
    global _SESSION
    if _SESSION is not None:
        return _SESSION
    session = requests.Session()
    session.headers.update(UA)
    adapter = HTTPAdapter(max_retries=_build_retry())
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    _SESSION = session
    return session


def resolve_egress_ipv4() -> tuple[str | None, bool, str]:
    """Compatibility wrapper for existing call sites/tests in this module."""
    return resolve_egress_ipv4_common(
        user_agent=UA["User-Agent"],
        timeout=TIMEOUT,
        override_env="OVERDRIVE_IP",
        session=_session(),
    )


def _result_cache_ttl_s() -> int:
    raw = (os.environ.get("OVERDRIVE_TOR_PROXY_CACHE_TTL") or "").strip()
    if raw.isdigit():
        return max(0, int(raw))
    return _DEFAULT_RESULT_CACHE_TTL_S


def _result_cache_disabled() -> bool:
    return (os.environ.get("OVERDRIVE_TOR_PROXY_NO_CACHE") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _read_result_cache(ip: str) -> tuple[int, str, list[dict[str, Any]]] | None:
    if _result_cache_disabled() or _result_cache_ttl_s() <= 0:
        return None
    path = CACHE_DIR / _RESULT_CACHE_NAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("ip") != ip:
        return None
    try:
        ts = float(data["ts"])
        score = int(data["score"])
        description = str(data["description"])
    except (KeyError, TypeError, ValueError):
        return None
    if time.time() - ts > _result_cache_ttl_s():
        return None
    rows = data.get("evidence")
    if not isinstance(rows, list):
        rows = []
    return score, description, rows


def _write_result_cache(
    ip: str,
    score: int,
    description: str,
    evidence: list[ReputationEvidence],
) -> None:
    if _result_cache_disabled() or _result_cache_ttl_s() <= 0:
        return
    path = CACHE_DIR / _RESULT_CACHE_NAME
    payload = {
        "ip": ip,
        "ts": time.time(),
        "score": score,
        "description": description,
        "evidence": [
            {
                "source": e.source,
                "severity": e.severity,
                "status": e.status,
                "detail": e.detail,
            }
            for e in evidence
        ],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


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


def _relay_matches_ip(relay: dict[str, Any], ip: str) -> bool:
    for addr in relay.get("or_addresses") or []:
        if isinstance(addr, str) and _or_address_host(addr) == ip:
            return True
    for addr in relay.get("exit_addresses") or []:
        if isinstance(addr, str) and addr.strip() == ip:
            return True
    return False


def onionoo_relays_exact(
    ip: str,
) -> tuple[list[dict[str, Any]] | None, str | None, bool]:
    """
    Returns ``(matches, error, unreliable_empty)``.
    ``unreliable_empty`` is True when there was no exact match but the response indicated
    truncated relay rows (so "no relay" is not definitive).
    """
    unreliable_empty = False
    last_err: str | None = None
    got_response = False

    for lim in ONIONOO_LIMITS:
        data: dict[str, Any] | None = None
        for attempt in range(3):
            try:
                r = _session().get(
                    ONIONOO_DETAILS,
                    params={"search": ip, "running": "true", "limit": lim},
                    timeout=TIMEOUT,
                )
                if r.status_code in (429, 500, 502, 503, 504):
                    last_err = f"HTTP {r.status_code}"
                    time.sleep(0.35 * (attempt + 1))
                    continue
                r.raise_for_status()
                parsed = r.json()
                if not isinstance(parsed, dict):
                    last_err = "unexpected Onionoo JSON"
                    continue
                data = parsed
                got_response = True
                break
            except (requests.RequestException, ValueError) as e:
                last_err = str(e)
                time.sleep(0.35 * (attempt + 1))

        if data is None:
            continue

        relays = data.get("relays")
        if not isinstance(relays, list):
            return None, "unexpected Onionoo JSON", False

        truncated = _onionoo_truncated(data)
        matched = [
            relay for relay in relays if isinstance(relay, dict) and _relay_matches_ip(relay, ip)
        ]

        if matched:
            return matched, None, False
        if not truncated:
            return [], None, False
        unreliable_empty = True

    if not got_response:
        return None, last_err or "Onionoo request failed", False
    return [], None, unreliable_empty


def _looks_like_ip_list(body: str) -> str | None:
    """Return an error string if body does not look like a usable IP/netset list."""
    if not body or not body.strip():
        return "empty list body"
    lower = body.lstrip()[:200].lower()
    if lower.startswith("<!doctype") or lower.startswith("<html") or "<html" in lower:
        return "list body looks like HTML, not an IP set"
    lines = 0
    usable = 0
    for line in body.splitlines():
        raw = line.split("#", 1)[0].strip()
        if not raw:
            continue
        lines += 1
        if raw.replace(".", "").replace("/", "").replace(":", "").replace("-", "").isalnum():
            usable += 1
        if lines >= MIN_LIST_LINES and usable >= max(5, MIN_LIST_LINES // 4):
            return None
    if usable < 5:
        return f"list too small/unusable ({usable} address-like lines)"
    return None


def _load_cached_text(url: str, cache_name: str) -> tuple[str | None, str, bool]:
    """
    Download ``url`` or use cache.

    Returns ``(text, note, stale)``. ``text is None`` if unavailable.
    ``stale`` is True when serving a cache older than the refresh window.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = CACHE_DIR / cache_name
    now = time.time()
    if path.is_file():
        age = now - path.stat().st_mtime
        if age < REFRESH_IF_OLDER_SEC:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                return None, str(e), False
            bad = _looks_like_ip_list(text)
            if bad:
                # Force refresh of corrupt cache.
                pass
            else:
                return text, "", False

    try:
        r = _session().get(url, timeout=TIMEOUT)
        r.raise_for_status()
        text = r.text
        bad = _looks_like_ip_list(text)
        if bad:
            raise ValueError(bad)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
        return text, "", False
    except (requests.RequestException, OSError, ValueError) as e:
        if path.is_file():
            age = now - path.stat().st_mtime
            if age > STALE_MAX_AGE_SEC:
                return None, f"cache too old ({age / 3600:.0f}h) and refresh failed: {e}", True
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as e2:
                return None, f"{e}; stale read failed: {e2}", True
            bad = _looks_like_ip_list(text)
            if bad:
                return None, f"{e}; cached body invalid ({bad})", True
            return text, f"using stale cache ({e})", True
        return None, str(e), False


def _ipv4_in_plain_list(ip: str, body: str) -> bool:
    for line in body.splitlines():
        raw = line.split("#", 1)[0].strip()
        if raw == ip:
            return True
    return False


def tor_check_api(ip: str) -> tuple[bool | None, str | None, str | None]:
    """
    Query check.torproject.org IsTor for the *requesting* egress.

    Returns ``(is_tor, detail_or_error, matched_ip)``.
    ``is_tor`` is None when the check cannot be attributed to ``ip``.
    """
    last_err: str | None = None
    for attempt in range(3):
        try:
            r = _session().get(TOR_CHECK_API, timeout=TIMEOUT)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict):
                return None, "unexpected Tor check JSON", None
            seen = str(data.get("IP") or "").strip()
            is_tor = data.get("IsTor")
            if seen != ip:
                return (
                    None,
                    f"Tor check IP {seen or '?'} != consensus {ip}; not attributing IsTor",
                    seen or None,
                )
            if not isinstance(is_tor, bool):
                return None, "Tor check missing boolean IsTor", seen
            return is_tor, f"check.torproject.org IsTor={is_tor} for {seen}", seen
        except (requests.RequestException, ValueError) as e:
            last_err = str(e)
            time.sleep(0.3 * (attempt + 1))
    return None, last_err or "Tor check failed", None


def ip_api_reputation(ip: str) -> tuple[dict[str, Any] | None, str | None]:
    last_err: str | None = None
    for attempt in range(3):
        try:
            r = _session().get(
                IP_API_URL_WITH_FIELDS.format(ip=ip),
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
            last_err = str(e)
            time.sleep(0.3 * (attempt + 1))
    return None, last_err or "ip-api failed"


def _usage_proxy_vpn(usage_type: str) -> bool:
    u = usage_type.lower()
    return "proxy" in u or "vpn" in u or "anonymizing" in u


def _usage_hosting(usage_type: str) -> bool:
    u = usage_type.lower()
    return "hosting" in u or "data center" in u or "datacenter" in u


def abuseipdb_check(ip: str, api_key: str) -> tuple[dict[str, Any] | None, str | None]:
    last_err: str | None = None
    for attempt in range(3):
        try:
            r = _session().get(
                ABUSEIPDB_CHECK,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=TIMEOUT,
            )
            if r.status_code == 401:
                return None, "401 Unauthorized (check ABUSEIPDB_API_KEY)"
            if r.status_code == 429:
                last_err = "429 Too Many Requests"
                time.sleep(0.6 * (attempt + 1))
                continue
            r.raise_for_status()
            payload = r.json()
            data = payload.get("data")
            if not isinstance(data, dict):
                return None, "unexpected AbuseIPDB JSON"
            return data, None
        except (requests.RequestException, ValueError) as e:
            last_err = str(e)
            time.sleep(0.3 * (attempt + 1))
    return None, last_err or "AbuseIPDB failed"


def _list_evidence(
    label: str,
    url: str,
    cache_name: str,
    hit_status: str,
    ip: str,
    *,
    is_netset: bool,
) -> ReputationEvidence:
    body, note, stale = _load_cached_text(url, cache_name)
    if body is None:
        return ReputationEvidence(label, 3, "unavailable", note or "list unavailable")
    listed = ipv4_listed_in_netset(ip, body) if is_netset else _ipv4_in_plain_list(ip, body)
    if listed:
        if "tor" in hit_status:
            sev = 5
        elif "proxy" in hit_status or "anonymous" in hit_status:
            sev = 5
        else:
            sev = 4
        detail = f"IP listed in {cache_name}"
        if note:
            detail += f" ({note})"
        # FireHOL Tor hits from stale cache are weaker until corroborated.
        if stale and "tor" in hit_status:
            return ReputationEvidence(label, 4, f"{hit_status}-stale", detail)
        return ReputationEvidence(label, sev, hit_status, detail)

    detail = f"not listed in {cache_name}"
    if note:
        detail += f" ({note})"
    if stale:
        return ReputationEvidence(label, 2, "clean-stale", detail)
    return ReputationEvidence(label, 1, "clean", detail)


def collect_reputation_evidence(ip: str, ip_strong: bool, ip_note: str) -> list[ReputationEvidence]:
    evidence: list[ReputationEvidence] = []
    if ip_note:
        evidence.append(
            ReputationEvidence("egress-ip", 2 if ip_strong else 3, "weak-consensus", ip_note)
        )
    else:
        evidence.append(
            ReputationEvidence("egress-ip", 1, "strong-consensus", f"public IPv4={ip}")
        )

    # Parallelize independent network sources for reliability under timeouts.
    list_specs = [
        ("FireHOL proxies", FIREHOL_PROXIES, "firehol_proxies.netset", "open-proxy", True),
        ("FireHOL anonymous", FIREHOL_ANONYMOUS, "firehol_anonymous.netset", "anonymous-proxy/vpn", True),
        ("FireHOL tor 1d", FIREHOL_TOR_EXITS_1D, "tor_exits_1d.ipset", "tor-exit-1d", True),
        ("FireHOL tor 7d", FIREHOL_TOR_EXITS_7D, "tor_exits_7d.ipset", "tor-exit-7d", True),
        ("Tor bulk exit list", TOR_BULK_EXIT_LIST, "tor_bulk_exit_list.txt", "tor-exit", False),
    ]

    onionoo_result: tuple[list[dict[str, Any]] | None, str | None, bool] | None = None
    tor_check_result: tuple[bool | None, str | None, str | None] | None = None
    ipapi_result: tuple[dict[str, Any] | None, str | None] | None = None
    list_results: dict[str, ReputationEvidence] = {}

    def _do_onionoo() -> None:
        nonlocal onionoo_result
        onionoo_result = onionoo_relays_exact(ip)

    def _do_tor_check() -> None:
        nonlocal tor_check_result
        tor_check_result = tor_check_api(ip)

    def _do_ipapi() -> None:
        nonlocal ipapi_result
        ipapi_result = ip_api_reputation(ip)

    def _do_list(spec: tuple[str, str, str, str, bool]) -> None:
        label, url, cache_name, hit_status, is_netset = spec
        list_results[label] = _list_evidence(
            label, url, cache_name, hit_status, ip, is_netset=is_netset
        )

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [
            pool.submit(_do_onionoo),
            pool.submit(_do_tor_check),
            pool.submit(_do_ipapi),
            *[pool.submit(_do_list, spec) for spec in list_specs],
        ]
        for fut in as_completed(futures):
            exc = fut.exception()
            if exc is not None:
                evidence.append(
                    ReputationEvidence("collector", 3, "error", f"worker failed: {exc}")
                )

    matched, onionoo_err, onionoo_unreliable_empty = onionoo_result or (None, "Onionoo did not run", False)
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
                f"matched running relay {nick!r}; flags="
                f"{','.join(flags) if isinstance(flags, list) else flags}",
            )
        )
    elif onionoo_unreliable_empty:
        evidence.append(
            ReputationEvidence(
                "Onionoo",
                3,
                "truncated",
                "relay result truncated; no exact match but clean result is not definitive",
            )
        )
    else:
        evidence.append(
            ReputationEvidence(
                "Onionoo",
                1,
                "clean",
                "no exact running relay or exit-address match",
            )
        )

    is_tor, tor_detail, _ = tor_check_result or (None, "Tor check did not run", None)
    if is_tor is True:
        evidence.append(
            ReputationEvidence(
                "Tor check API",
                5,
                "tor-exit",
                tor_detail or "IsTor=true",
            )
        )
    elif is_tor is False:
        evidence.append(
            ReputationEvidence(
                "Tor check API",
                1,
                "clean",
                tor_detail or "IsTor=false",
            )
        )
    else:
        evidence.append(
            ReputationEvidence(
                "Tor check API",
                2,
                "unattributed" if tor_detail and "!= consensus" in tor_detail else "error",
                tor_detail or "Tor check unavailable",
            )
        )

    for label, *_ in list_specs:
        if label in list_results:
            evidence.append(list_results[label])
        else:
            evidence.append(ReputationEvidence(label, 3, "unavailable", "list check did not run"))

    # Downgrade uncorroborated FireHOL Tor hits when official Tor sources disagree.
    official_tor_clean = any(
        e.source in {"Tor check API", "Tor bulk exit list", "Onionoo"}
        and e.status == "clean"
        and e.severity == 1
        for e in evidence
    )
    official_tor_hit = any(
        e.source in {"Tor check API", "Tor bulk exit list", "Onionoo"} and e.severity >= 5
        for e in evidence
    )
    if official_tor_clean and not official_tor_hit:
        adjusted: list[ReputationEvidence] = []
        for e in evidence:
            if e.source.startswith("FireHOL tor") and e.severity >= 5:
                adjusted.append(
                    ReputationEvidence(
                        e.source,
                        4,
                        e.status + "-uncorroborated",
                        e.detail
                        + "; official Tor sources clean — treating FireHOL Tor hit as elevated, not definitive",
                    )
                )
            else:
                adjusted.append(e)
        evidence = adjusted

    ipapi, ipapi_err = ipapi_result or (None, "ip-api did not run")
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
            evidence.append(
                ReputationEvidence("ip-api", 4, "proxy-flag", f"{', '.join(flags)}; org={org}")
            )
        elif ipapi.get("hosting") is True:
            evidence.append(
                ReputationEvidence("ip-api", 2, "hosting", f"{', '.join(flags)}; org={org}")
            )
        else:
            evidence.append(
                ReputationEvidence(
                    "ip-api",
                    1,
                    "clean",
                    f"no proxy/hosting flag; org={org}",
                )
            )

    abuse_key = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()
    if abuse_key:
        abuse_data, abuse_err = abuseipdb_check(ip, abuse_key)
        if abuse_err:
            evidence.append(ReputationEvidence("AbuseIPDB", 3, "error", abuse_err))
        elif abuse_data:
            conf = int(abuse_data.get("abuseConfidenceScore") or 0)
            usage = str(abuse_data.get("usageType") or "")
            if abuse_data.get("isTor") is True:
                evidence.append(
                    ReputationEvidence(
                        "AbuseIPDB",
                        5,
                        "tor",
                        f"isTor=true; confidence={conf}%; usageType={usage!r}",
                    )
                )
            elif _usage_proxy_vpn(usage):
                evidence.append(
                    ReputationEvidence(
                        "AbuseIPDB",
                        5,
                        "proxy-vpn-usage",
                        f"confidence={conf}%; usageType={usage!r}",
                    )
                )
            elif conf >= 85 and _usage_hosting(usage):
                evidence.append(
                    ReputationEvidence(
                        "AbuseIPDB",
                        4,
                        "high-risk-hosting",
                        f"confidence={conf}%; usageType={usage!r}",
                    )
                )
            elif conf >= 40:
                evidence.append(
                    ReputationEvidence(
                        "AbuseIPDB",
                        4,
                        "elevated-risk",
                        f"confidence={conf}%; usageType={usage!r}",
                    )
                )
            else:
                evidence.append(
                    ReputationEvidence(
                        "AbuseIPDB",
                        1,
                        "low-risk",
                        f"confidence={conf}%; usageType={usage!r}",
                    )
                )
    else:
        # Optional source: do not demote an otherwise strong clean result.
        evidence.append(
            ReputationEvidence(
                "AbuseIPDB",
                1,
                "skipped",
                "ABUSEIPDB_API_KEY not set; optional check skipped",
            )
        )

    return evidence


def score_reputation_evidence(evidence: list[ReputationEvidence]) -> tuple[int, str]:
    hits5 = [e for e in evidence if e.severity >= 5]
    hits4 = [e for e in evidence if e.severity == 4]
    errors = [e for e in evidence if e.severity == 3]
    partial = [e for e in evidence if e.severity == 2]
    clean_sources = [
        e
        for e in evidence
        if e.severity == 1
        and e.status in {"clean", "low-risk", "strong-consensus", "skipped"}
    ]

    if hits5:
        return 5, "; ".join(
            f"{e.source}: {e.status} ({_short(e.detail, 120)})" for e in hits5[:4]
        )
    if hits4:
        return 4, "; ".join(
            f"{e.source}: {e.status} ({_short(e.detail, 120)})" for e in hits4[:4]
        )

    critical_clean = {
        "Onionoo",
        "FireHOL proxies",
        "FireHOL anonymous",
        "FireHOL tor 1d",
        "FireHOL tor 7d",
        "Tor bulk exit list",
    }
    # Prefer official Tor check when attributed; required for score 1 when present as clean.
    clean_names = {e.source for e in clean_sources}
    strong_ip = any(e.source == "egress-ip" and e.status == "strong-consensus" for e in evidence)
    tor_check_clean = any(
        e.source == "Tor check API" and e.status == "clean" and e.severity == 1 for e in evidence
    )
    tor_check_partial = any(e.source == "Tor check API" and e.severity == 2 for e in evidence)

    hard_errors = [
        e
        for e in errors
        if e.source in critical_clean or e.source in {"egress-ip", "ip-api", "Tor check API", "Onionoo"}
    ]
    if hard_errors and not (critical_clean <= clean_names):
        return (
            3,
            "Inconclusive reputation data: "
            + "; ".join(f"{e.source}: {_short(e.detail, 110)}" for e in hard_errors[:4]),
        )

    stale_critical = [
        e
        for e in evidence
        if e.source in critical_clean and e.status == "clean-stale"
    ]

    if strong_ip and critical_clean <= clean_names and not stale_critical:
        if tor_check_partial:
            return (
                2,
                "Likely clean on lists, but Tor check API could not be attributed to consensus IPv4.",
            )
        abuse_note = ""
        if any(e.source == "AbuseIPDB" and e.status == "low-risk" for e in clean_sources):
            abuse_note = " AbuseIPDB low risk."
        elif any(e.source == "AbuseIPDB" and e.status == "skipped" for e in clean_sources):
            abuse_note = " AbuseIPDB not configured (optional)."
        tor_note = " Tor check IsTor=false." if tor_check_clean else ""
        return (
            1,
            "Strong clean result: consensus IPv4, Onionoo clean, Tor/proxy lists clean."
            + tor_note
            + abuse_note,
        )

    if strong_ip and (critical_clean <= (clean_names | {e.source for e in stale_critical})) and stale_critical:
        return (
            2,
            "Likely clean, but one or more blocklists were served from stale cache: "
            + ", ".join(e.source for e in stale_critical[:4]),
        )

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
        print(
            f"{item.severity:<3} {_short(item.source, 22):<22} "
            f"{_short(item.status, 22):<22} {_short(item.detail, 220)}"
        )


def check_tor_proxy_reputation() -> tuple[int, str]:
    ip, ip_strong, ip_note = resolve_egress_ipv4()
    if not ip:
        return 3, f"Could not determine public IPv4. {ip_note}"
    cached = _read_result_cache(ip)
    if cached:
        score, description, _ = cached
        return score, f"[cached ≤{_result_cache_ttl_s()}s] {description}"
    evidence = collect_reputation_evidence(ip, ip_strong, ip_note)
    score, description = score_reputation_evidence(evidence)
    _write_result_cache(ip, score, description, evidence)
    return score, description


def main() -> None:
    print("=" * 60)
    print("Tor / Proxy / Abuse IP Reputation")
    print("=" * 60)
    print()
    ip, ip_strong, ip_note = resolve_egress_ipv4()
    if not ip:
        score, description = 3, f"Could not determine public IPv4. {ip_note}"
    else:
        cached = _read_result_cache(ip)
        if cached:
            score, description, rows = cached
            evidence = [
                ReputationEvidence(
                    str(r.get("source", "?")),
                    int(r.get("severity", 3)),
                    str(r.get("status", "?")),
                    str(r.get("detail", "")),
                )
                for r in rows
                if isinstance(r, dict)
            ]
            print_reputation_evidence(ip, evidence)
            print()
            print(f"(result cache hit, TTL {_result_cache_ttl_s()}s)")
            description = f"[cached ≤{_result_cache_ttl_s()}s] {description}"
        else:
            evidence = collect_reputation_evidence(ip, ip_strong, ip_note)
            print_reputation_evidence(ip, evidence)
            print()
            score, description = score_reputation_evidence(evidence)
            _write_result_cache(ip, score, description, evidence)
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
