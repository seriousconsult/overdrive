#!/usr/bin/env python3
"""
When you connect via QUIC, your client sends Transport Parameters. These are tiny technical details that vary depending on which software is being used:

    Initial Packet Size: How big is the very first piece of data sent?

    Max Data Limits: How much data can the server send before you acknowledge it?

    Stream Concurrency: How many parallel "conversations" can happen at once?

    Error Handling: How does the client react if a packet is lost?

A standard Chrome browser on Windows has one specific pattern of these settings. A Python script (bot) pretending to be Chrome usually has a different pattern,
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

API_URL = "https://tls.peet.ws/api/all"
TIMEOUT = 25


def build_driver() -> webdriver.Chrome:
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,800")
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    opts.add_argument("--disable-blink-features=AutomationControlled")
    return webdriver.Chrome(options=opts)


def _extract_json_text(driver: webdriver.Chrome) -> str | None:
    """
    tls.peet.ws/api/all usually renders JSON as plain text or inside <pre>.
    """
    try:
        pre = WebDriverWait(driver, TIMEOUT).until(
            EC.presence_of_element_located((By.TAG_NAME, "pre"))
        )
        text = (pre.text or "").strip()
        if text.startswith("{") and text.endswith("}"):
            return text
    except Exception:
        pass

    try:
        text = driver.find_element(By.TAG_NAME, "body").text.strip()
        if text.startswith("{") and text.endswith("}"):
            return text
    except Exception:
        pass

    return None


def fetch_browser_observation() -> tuple[dict[str, Any] | None, str | None]:
    driver = None
    try:
        driver = build_driver()
        url = f"{API_URL}?src=browser&t={int(time.time())}"
        driver.get(url)
        raw = _extract_json_text(driver)
        if not raw:
            return None, "Could not parse JSON from browser probe page."
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data, None
            return None, "Probe response was JSON but not an object."
        except Exception as e:
            return None, f"JSON parse error: {type(e).__name__}: {e}"
    except Exception as e:
        return None, f"Browser probe failed: {type(e).__name__}: {e}"
    finally:
        if driver is not None:
            try:
                driver.quit()
            except Exception:
                pass


def _walk_key_values(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            out.append((path, v))
            out.extend(_walk_key_values(v, path))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = f"{prefix}[{i}]"
            out.extend(_walk_key_values(v, path))
    return out


def extract_quic_signals(data: dict[str, Any]) -> dict[str, Any]:
    kv = _walk_key_values(data)

    key_pat = re.compile(
        r"(?:^|\.)(quic|http3|h3|transport|alpn|grease|max_data|max_streams|"
        r"ack_delay|initial|max_udp_payload|active_connection_id_limit|disable_active_migration)",
        re.I,
    )
    str_pat = re.compile(r"\b(h3|http/3|quic)\b", re.I)

    matched_entries: list[tuple[str, Any]] = []
    for k, v in kv:
        if key_pat.search(k):
            matched_entries.append((k, v))
            continue
        if isinstance(v, str) and str_pat.search(v):
            matched_entries.append((k, v))

    http_version = str(data.get("http_version", "") or "").lower()
    ua = str(data.get("user_agent", "") or "")

    tls = data.get("tls", {})
    alpn = ""
    if isinstance(tls, dict):
        alpn = str(tls.get("alpn", "") or "").lower()

    has_h3 = ("h3" in http_version) or ("h3" in alpn) or ("quic" in http_version)

    transport_param_paths = []
    for k, _v in matched_entries:
        lk = k.lower()
        if "transport" in lk or "max_data" in lk or "max_streams" in lk:
            transport_param_paths.append(k)

    return {
        "http_version": http_version,
        "alpn": alpn,
        "user_agent": ua,
        "has_h3_or_quic": has_h3,
        "matched_entries": matched_entries[:80],
        "transport_param_paths": transport_param_paths[:40],
        "transport_param_count": len(transport_param_paths),
    }


def score_quic_fingerprint(sig: dict[str, Any], probe_error: str | None) -> tuple[int, str]:
    """
    1 = Browser-like and coherent QUIC/HTTP3 evidence
    2 = Mostly coherent, minor uncertainty
    3 = Inconclusive / partial evidence
    4 = Suspicious mismatch (automation-like behavior or missing expected evidence)
    5 = Strong non-browser / bot-like inconsistency
    """
    if probe_error:
        return 3, f"Could not complete browser observation ({probe_error})"

    ua = (sig.get("user_agent") or "").lower()
    has_h3 = bool(sig.get("has_h3_or_quic"))
    tp_count = int(sig.get("transport_param_count") or 0)
    http_version = str(sig.get("http_version", ""))
    alpn = str(sig.get("alpn", ""))

    is_headless = "headlesschrome" in ua
    is_library_ua = any(tok in ua for tok in ("python", "httpx", "requests", "curl/", "aiohttp"))
    has_chrome_ua = ("chrome/" in ua) or ("edg/" in ua) or ("chromium" in ua)
    ua_windows = "windows nt" in ua
    ua_linux = ("x11;" in ua and "linux" in ua) or ("linux" in ua and not ua_windows)
    ua_mac = "macintosh" in ua or "mac os x" in ua

    if is_library_ua:
        return 5, "User-Agent looks like a script/library client instead of a browser."

    # Strong automation signal: headless Chromium with no QUIC/H3 evidence.
    # This should not score as neutral because it is a high-confidence non-human profile in many environments.
    if is_headless and not has_h3 and tp_count == 0:
        return 5, (
            "HeadlessChrome observed with HTTP/2 fallback and no QUIC transport-parameter evidence "
            "(strong automation/non-standard client signal)."
        )

    # Headless still carries substantial bot signal even when H3 appears.
    if is_headless and has_h3:
        if tp_count >= 2:
            return 4, "HeadlessChrome with QUIC/H3 present, but automation fingerprint remains strong."
        return 5, "HeadlessChrome with weak QUIC evidence (high-confidence automation profile)."

    # Optional environment heuristic from UA only:
    # baseline expectation in this repo comment is "standard Chrome on Windows".
    if has_chrome_ua and not ua_windows and (ua_linux or ua_mac) and not has_h3 and tp_count == 0:
        return 4, (
            "Chrome-like UA is non-Windows and no QUIC transport evidence was observed "
            "(possible downgraded or non-standard stack)."
        )

    if has_h3 and tp_count >= 3 and has_chrome_ua and not is_headless:
        return 1, "HTTP/3 + QUIC transport-parameter evidence looks coherent for a normal browser."

    if has_h3 and tp_count >= 1 and has_chrome_ua:
        if is_headless:
            return 2, "HTTP/3/QUIC observed, but headless browser context reduces confidence."
        return 2, "HTTP/3/QUIC observed with partial transport-parameter evidence."

    if (("h2" in http_version) or ("h2" in alpn)) and has_chrome_ua and tp_count == 0:
        return 4, (
            "Chrome-like UA negotiated HTTP/2 and exposed no QUIC transport-parameter evidence "
            "(suspicious for an H3-capable client path)."
        )

    if has_chrome_ua and not has_h3 and tp_count == 0:
        return 4, "Browser-like UA without QUIC/HTTP3 transport evidence (possible downgrade or stack mismatch)."

    return 4, "QUIC/HTTP3 fingerprint evidence is sparse or inconsistent for the claimed client profile."


def main() -> None:
    print("=" * 64)
    print("HTTP/3 (QUIC) Fingerprint Detection")
    print("=" * 64)
    print()
    print("Probe endpoint:", API_URL)
    print("Method: Selenium browser probe + recursive QUIC signal extraction")
    print()

    data, err = fetch_browser_observation()
    if not data:
        score, status = score_quic_fingerprint({}, err or "no data returned")
        print(f"SCORE: {score}")
        print(f"STATUS: {status}")
        print()
        print("=" * 64)
        return

    sig = extract_quic_signals(data)
    score, status = score_quic_fingerprint(sig, None)

    print("[Observed]")
    print(f"- http_version: {sig.get('http_version') or '(empty)'}")
    print(f"- tls.alpn:     {sig.get('alpn') or '(empty)'}")
    print(f"- user_agent:   {sig.get('user_agent') or '(empty)'}")
    print(f"- h3/quic seen: {sig.get('has_h3_or_quic')}")
    print(f"- transport-parameter key hits: {sig.get('transport_param_count')}")
    print()

    hits = sig.get("matched_entries") or []
    if hits:
        print("[Matched QUIC/HTTP3 Signals]")
        for k, v in hits[:15]:
            vs = str(v)
            if len(vs) > 120:
                vs = vs[:117] + "..."
            print(f"  - {k}: {vs}")
        if len(hits) > 15:
            print(f"  - ... and {len(hits) - 15} more")
        print()
    else:
        print("[Matched QUIC/HTTP3 Signals]")
        print("  - none")
        print()

    print(f"SCORE: {score}")
    print(f"STATUS: {status}")
    print("Scale: 1 = coherent browser-like QUIC profile · 5 = strong bot/mismatch signal")
    print()
    print("=" * 64)


if __name__ == "__main__":
    main()
