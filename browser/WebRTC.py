#!/usr/bin/env python3
 
'''
This script is a WebRTC Leak Tester. It uses Selenium (a browser automation tool) 
to see if your real local or public IP address is "leaking" through your browser's 
WebRTC protocol, even if you are using a VPN or Proxy.

WebRTC Leak Tester using Selenium + browserleaks.com/webrtc.

- Forces headless Chrome + WSL-safe flags
- Better error output (exception type + message)
- Keeps screenshot + page source snippet in memory only (no files written)

WebRTC leak tester using Selenium (BrowserLeaks page)

What it does:
- Opens https://browserleaks.com/webrtc in headless Chrome
- Waits for JS to populate WebRTC results
- Tries multiple ways to extract the WebRTC-revealed IP:
    1) Look for element id="rtc-ipv4"
    2) Look for any element with id starting "rtc-"
    3) If still missing, scan page text for IPv4-like strings
- Prints diagnostics so you can distinguish:
    - "No leak data present" vs "JS didn’t populate / selectors wrong"

This script is a WebRTC Leak Tester. It uses Selenium (a browser automation tool)
to see if your real local or public IP address is "leaking" through your browser's
WebRTC protocol, even if you are using a VPN or Proxy.
'''

import re
import traceback

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


URL = "https://browserleaks.com/webrtc"


def build_driver():
    chrome_options = Options()

    # Headless stable flags for WSL
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1280,800")

    # Make media permissions less likely to block WebRTC in headless
    chrome_options.add_argument("--use-fake-ui-for-media-stream")
    chrome_options.add_argument("--use-fake-device-for-media-stream")

    # Reduce automation fingerprinting a bit
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option("useAutomationExtension", False)
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")

    # If Chrome is not on PATH, uncomment and set:
    # chrome_options.binary_location = "/usr/bin/google-chrome"

    return webdriver.Chrome(options=chrome_options)


def ipv4_like_strings(text: str):
    # Simple IPv4 matcher
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")


def is_private_ipv4(ip: str) -> bool:
    """
    Ticket interpretation: "private/local IP" => RFC1918 ranges.
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
    """
    if not ip:
        return False
    try:
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        return False
    except Exception:
        return False


def collect_diagnostics_memory(driver):
    """
    In-memory capture only (no disk). Caller may inspect bytes/str before shutdown.
    """
    out = {"screenshot_png": None, "page_source_snippet": None}
    try:
        out["screenshot_png"] = driver.get_screenshot_as_png()
    except Exception:
        pass
    try:
        out["page_source_snippet"] = (driver.page_source or "")[:30000]
    except Exception:
        pass
    return out


def compute_webrtc_leak_score(
    ip: str | None,
    evidence: dict,
    *,
    had_exception: bool = False,
) -> tuple[int, str]:
    """
    1 — No leak signal from this run (no IPv4 extracted / WebRTC looks quiet).
    5 — Strong leak signal (RFC1918 “local” IP visible via WebRTC).
    2–4 — Increasing confidence that some address path is exposed, or run is ambiguous.

    Note: A visible *public* candidate in rtc-* fields is scored 4 (WebRTC is surfacing
    an address); only RFC1918 in the collected evidence yields 5.
    """
    if had_exception:
        return 3, "Run failed before a clean result; leak status unknown."

    private = evidence.get("private_ips") or []
    if private:
        return (
            5,
            "RFC1918 address visible via WebRTC (local/private leak).",
        )

    if not ip:
        rtc_ids = evidence.get("rtc_ids_found") or []
        if rtc_ids:
            return (
                3,
                "rtc-* elements exist but no IPv4 was parsed — page or timing ambiguous.",
            )
        return (
            1,
            "No client IPv4 extracted; no private leak and no structured candidate.",
        )

    src = evidence.get("ip_source_id")
    if src in ("rtc-local", "rtc-public", "rtc-ipv4"):
        return (
            4,
            "Structured WebRTC fields expose an IPv4 candidate (public or path-visible).",
        )

    if src == "body_text":
        return (
            2,
            "IPv4 matched only from loose page text — low confidence (may be noise).",
        )

    return 3, "Extraction source unclear; treat as uncertain."


def dom_rtc_ids(driver):
    # Ask the page which rtc-* ids exist right now
    try:
        ids = driver.execute_script(
            'return Array.from(document.querySelectorAll(\'[id^="rtc-"]\'))'
            '.map(e => e.id);'
        )
        if not isinstance(ids, list):
            return []
        return ids
    except Exception:
        return []


def dom_text(driver):
    try:
        # innerText includes rendered JS content
        return driver.execute_script(
            "return document.body ? document.body.innerText : ''"
        ) or ""
    except Exception:
        return driver.page_source or ""


def try_extract_webrtc_evidence(driver, wait_seconds=30):
    """
    Returns evidence dict and a "primary" IP candidate for display:
      - evidence["ticket_fail"] is True iff any PRIVATE/RFC1918 IP is detected.
      - evidence["private_ips"] lists all detected private IPs with sources.
    """
    evidence = {
        "rtc_ipv4_found": False,
        "rtc_ids_found": [],
        "ipv4_strings_in_body_text": [],
        "selector_attempts": [],

        # explicit fields
        "rtc_local_raw": None,
        "rtc_public_raw": None,
        "rtc_local_ipv4": [],
        "rtc_public_ipv4": [],

        # body scan classifications
        "private_ips": [],  # list of {ip, source}
        "detected_ip_candidates": [],  # list of {ip, source}

        # pick which one to display as primary
        "ip_source_id": None,
        "ip_source_text": None,
    }

    wait = WebDriverWait(driver, wait_seconds)

    def record_candidate(ip, source):
        evidence["detected_ip_candidates"].append({"ip": ip, "source": source})
        if is_private_ipv4(ip):
            evidence["private_ips"].append({"ip": ip, "source": source})

    # 1) Try rtc-ipv4 specifically (original selector)
    try:
        evidence["selector_attempts"].append('wait for #rtc-ipv4')
        el = wait.until(EC.presence_of_element_located((By.ID, "rtc-ipv4")))
        txt = (el.text or "").strip()
        evidence["rtc_ipv4_found"] = True

        evidence["ip_source_id"] = "rtc-ipv4"
        evidence["ip_source_text"] = txt

        ips = ipv4_like_strings(txt)
        if ips:
            # record all IPv4s we can see in that element
            for ip in ips:
                record_candidate(ip, "rtc-ipv4")
            # choose first as primary
            evidence["ip_source_text"] = txt
            return ips[0], evidence

        # if rtc-ipv4 exists but no IPv4 strings matched, continue
    except Exception:
        pass

    # 2) Collect rtc-* ids for diagnostics
    evidence["rtc_ids_found"] = dom_rtc_ids(driver)
    evidence["selector_attempts"].append('querySelectorAll([id^="rtc-"])')

    # Explicit rtc-local / rtc-public extraction (important for ticket meaning)
    for target_id in ["rtc-local", "rtc-public"]:
        try:
            el = driver.find_element(By.ID, target_id)
            t = (el.text or "").strip()
            if target_id == "rtc-local":
                evidence["rtc_local_raw"] = t
                evidence["rtc_local_ipv4"] = ipv4_like_strings(t)
                for ip in evidence["rtc_local_ipv4"]:
                    record_candidate(ip, "rtc-local")
            else:
                evidence["rtc_public_raw"] = t
                evidence["rtc_public_ipv4"] = ipv4_like_strings(t)
                for ip in evidence["rtc_public_ipv4"]:
                    record_candidate(ip, "rtc-public")
        except Exception:
            pass

    # If we saw any IP candidates so far, choose a primary to display.
    # Prefer showing rtc-local first (since that's what your ticket rejects).
    if evidence["rtc_local_ipv4"]:
        evidence["ip_source_id"] = "rtc-local"
        evidence["ip_source_text"] = evidence["rtc_local_raw"]
        return evidence["rtc_local_ipv4"][0], evidence

    if evidence["rtc_public_ipv4"]:
        evidence["ip_source_id"] = "rtc-public"
        evidence["ip_source_text"] = evidence["rtc_public_raw"]
        return evidence["rtc_public_ipv4"][0], evidence

    # 3) Fallback: scan body text for IPv4-like strings
    text = dom_text(driver)
    ips = ipv4_like_strings(text)
    evidence["ipv4_strings_in_body_text"] = ips[:20]

    for ip in ips:
        record_candidate(ip, "body_text")

    if ips:
        # choose first non-empty for display
        evidence["ip_source_id"] = "body_text"
        evidence["ip_source_text"] = ips[0]
        return ips[0], evidence

    return None, evidence


def main():
    driver = None
    mem_diag = None
    score, note = 3, "No run completed."
    ip = None
    evidence: dict = {}

    try:
        driver = build_driver()

        print("Loading BrowserLeaks WebRTC test...")
        driver.get(URL)

        print("Waiting for WebRTC results to render (JS)...")
        ip, evidence = try_extract_webrtc_evidence(driver, wait_seconds=30)

        # ---- ticket rule ----
        # Expected outcome: "No private/local IP exposed"
        ticket_fail = len(evidence.get("private_ips", [])) > 0
        score, note = compute_webrtc_leak_score(ip, evidence, had_exception=False)

        if not ip:
            print("WebRTC IP not detected in the DOM/text.")
            print("This can mean either:")
            print("  - WebRTC leak is blocked/hidden (good for privacy), OR")
            print("  - BrowserLeaks JS did not populate results / selector mismatch.")
        else:
            print("--- RESULT ---")
            print(f"WebRTC Detected IP candidate: {ip}")
            print("--------------")

        print("\n[RESULT]")
        if ticket_fail:
            print("FAIL: Private/local IP was exposed (RFC1918).")
            # show first failing private ip for clarity
            first_private = evidence["private_ips"][0]
            print(f"  First private IP: {first_private['ip']} (source: {first_private['source']})")
        else:
            print("PASS: No private/local IP detected (RFC1918).")

        print(f"\nScore:{score}")
        print(f"  {note}")
        print("  Scale: 1 = no leak signal  ·  5 = strong local (RFC1918) WebRTC leak")

        # Print concise evidence to make it debuggable
        print("\n[Diagnostics]")
        print(f"rtc-ipv4 found?     {evidence.get('rtc_ipv4_found')}")
        rtc_ids = evidence.get("rtc_ids_found", [])
        print(f"rtc-* element ids:  {rtc_ids[:30]}")
        print(f"IPv4-like strings in body text (top): {evidence.get('ipv4_strings_in_body_text', [])[:10]}")

        print("\n[Extracted rtc-local / rtc-public]")
        print(f"rtc-local raw:      {evidence.get('rtc_local_raw')}")
        print(f"rtc-local ipv4:     {evidence.get('rtc_local_ipv4', [])}")
        print(f"rtc-public raw:     {evidence.get('rtc_public_raw')}")
        print(f"rtc-public ipv4:    {evidence.get('rtc_public_ipv4', [])}")

        print("\n[Detected IP candidates]")
        for item in evidence.get("detected_ip_candidates", [])[:30]:
            print(f"  - {item['ip']}  (source: {item['source']})")

        print("\n[Private IPs (RFC1918)]")
        if evidence.get("private_ips"):
            for item in evidence["private_ips"][:30]:
                print(f"  - {item['ip']} (source: {item['source']})")
        else:
            print("  none")

        print("\n[Primary displayed source]")
        print(f"IP came from:       {evidence.get('ip_source_id')}")
        print(f"IP source text:    {evidence.get('ip_source_text')}")
    except Exception as e:
        score, note = compute_webrtc_leak_score(None, {}, had_exception=True)
        print("\nAn error occurred in Selenium:")
        print(f"Exception type: {type(e).__name__}")
        print(f"Exception message: {e}")
        traceback.print_exc()
        print(f"\n[Leak score 1–5] {score}")
        print(f"  {note}")
    finally:
        if driver is not None:
            try:
                mem_diag = collect_diagnostics_memory(driver)
            except Exception:
                mem_diag = None
            try:
                driver.quit()
            except Exception:
                pass

    return score


if __name__ == "__main__":
    main()