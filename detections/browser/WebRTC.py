#!/usr/bin/env python3
 
'''
This script is a WebRTC Leak Tester. It uses Chromium DevTools
to see if your real local or public IP address is "leaking" through your browser's
WebRTC protocol, even if you are using a VPN or Proxy.

WebRTC Leak Tester using Chromium DevTools + browserleaks.com/webrtc.

- Launches Chromium directly through DevTools; no Selenium/WebDriver.
- Better error output (exception type + message)
- Keeps page text in memory only (no files written)

WebRTC leak tester using Chromium DevTools (BrowserLeaks page)

What it does:
- Opens https://browserleaks.com/webrtc in Chromium
- Waits for JS to populate WebRTC results
- Tries multiple ways to extract the WebRTC-revealed IP:
    1) Look for element id="rtc-ipv4"
    2) Look for any element with id starting "rtc-"
    3) If still missing, scan page text for IPv4-like strings
- Prints diagnostics so you can distinguish:
    - "No leak data present" vs "JS didn’t populate / selectors wrong"

This script is a WebRTC Leak Tester. It uses Chromium DevTools
to see if your real local or public IP address is "leaking" through your browser's
WebRTC protocol, even if you are using a VPN or Proxy.
'''

import re

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_browser import ipv4_like_strings, is_private_ipv4, print_browser_probe_error
from detections.common.direct_chromium import run_async_script
from detections.common.common_config import BROWSERLEAKS_WEBRTC_URL


URL = BROWSERLEAKS_WEBRTC_URL

WEBRTC_PROBE_JS = r"""
const callback = arguments[arguments.length - 1];
function finish(value) {
  if (typeof callback === "function") {
    callback(value);
  }
}

function collect() {
  const byId = (id) => {
    const el = document.getElementById(id);
    return el ? (el.innerText || el.textContent || "").trim() : "";
  };
  const rtcIds = Array.from(document.querySelectorAll('[id^="rtc-"]')).map((el) => el.id);
  const bodyText = document.body ? (document.body.innerText || document.body.textContent || "") : "";
  return {
    ok: true,
    rtcIds,
    rtcIpv4: byId("rtc-ipv4"),
    rtcLocal: byId("rtc-local"),
    rtcPublic: byId("rtc-public"),
    bodyText,
  };
}

(async () => {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const data = collect();
    if (data.rtcIpv4 || data.rtcLocal || data.rtcPublic || data.rtcIds.length > 0) {
      finish(data);
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  finish(collect());
})().catch((err) => finish({ok: false, error: String(err && err.message ? err.message : err)}));
"""


def compute_webrtc_leak_score(
    ip: str | None,
    evidence: dict,
    *,
    had_exception: bool = False,
) -> tuple[int, str]:
    """
    1 - Strong residential browser/network evidence.
    2 - Mildly atypical but still common browser/WebRTC behavior.
    3 - Ambiguous or failed run.
    4/5 are reserved for artificial-host evidence, which this probe does not produce.
    """
    if had_exception:
        return 3, "Run failed before a clean result; leak status unknown."

    private = evidence.get("private_ips") or []
    if private:
        return (
            1,
            "RFC1918 address visible via WebRTC; strong local residential network signal.",
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
            "No client IPv4 extracted; quiet WebRTC result is common on normal browsers.",
        )

    src = evidence.get("ip_source_id")
    if src in ("rtc-local", "rtc-public", "rtc-ipv4"):
        return (
            2,
            "Structured WebRTC fields expose an IPv4 candidate; mildly atypical but still browser-like.",
        )

    if src == "body_text":
        return (
            2,
            "IPv4 matched only from loose page text — low confidence (may be noise).",
        )

    return 3, "Extraction source unclear; treat as uncertain."


def try_extract_webrtc_evidence(timeout=30):
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

    result, error = run_async_script(WEBRTC_PROBE_JS, timeout=max(25, timeout), url=URL)
    if error:
        raise RuntimeError(error)
    if not isinstance(result, dict):
        raise RuntimeError(f"WebRTC probe returned unexpected data: {result!r}")
    if result.get("ok") is False:
        raise RuntimeError(str(result.get("error") or "WebRTC page probe failed"))

    def record_candidate(ip, source):
        evidence["detected_ip_candidates"].append({"ip": ip, "source": source})
        if is_private_ipv4(ip):
            evidence["private_ips"].append({"ip": ip, "source": source})

    # 1) Try rtc-ipv4 specifically (original selector)
    evidence["selector_attempts"].append('query #rtc-ipv4')
    txt = str(result.get("rtcIpv4") or "").strip()
    if txt:
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

    # 2) Collect rtc-* ids for diagnostics
    evidence["rtc_ids_found"] = list(result.get("rtcIds") or [])
    evidence["selector_attempts"].append('querySelectorAll([id^="rtc-"])')

    # Explicit rtc-local / rtc-public extraction (important for ticket meaning)
    evidence["rtc_local_raw"] = str(result.get("rtcLocal") or "").strip()
    evidence["rtc_local_ipv4"] = ipv4_like_strings(evidence["rtc_local_raw"])
    for ip in evidence["rtc_local_ipv4"]:
        record_candidate(ip, "rtc-local")

    evidence["rtc_public_raw"] = str(result.get("rtcPublic") or "").strip()
    evidence["rtc_public_ipv4"] = ipv4_like_strings(evidence["rtc_public_raw"])
    for ip in evidence["rtc_public_ipv4"]:
        record_candidate(ip, "rtc-public")

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
    text = str(result.get("bodyText") or "")
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
    score, note = 3, "No run completed."
    ip = None
    evidence: dict = {}

    try:
        print("Loading BrowserLeaks WebRTC test...")
        print("Waiting for WebRTC results to render (JS)...")
        ip, evidence = try_extract_webrtc_evidence(timeout=25)

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

        print(f"\nSCORE: {score}")
        # First substantive line after Score is what detections/run_detections.py prefers for HTML comments.
        print(f"STATUS: {note}")
        print("  Scale: 1 = residential/browser-like signal  ·  5 = definitely artificial host")

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
        err = f"{type(e).__name__}: {e}"
        print("\nAn error occurred in the Chromium DevTools probe:")
        print(f"Exception type: {type(e).__name__}")
        print(f"Exception message: {e}")
        return print_browser_probe_error(err)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
