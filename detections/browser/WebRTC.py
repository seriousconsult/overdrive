#!/usr/bin/env python3
 
'''
This script is a WebRTC Leak Tester. It uses Chromium DevTools
to see if your real local or public IP address is "leaking" through your browser's
WebRTC protocol, even if you are using a VPN or Proxy.

- Launches Chromium directly through DevTools; no Selenium/WebDriver.
- Better error output (exception type + message)
- Keeps page text in memory only (no files written)

WebRTC leak tester using Chromium DevTools and local RTCPeerConnection probing.

What it does:
- Opens a localhost page in Chromium.
- Creates an RTCPeerConnection with no STUN/TURN servers.
- Extracts IPv4-like strings from local ICE candidates only.
- Prints diagnostics so you can distinguish:
    - "No host candidate data present" vs "WebRTC API unavailable"

This script is a WebRTC Leak Tester. It uses Chromium DevTools
to see if your real local or public IP address is "leaking" through your browser's
WebRTC protocol, even if you are using a VPN or Proxy.
'''

import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_browser import ipv4_like_strings, is_private_ipv4, print_browser_probe_error
from detections.common.direct_chromium import run_async_script


WEBRTC_PROBE_JS = r"""
const callback = arguments[arguments.length - 1];
function finish(value) {
  if (typeof callback === "function") {
    callback(value);
  }
}

(async () => {
  const RTCPeerConnectionClass =
    window.RTCPeerConnection || window.webkitRTCPeerConnection || null;
  if (!RTCPeerConnectionClass) {
    finish({ok: true, supported: false, candidates: [], localDescription: ""});
    return;
  }
  const pc = new RTCPeerConnectionClass({iceServers: []});
  const candidates = [];
  pc.onicecandidate = (event) => {
    if (event && event.candidate && event.candidate.candidate) {
      candidates.push(String(event.candidate.candidate));
    }
  };
  try {
    pc.createDataChannel("overdrive");
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    const deadline = Date.now() + 4000;
    while (Date.now() < deadline && pc.iceGatheringState !== "complete") {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const localDescription = pc.localDescription && pc.localDescription.sdp
      ? String(pc.localDescription.sdp)
      : "";
    try { pc.close(); } catch (_ignore) {}
    finish({
      ok: true,
      supported: true,
      iceGatheringState: pc.iceGatheringState,
      candidates,
      localDescription,
    });
  } catch (err) {
    try { pc.close(); } catch (_ignore) {}
    finish({
      ok: false,
      error: String(err && err.message ? err.message : err),
      candidates,
    });
  }
})().catch((err) => finish({ok: false, error: String(err && err.message ? err.message : err)}));
"""


class WebRTCProbeHandler(BaseHTTPRequestHandler):
    server_version = "OverdriveWebRTCProbe/1.0"

    def log_message(self, _fmt: str, *_args) -> None:
        return

    def do_GET(self) -> None:
        body = b"<!doctype html><meta charset='utf-8'><title>WebRTC Probe</title>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_webrtc_probe_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), WebRTCProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="webrtc-probe")
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/"


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

    server = None
    try:
        server, url = start_webrtc_probe_server()
        result, error = run_async_script(WEBRTC_PROBE_JS, timeout=max(10, timeout), url=url)
        if error:
            raise RuntimeError(error)
        if not isinstance(result, dict):
            raise RuntimeError(f"WebRTC probe returned unexpected data: {result!r}")
        if result.get("ok") is False:
            raise RuntimeError(str(result.get("error") or "WebRTC local probe failed"))
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()

    evidence["supported"] = bool(result.get("supported"))
    evidence["ice_gathering_state"] = result.get("iceGatheringState")
    evidence["local_candidate_lines"] = list(result.get("candidates") or [])[:30]

    candidate_texts = list(result.get("candidates") or [])
    local_description = str(result.get("localDescription") or "")
    if local_description:
        candidate_texts.extend(
            line.strip()
            for line in local_description.splitlines()
            if line.strip().startswith("a=candidate:")
        )

    def record_candidate(ip, source):
        evidence["detected_ip_candidates"].append({"ip": ip, "source": source})
        if is_private_ipv4(ip):
            evidence["private_ips"].append({"ip": ip, "source": source})

    ips: list[str] = []
    for text in candidate_texts:
        for ip in ipv4_like_strings(text):
            ips.append(ip)
            record_candidate(ip, "local_ice_candidate")

    if ips:
        evidence["ip_source_id"] = "local_ice_candidate"
        evidence["ip_source_text"] = ips[0]
        return ips[0], evidence

    return None, evidence


def main():
    score, note = 3, "No run completed."
    ip = None
    evidence: dict = {}

    try:
        print("Running local WebRTC candidate probe...")
        print("Waiting for browser ICE gathering...")
        ip, evidence = try_extract_webrtc_evidence(timeout=25)

        # ---- ticket rule ----
        # Expected outcome: "No private/local IP exposed"
        ticket_fail = len(evidence.get("private_ips", [])) > 0
        score, note = compute_webrtc_leak_score(ip, evidence, had_exception=False)

        if not ip:
            print("WebRTC IP not detected in the DOM/text.")
            print("This can mean either:")
            print("  - WebRTC leak is blocked/hidden (good for privacy), OR")
            print("  - Browser used mDNS/host obfuscation for local candidates.")
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
        print(f"RTCPeerConnection supported? {evidence.get('supported')}")
        print(f"ICE gathering state:         {evidence.get('ice_gathering_state')}")
        print("Local candidate lines:")
        for line in evidence.get("local_candidate_lines", [])[:10]:
            print(f"  - {line[:180]}")

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
