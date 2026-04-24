#!/usr/bin/env python3


'''
This is layer 7. Note that TCP fingerprinting may also occur and that is layer 2.

When you connect via HTTP2, your client sends a SETTINGS frame and a WINDOW_UPDATE frame. 
The specific values and the order in which they are sent are unique to different browsers.
These are a fingerprint. So if the site is intended for browsers and your fingerprint is
H2 Fingerprint: 1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p that matches 
Python h2 / httpx libraries not chrome (Ex. 1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p). 
So it is obvious you are not an intended user. 

While this doesn't detect the VPN "tunnel," it detects the software being used over the VPN.
Most people using a VPN for privacy use a standard browser. However, people using VPNs for automated
tasks (botting, scraping, account creation) often use Python or headless browsers. 
These tools have very different HTTP2 signatures than a typical human's browser.

1. Settings (The "Signature")
    HEADER_TABLE_SIZE: How much memory the server should use to compress headers.
    ENABLE_PUSH: Whether the client accepts "Server Push."
    INITIAL_WINDOW_SIZE: How much data the client can receive before sending an acknowledgment.
    MAX_FRAME_SIZE: The largest frame the client is willing to receive.
2. Window Update
    The value 12517377 is a massive tell. In HTTP2, the flow control window size is often set to a
       specific number by different network libraries. If your "Browser" sends a window update that
         matches a known Python-httpx or Go-http2 value, you get flagged.
3. Pseudo-Header Order
    Notice the list on the right: method, path, authority, scheme.
    The "Gotcha": Google Chrome always sends these in a specific order (usually :method, :authority, 
    :scheme, :path). If your script sends them in a different order (like putting path before authority),
      the server knows you aren't actually using Chrome, regardless of what your User-Agent says.

'''
#!/usr/bin/env python3
"""
HTTP/2 + TLS Fingerprint Consistency Check

What this does (useful + explicit):
  1) Determines the local runtime environment (WSL/Linux, OS, python, httpx versions).
  2) Performs a fresh HTTP/2 request to tls.peet.ws /api/all (unique query param).
  3) Extracts observed fingerprints:
       - server-observed user_agent
       - HTTP/2 Akamai fingerprint (settings-derived)
       - TLS JA3/JA4 and PeetPrint
  4) Produces a heuristic verdict:
       - Is the observed client stack consistent with THIS script (httpx on your machine)?
       - If Akamai HTTP/2 SETTINGS look browser-like vs library-like, highlight it.

Note:
  - This is NOT definitive VPN detection.
  - It’s a “does the network-observed stack match my actual client stack?” check.
"""

import time
import platform
import sys
import ssl
import re

import httpx


def detect_runtime():
    sysname = platform.system()
    machine = platform.machine()

    # WSL detection
    is_wsl = False
    try:
        with open("/proc/version", "r", encoding="utf-8", errors="ignore") as f:
            is_wsl = "microsoft" in f.read().lower()
    except Exception:
        is_wsl = False

    if sysname.lower() == "linux" and is_wsl:
        runtime = "WSL (Linux)"
    elif sysname.lower() == "linux":
        runtime = "Linux"
    elif sysname.lower() == "windows":
        runtime = "Windows"
    elif sysname.lower() == "darwin":
        runtime = "macOS"
    else:
        runtime = sysname

    # Python/openssl info
    pyver = sys.version.replace("\n", " ")
    openssl_ver = getattr(ssl, "OPENSSL_VERSION", "unknown")

    return {
        "runtime": runtime,
        "machine": machine,
        "python": pyver,
        "openssl": openssl_ver,
    }


def parse_akamai_fingerprint_settings(akamai_fp: str):
    """
    Akamai fingerprint format example:
      1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p

    The left part before first '|' lists SETTINGS IDs and values.
    We'll parse a few keys heuristically:
      header_table_size (SETTINGS id 1)
      max_frame_size     (id 4 or 5 depending on how mapped; we’ll just report what we see)
    """
    if not akamai_fp:
        return {}

    left = akamai_fp.split("|", 1)[0]
    # entries like "1:4096;2:0;4:65535"
    parts = left.split(";")
    kv = {}
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k.isdigit():
            try:
                kv[int(k)] = int(v)
            except ValueError:
                pass

    # Common: SETTINGS[1] = HEADER_TABLE_SIZE
    header_table_size = kv.get(1)
    return {
        "settings_raw_left": left,
        "header_table_size": header_table_size,
        "settings_kv": kv,
    }


def likely_browser_vs_library(header_table_size: int | None):
    """
    Very heuristic:
      - Many browsers have larger header table sizes (often 65536).
      - Some HTTP/2 library clients use smaller values (often 4096).
    """
    if header_table_size is None:
        return "unknown"
    if header_table_size >= 32768:
        return "browser-like (heuristic)"
    if header_table_size <= 8192:
        return "library-like (heuristic)"
    return "mixed (heuristic)"


def main():
    print("============================================================")
    print("HTTP/2 Fingerprint Consistency Check (Observed vs Expected)")
    print("============================================================\n")

    rt = detect_runtime()
    print("[1] Local runtime (expected)")
    print("- Runtime: ", rt["runtime"])
    print("- Machine: ", rt["machine"])
    print("- Python:  ", rt["python"])
    print("- OpenSSL: ", rt["openssl"])

    # Print library versions
    try:
        import httpx as _httpx
        try:
            import httpcore as _httpcore  # type: ignore
            httpcore_ver = getattr(_httpcore, "__version__", "unknown")
        except Exception:
            httpcore_ver = "unknown"

        print("- httpx:   ", getattr(_httpx, "__version__", "unknown"))
        print("- httpcore:", httpcore_ver)
    except Exception:
        print("- httpx:   (unknown)")

    # Fresh request
    url = f"https://tls.peet.ws/api/all?t={int(time.time())}"
    print("\n[2] Observing network (tls.peet.ws)")
    print("Request URL:", url)

    # Important: use HTTP/2 and disable pooling for a “fresh” fingerprint
    with httpx.Client(http2=True, limits=httpx.Limits(max_connections=1)) as client:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.json()

    # Extract observed fields
    observed_user_agent = data.get("user_agent", "") or ""
    negotiated_http_version = data.get("http_version", "") or resp.http_version
    http2 = data.get("http2", {}) or {}
    tls = data.get("tls", {}) or {}

    akamai_fp = http2.get("akamai_fingerprint") or ""
    akamai_fp_hash = http2.get("akamai_fingerprint_hash") or ""
    settings = http2.get("settings")  # may be None in some cases

    ja3_hash = tls.get("ja3_hash") or ""
    ja4 = tls.get("ja4") or ""
    ja4_r = tls.get("ja4_r") or ""
    peetprint_hash = tls.get("peetprint_hash") or ""
    peetprint = tls.get("peetprint") or ""

    print("\n[3] Observed fingerprints (what the network stack reported)")
    print("- Negotiated protocol: ", negotiated_http_version)
    print("- Observed user_agent: ", repr(observed_user_agent))

    print("\n--- HTTP/2 / Akamai ---")
    print("- Akamai fingerprint:      ", akamai_fp if akamai_fp else "(empty)")
    print("- Akamai fingerprint hash: ", akamai_fp_hash if akamai_fp_hash else "(empty)")
    print("- HTTP/2 sent settings:   ", settings if settings is not None else "(not provided)")

    print("\n--- TLS / Peet ---")
    print("- JA3 hash:     ", ja3_hash if ja3_hash else "(empty)")
    print("- JA4:          ", ja4 if ja4 else "(empty)")
    print("- JA4 (raw):    ", ja4_r if ja4_r else "(empty)")
    print("- PeetPrint hash:", peetprint_hash if peetprint_hash else "(empty)")

    # Expected from THIS script: httpx adds a python-httpx UA
    print("\n[4] Consistency verdict (heuristic, not VPN-proof)")
    expected_substrings = ["python-httpx", "httpx"]
    ua_looks_like_httpx = any(s in observed_user_agent.lower() for s in expected_substrings)

    # Parse the HTTP/2 fingerprint settings
    akamai_settings = parse_akamai_fingerprint_settings(akamai_fp)
    header_table_size = akamai_settings.get("header_table_size")
    http2_style = likely_browser_vs_library(header_table_size)

    # Build verdict
    verdict = "UNCERTAIN"
    confidence = "low"

    if ua_looks_like_httpx:
        # UA matches the client we are running
        if http2_style.startswith("library-like"):
            verdict = "CONSISTENT with httpx/library HTTP/2 stack (heuristic)"
            confidence = "high"
        elif http2_style.startswith("browser-like"):
            verdict = "UA matches httpx, but HTTP/2 settings look browser-like (possible proxy/translation/mismatch)"
            confidence = "medium"
        else:
            verdict = "UA matches httpx; HTTP/2 settings are mixed/unknown (heuristic)"
            confidence = "medium"
    else:
        # UA does not match expected local library behavior
        if observed_user_agent:
            verdict = "MISMATCH: UA does not look like httpx, but you ran httpx (possible proxy/rewriting)"
            confidence = "high"
        else:
            verdict = "MISMATCH/LOW INFO: UA is empty; cannot validate library consistency"
            confidence = "low"

    print("- Expected client: python-httpx/httpx (THIS script)")
    print("- UA looks like httpx? ", ua_looks_like_httpx)
    print("- HTTP/2 style guess:", http2_style)
    if header_table_size is not None:
        print("  (Parsed SETTINGS header table size):", header_table_size)

    print("- Verdict:", verdict)
    print("- Confidence:", confidence)

    print("\n============================================================")


if __name__ == "__main__":
    main()