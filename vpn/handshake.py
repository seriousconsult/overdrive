#!/usr/bin/env python3


'''
VPN servers often use specific versions of OpenSSL or other libraries. 
A server can look at the  hash of your SSL handshake (JA3).
If that hash matches a known "NordVPN Exit Node" or "OpenVPN Client" signature,
they know you aren't just a typial person on Chrome and are using a VPN.


Since JA3 hashes change slightly when libraries (like openssl) update, one way to do this is to keep 
an eye on JA3 Fingerprint Databases, such as:
https://www.google.com/search?q=JA3er.com: A massive community-driven database of hashes.
Abuse.ch: Often lists JA3 hashes associated with malware or known botnets/VPN nodes.

Many high-end VPNs use TLS Grease. This adds random data to the handshake so that your JA3 hash 
changes every single time you connect. If you run your script twice and get two different hashes,
 your VPN is using "Grease" to try to defeat fingerprinting matches to a specific fingerprint.   


TODO:TLS info
 TLS version used
Protocols
Supported versions
Curves
Signature algorithms
Extensions
Ciphers


'''


#!/usr/bin/env python3
"""
Deep TLS Fingerprint Analysis (JA3 + JA4 + PeetPrint + Akamai) using tls.peet.ws

Output is formatted into clear sections with wrapped long fields.
"""

import re
import httpx


GREASE_DECIMALS = {
    2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
    35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250
}


def detect_grease_from_ja3(ja3: str):
    """Heuristic GREASE detection by extracting integers from JA3."""
    if not ja3:
        return []

    nums = re.findall(r"\d+", ja3)
    found = []
    for n in nums:
        v = int(n)
        if v in GREASE_DECIMALS:
            found.append(v)

    # de-dupe preserving order
    seen = set()
    out = []
    for v in found:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def wrap(s: str, width: int = 88):
    """Wrap long strings for terminal readability."""
    if s is None:
        return ""
    s = str(s)
    if len(s) <= width:
        return s
    # simple word-less wrap (since these strings are usually delimiter-separated)
    return "\n".join(s[i:i + width] for i in range(0, len(s), width))


def print_kv(label: str, value: str, wrap_width: int = 0):
    """Print a consistent key/value line; optionally wrap value."""
    if wrap_width and value is not None:
        wrapped = wrap(value, wrap_width)
        # first line aligns with label, subsequent lines are indented
        lines = wrapped.splitlines()
        print(f"{label}: {lines[0]}")
        for extra in lines[1:]:
            print(f"{' ' * (len(label) + 2)}{extra}")
    else:
        print(f"{label}: {value}")


def run_deep_analysis():
    # Exact-string DB match (brittle by design)
    JA3_DB = {
        "771,4866-4867-4865-4868-49196-49200-52393-52392-49325-49195-49199-49324-49187-49191-49162-49172-49161-49171-157-49309-156-49308-61-60-53-47-159-52394-49311-158-49310-107-103-57-51,65281-0-11-10-35-16-22-23-13-43-45-51-27,4588-4587-4589-29-23-30-25-24-256-257-258-259-260,0-1-2":
            "Python (Requests / Urllib3) - Standard Linux/WSL (heuristic)"
    }

    url = "https://tls.peet.ws/api/all"

    # http2=True gives the best chance of HTTP/2 fingerprint fields populating
    with httpx.Client(http2=True, timeout=20) as client:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.json()

    tls = data.get("tls", {}) or {}
    http2 = data.get("http2", {}) or {}

    # Core fields
    http_version = data.get("http_version")
    method = data.get("method")
    user_agent = data.get("user_agent", "")

    ja3 = tls.get("ja3", "")
    ja3_hash = tls.get("ja3_hash", "")
    ja4 = tls.get("ja4", "")
    ja4_r = tls.get("ja4_r", "")

    peetprint = tls.get("peetprint", "")
    peetprint_hash = tls.get("peetprint_hash", "")

    akamai_fp = http2.get("akamai_fingerprint", "")
    akamai_fp_hash = http2.get("akamai_fingerprint_hash", "")

    # Analysis
    grease_values = detect_grease_from_ja3(ja3)
    db_match = JA3_DB.get(ja3, "Unknown / DB miss or GREASE variation")

    ua_present = bool(user_agent and user_agent.strip())
    ua_lower = user_agent.lower() if ua_present else ""
    looks_python = ("python" in ua_lower) or ("requests" in ua_lower) or ("urllib3" in ua_lower)

    # ---- Print Organized Report ----
    line = "=" * 76
    print(line)
    print("TLS Fingerprint Report (tls.peet.ws/api/all)")
    print(line)

    print("\n[1] Transport / Request")
    print("-" * 76)
    print_kv("HTTP version", http_version)
    print_kv("Method", method)
    print_kv("User-Agent", user_agent)

    print("\n[2] TLS Fingerprints (JA3 / JA4)")
    print("-" * 76)
    print_kv("JA3", ja3, wrap_width=88)
    print_kv("JA3 Hash", ja3_hash)
    print_kv("JA4", ja4)
    print_kv("JA4 (raw)", ja4_r, wrap_width=88)

    print("\n[3] PeetPrint Fingerprint")
    print("-" * 76)
    print_kv("PeetPrint", peetprint, wrap_width=88)
    print_kv("PeetPrint Hash", peetprint_hash)

    print("\n[4] Akamai HTTP/2 Fingerprint")
    print("-" * 76)
    if akamai_fp:
        print_kv("Akamai Fingerprint", akamai_fp, wrap_width=88)
        print_kv("Akamai Fingerprint Hash", akamai_fp_hash)
    else:
        print("Akamai Fingerprint: (empty / not provided)")
        print("  This often means the HTTP/2 fingerprint data was not produced reliably for this request.")

    print("\n[5] Heuristics / Detection Signals")
    print("-" * 76)
    print_kv("GREASE detected values", ", ".join(map(str, grease_values)) if grease_values else "(none)")

    if grease_values:
        print("GREASE STATUS: DETECTED")
        print(f"  Values ({len(grease_values)}): {grease_values}")
    else:
        print("GREASE STATUS: ❌ NOT DETECTED")
        print("  Heuristic note: can indicate a non-browser/static client, but it's NOT VPN proof.")

    print("\nDatabase Match (exact JA3 lookup):")
    print("-" * 76)
    print(db_match)

    print("\n[6] Consistency / VPN Relevance (Heuristic Only)")
    print("-" * 76)
    if not ua_present:
        print("⚠️ Low confidence: User-Agent missing/blank; consistency checks are unreliable.")
    else:
        if looks_python and grease_values:
            print("⚠️ Note: UA looks like Python, but GREASE detected.")
            print("  This can happen depending on TLS stack/implementation; not definitive.")
        elif (not looks_python) and ("python" in db_match.lower()):
            print("🚨 Inconsistency: UA doesn't look Python, but DB match suggests Python (heuristic).")
            print("  Treat as low confidence; DB exact-string matching is brittle.")
        else:
            print("🟢 Consistency looks reasonable for the observed client stack.")
            print("  Still: fingerprints alone are not reliable proof of VPN on/off.")

    print("\n" + line)


if __name__ == "__main__":
    try:
        run_deep_analysis()
    except httpx.HTTPError as e:
        print(f"❌ HTTP error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")