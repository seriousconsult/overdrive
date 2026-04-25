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



Deep TLS Fingerprint Analysis (JA3 + JA4 + PeetPrint + Akamai) using tls.peet.ws

Output is formatted into clear sections with wrapped long fields.
'''

import re
import httpx


GREASE_DECIMALS = {
    2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
    35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250
}



# Known TLS fingerprints for common Python HTTP stacks (extend as needed).
PYTHON_JA3_HASHES = {
    "3adacb99ecb51ed59c4f6c4ed9a7dcaa",  # httpx
    "764949511634563a62f4007f9c89420a",  # requests
    "ee99e69123896791e84610996841edaa",  # urllib3
}
# PeetPrint hashes for the same stacks (tls.peet.ws); fill when you capture them.
PYTHON_PEETPRINT_HASHES: set[str] = set()
# Full JA4 strings (Salesforce JA4) for library clients, if you catalog them.
PYTHON_JA4_STRINGS: set[str] = set()


def _parse_akamai_fingerprint_settings(akamai_fp: str):
    """SETTINGS prefix of Akamai HTTP/2 fingerprint: '1:4096;2:0;4:65535|...'."""
    if not akamai_fp:
        return {}
    left = akamai_fp.split("|", 1)[0]
    kv = {}
    for part in left.split(";"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        k, v = part.split(":", 1)
        k, v = k.strip(), v.strip()
        if k.isdigit():
            try:
                kv[int(k)] = int(v)
            except ValueError:
                pass
    return {"header_table_size": kv.get(1), "settings_kv": kv}


def _http2_browser_vs_library(header_table_size: int | None) -> str:
    if header_table_size is None:
        return "unknown"
    if header_table_size >= 32768:
        return "browser-like (heuristic)"
    if header_table_size <= 8192:
        return "library-like (heuristic)"
    return "mixed (heuristic)"


def _looks_library_tls(ja3_hash: str, peetprint_hash: str, ja4: str) -> bool:
    if ja3_hash in PYTHON_JA3_HASHES:
        return True
    if peetprint_hash and peetprint_hash in PYTHON_PEETPRINT_HASHES:
        return True
    if ja4 and ja4 in PYTHON_JA4_STRINGS:
        return True
    return False


def calculate_fingerprint_score(
    user_agent: str,
    *,
    ja3: str = "",
    ja3_hash: str = "",
    ja4: str = "",
    ja4_r: str = "",
    peetprint_hash: str = "",
    akamai_fingerprint: str = "",
):
    """
    Composite 1–5 score using JA3, JA4, PeetPrint, GREASE (via JA3 string), and
    Akamai HTTP/2 SETTINGS heuristics. Higher = more consistent / less “lying”.

    Returns (score, breakdown dict) for printing.
    """
    ua_lower = (user_agent or "").lower()
    is_python_ua = "python" in ua_lower or "httpx" in ua_lower
    ua_browser = "chrome" in ua_lower or "mozilla" in ua_lower

    library_tls = _looks_library_tls(ja3_hash, peetprint_hash, ja4)
    grease_values = detect_grease_from_ja3(ja3)

    ak = _parse_akamai_fingerprint_settings(akamai_fingerprint)
    h2_style = _http2_browser_vs_library(ak.get("header_table_size"))
    akamai_present = bool(akamai_fingerprint and akamai_fingerprint.strip())

    # --- Base score from UA vs library TLS fingerprints (JA3 / PeetPrint / JA4) ---
    if is_python_ua and library_tls:
        score = 5
        base_reason = "UA and TLS fingerprints align with a script/library stack."
    elif ua_browser:
        if library_tls:
            score = 1
            base_reason = "UA claims a browser but TLS looks like a library/automation stack."
        else:
            score = 4
            base_reason = "Browser UA with no library TLS match (fingerprints still vary)."
    elif not is_python_ua and library_tls:
        score = 2
        base_reason = "TLS looks library-like but UA is not clearly Python/httpx."
    else:
        score = 3
        base_reason = "Neutral: no strong library TLS match."

    breakdown = {
        "base": base_reason,
        "grease": "",
        "akamai": "",
        "ja4_note": "",
    }

    # --- GREASE: common on real browsers; nudges ambiguous cases toward “browser-like” ---
    if ua_browser and grease_values and not library_tls:
        if score == 3:
            score = 4
            breakdown["grease"] = "GREASE in ClientHello + browser UA → slight bump (typical browser behavior)."
        else:
            breakdown["grease"] = f"GREASE values present ({len(grease_values)}); consistent with many browsers."
    elif grease_values:
        breakdown["grease"] = f"GREASE detected ({len(grease_values)} values); not a VPN proof on its own."
    else:
        breakdown["grease"] = "No GREASE values parsed from JA3 string."

    if ja4_r and not ja4:
        breakdown["ja4_note"] = "JA4 raw present but short JA4 empty — using other signals."

    # --- Akamai HTTP/2 fingerprint: SETTINGS vs claimed UA ---
    if not akamai_present:
        breakdown["akamai"] = "Akamai HTTP/2 fingerprint missing — HTTP/2 layer not scored."
    else:
        breakdown["akamai"] = f"HTTP/2 SETTINGS heuristic: {h2_style}."
        if ua_browser:
            if h2_style.startswith("library-like"):
                score = min(score, 2)
                breakdown["akamai"] += " Browser UA but library-like HTTP/2 — strong mismatch."
            elif h2_style.startswith("browser-like") and score == 3 and not library_tls:
                score = 4
                breakdown["akamai"] += " Browser-like HTTP/2 aligns with browser UA."
        elif is_python_ua and h2_style.startswith("library-like") and library_tls:
            score = max(score, 5)
            breakdown["akamai"] += " Python UA + library TLS + library-like HTTP/2 — consistent."

    score = max(1, min(5, score))
    return score, breakdown

def run_deep_analysis():
    url = "https://tls.peet.ws/api/all"

    with httpx.Client(http2=True, timeout=20) as client:
        resp = client.get(url)
        data = resp.json()

    tls = data.get("tls", {}) or {}
    http2 = data.get("http2", {}) or {}
    user_agent = data.get("user_agent", "Unknown")

    score, br = calculate_fingerprint_score(
        user_agent,
        ja3=tls.get("ja3", "") or "",
        ja3_hash=tls.get("ja3_hash", "") or "",
        ja4=tls.get("ja4", "") or "",
        ja4_r=tls.get("ja4_r", "") or "",
        peetprint_hash=tls.get("peetprint_hash", "") or "",
        akamai_fingerprint=http2.get("akamai_fingerprint", "") or "",
    )

    print("\n" + "="*45)
    print(f"SCORE: {score} (JA3 + JA4 + PeetPrint + GREASE + Akamai)")
    print(f"  • {br['base']}")
    print(f"  • {br['grease']}")
    print(f"  • {br['akamai']}")
    if br.get("ja4_note"):
        print(f"  • {br['ja4_note']}")
    
    messages = {
        5: "CONSISTENT: Fingerprint matches the declared User-Agent.",
        4: "NORMAL: Standard browser handshake detected.",
        3: "NEUTRAL: Fingerprint is unrecognized.",
        2: "SUSPICIOUS: Handshake does not match common browser patterns.",
        1: "MISMATCH: User-Agent is lying! (Bot/VPN Detection Triggered)."
    }
    
    print(f" STATUS: {messages.get(score)}")
    print("="*45)
    
    if score == 1:
        print("🚨 Warning: If you were trying to hide, the server just caught you.")



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


def run_deep_analysis2():
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

    composite, br = calculate_fingerprint_score(
        user_agent,
        ja3=ja3,
        ja3_hash=ja3_hash,
        ja4=ja4,
        ja4_r=ja4_r,
        peetprint_hash=peetprint_hash,
        akamai_fingerprint=akamai_fp,
    )

    print("\n[6] Composite score (JA3 + JA4 + PeetPrint + GREASE + Akamai)")
    print("-" * 76)
    print(f"SCORE: {composite}")
    print(f"  • {br['base']}")
    print(f"  • {br['grease']}")
    print(f"  • {br['akamai']}")
    if br.get("ja4_note"):
        print(f"  • {br['ja4_note']}")

    print("\n[7] Consistency / VPN Relevance (Heuristic Only)")
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
        run_deep_analysis2()
    except httpx.HTTPError as e:
        print(f"❌ HTTP error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")