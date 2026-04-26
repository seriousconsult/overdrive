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


Also uses raw TLS ClientHello details from the API when present:
  negotiated/record version, cipher list size, extension list, supported_groups
  (curves), and signature_algorithms — as extra consistency checks vs User-Agent.

Deep TLS Fingerprint Analysis (JA3 + JA4 + PeetPrint + Akamai + TLS shape) using tls.peet.ws.

Composite score is an **automation signal**: **1** ≈ normal user browser, **5** ≈ script, bot, or
library/VPN-style TLS (including a browser UA that does not match the handshake).

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


TLS_VERSION_HEX = {
    "772": "TLS 1.3",
    "771": "TLS 1.2",
    "770": "TLS 1.1",
    "769": "TLS 1.0",
    "768": "SSL 3.0",
}


def _tls_version_label(hex_code: str | int | None) -> str | None:
    if hex_code is None:
        return None
    key = str(hex_code).strip()
    return TLS_VERSION_HEX.get(key, f"0x{key}" if key.isdigit() else key)


def extract_tls_clienthello_details(tls: dict | None) -> dict:
    """
    Normalize tls.peet.ws `tls` object: versions, cipher/extension counts,
    curves (supported_groups), signature_algorithms count, advertised versions.
    """
    out: dict = {
        "negotiated_label": None,
        "record_label": None,
        "cipher_count": 0,
        "extension_count": 0,
        "extension_names": [],
        "curves": [],
        "sigalg_count": 0,
        "supported_versions": [],
    }
    if not tls or not isinstance(tls, dict):
        return out

    out["negotiated_label"] = _tls_version_label(tls.get("tls_version_negotiated"))
    out["record_label"] = _tls_version_label(tls.get("tls_version_record"))
    ciphers = tls.get("ciphers") or []
    out["cipher_count"] = len(ciphers) if isinstance(ciphers, list) else 0

    exts = tls.get("extensions") or []
    if not isinstance(exts, list):
        return out

    out["extension_count"] = len(exts)
    names: list[str] = []
    curves: list[str] = []
    sig_max = 0
    versions: list[str] = []

    for e in exts:
        if not isinstance(e, dict):
            continue
        raw_name = e.get("name")
        if raw_name:
            names.append(str(raw_name).split("(")[0].strip())
        for g in e.get("supported_groups") or []:
            curves.append(str(g))
        sa = e.get("signature_algorithms")
        if isinstance(sa, list):
            sig_max = max(sig_max, len(sa))
        for v in e.get("versions") or []:
            versions.append(str(v))

    out["extension_names"] = names
    out["curves"] = curves
    out["sigalg_count"] = sig_max
    out["supported_versions"] = versions
    return out


def _tls_shape_automation_like(d: dict) -> bool:
    """Narrow / legacy ClientHello often seen on scripted TLS stacks."""
    neg = d.get("negotiated_label") or ""
    if "1.0" in neg or "1.1" in neg or "SSL 3" in neg:
        return True
    cc = d.get("cipher_count") or 0
    ec = d.get("extension_count") or 0
    if cc and cc < 16:
        return True
    if ec and ec < 6:
        return True
    sg = d.get("sigalg_count") or 0
    if sg and sg < 6:
        return True
    return False


def _tls_shape_modern_browser_like(d: dict) -> bool:
    """Broad TLS 1.3 ClientHello with rich offers (typical current browsers)."""
    if d.get("negotiated_label") != "TLS 1.3":
        return False
    cc = d.get("cipher_count") or 0
    ec = d.get("extension_count") or 0
    if cc and cc < 20:
        return False
    if ec and ec < 8:
        return False
    return True


def calculate_fingerprint_score(
    user_agent: str,
    *,
    ja3: str = "",
    ja3_hash: str = "",
    ja4: str = "",
    ja4_r: str = "",
    peetprint_hash: str = "",
    akamai_fingerprint: str = "",
    tls: dict | None = None,
):
    """
    Automation / VPN–client signal (1–5). **Higher = more script, bot, or VPN-library-like.**

      1 — Looks like a normal end-user browser (TLS + HTTP/2 line up with typical browsers).
      5 — Strong script / automation / library TLS (or a browser UA that does not match the TLS stack).

    Uses JA3 / JA4 / PeetPrint, GREASE, Akamai HTTP/2 SETTINGS, and ClientHello shape from tls.peet.ws.

    Returns (score, breakdown dict) for printing.
    """
    ua_lower = (user_agent or "").lower()
    is_python_ua = any(
        x in ua_lower
        for x in (
            "python",
            "httpx",
            "urllib",
            "requests",
            "aiohttp",
            "curl/",
            "java/",
            "go-http",
        )
    )
    ua_browser = any(
        x in ua_lower
        for x in ("chrome/", "mozilla/", "firefox/", "safari/", "edg/", "webkit/")
    )

    library_tls = _looks_library_tls(ja3_hash, peetprint_hash, ja4)
    grease_values = detect_grease_from_ja3(ja3)

    ak = _parse_akamai_fingerprint_settings(akamai_fingerprint)
    h2_style = _http2_browser_vs_library(ak.get("header_table_size"))
    akamai_present = bool(akamai_fingerprint and akamai_fingerprint.strip())

    tls_d = extract_tls_clienthello_details(tls)
    has_tls_shape = bool(
        tls and isinstance(tls, dict) and (tls_d.get("cipher_count") or tls_d.get("extension_count"))
    )

    # risk: 1 = normal browser, 5 = script / bot / VPN-library stack
    if is_python_ua:
        if library_tls:
            risk = 5
            base_reason = (
                "Declared script/library UA matches known automation TLS fingerprints (JA3/PeetPrint/JA4)."
            )
        else:
            risk = 4
            base_reason = (
                "Declared script UA; TLS is not a catalogued library hash (custom stack or rare build)."
            )
    elif ua_browser:
        if library_tls:
            risk = 5
            base_reason = (
                "Browser User-Agent but TLS matches library/VPN-style fingerprints — likely spoofed UA "
                "or VPN client pretending to be a browser."
            )
        else:
            risk = 2
            base_reason = (
                "Browser UA and TLS is not a known library hash — plausibly a real browser."
            )
    else:
        if library_tls:
            risk = 4
            base_reason = (
                "TLS matches automation/library fingerprints; UA is not clearly a browser or script."
            )
        else:
            risk = 3
            base_reason = "Neutral UA; TLS is not a known library fingerprint."

    breakdown = {
        "base": base_reason,
        "grease": "",
        "akamai": "",
        "ja4_note": "",
        "tls_shape": "",
    }

    if ja4_r and not ja4:
        breakdown["ja4_note"] = "JA4 raw present but short JA4 empty — using other signals."

    # --- ClientHello shape (before GREASE so “modern browser” can land at 1) ---
    if has_tls_shape:
        breakdown["tls_shape"] = (
            f"Negotiated {tls_d.get('negotiated_label') or '?'}, "
            f"record {tls_d.get('record_label') or '?'}, "
            f"{tls_d['cipher_count']} ciphers, {tls_d['extension_count']} extensions, "
            f"{tls_d['sigalg_count']} sig algs, {len(tls_d['curves'])} curves offered."
        )
        if tls_d.get("supported_versions"):
            breakdown["tls_shape"] += f" Advertised: {', '.join(tls_d['supported_versions'][:6])}."

        if ua_browser and not library_tls:
            if _tls_shape_automation_like(tls_d):
                risk = max(risk, 4)
                breakdown["tls_shape"] += (
                    " Narrow/legacy ClientHello — unlike typical current browsers; raises automation signal."
                )
            elif _tls_shape_modern_browser_like(tls_d):
                risk = min(risk, 1)
                breakdown["tls_shape"] += " Broad TLS 1.3 ClientHello — typical of modern browsers."
        elif ua_browser and library_tls:
            if _tls_shape_modern_browser_like(tls_d):
                risk = 5
                breakdown["tls_shape"] += (
                    " Handshake looks “browser-fat” but fingerprints are library-class — strong spoof/VPN signal."
                )
            elif _tls_shape_automation_like(tls_d):
                risk = max(risk, 4)
                breakdown["tls_shape"] += " Thin/legacy hello plus library JA3 — consistent with non-browser stack."
        elif is_python_ua:
            if _tls_shape_automation_like(tls_d) and library_tls:
                risk = 5
                breakdown["tls_shape"] += " Narrow handshake matches script stack + library fingerprint."
            elif _tls_shape_modern_browser_like(tls_d) and not library_tls:
                risk = min(risk, 3)
                breakdown["tls_shape"] += " Browser-shaped hello with script UA but non-catalogued JA3 — ambiguous."
    elif tls and isinstance(tls, dict):
        breakdown["tls_shape"] = "TLS object present but no ciphers/extensions parsed."
    else:
        breakdown["tls_shape"] = "No TLS detail blob passed; ClientHello shape not scored."

    # --- Akamai HTTP/2 SETTINGS ---
    if not akamai_present:
        breakdown["akamai"] = "Akamai HTTP/2 fingerprint missing — HTTP/2 layer not scored."
    else:
        breakdown["akamai"] = f"HTTP/2 SETTINGS heuristic: {h2_style}."
        if ua_browser and not library_tls:
            if h2_style.startswith("library-like"):
                risk = max(risk, 4)
                breakdown["akamai"] += (
                    " Library-like HTTP/2 SETTINGS despite browser UA — common for httpx/curl-class over H2."
                )
            elif h2_style.startswith("browser-like"):
                risk = min(risk, 2)
                breakdown["akamai"] += " Browser-like HTTP/2 SETTINGS."
        elif is_python_ua and h2_style.startswith("library-like") and library_tls:
            risk = max(risk, 5)
            breakdown["akamai"] += " Script UA + library TLS + library-like HTTP/2 — aligned automation stack."

    # --- GREASE: Chromium-class browsers usually send GREASE ---
    if grease_values:
        breakdown["grease"] = (
            f"GREASE in ClientHello ({len(grease_values)} values) — typical of many real browsers."
        )
        if ua_browser and not library_tls:
            risk = min(risk, 2)
    else:
        breakdown["grease"] = "No GREASE parsed from JA3 — more common in minimal / library TLS stacks."
        if ua_browser and not library_tls and not (has_tls_shape and _tls_shape_modern_browser_like(tls_d)):
            risk = max(risk, 2)

    risk = max(1, min(5, risk))
    return risk, breakdown

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
        tls=tls,
    )

    print("\n" + "="*45)
    print("Scale: 1 = normal browser · 5 = script/bot/VPN-library TLS")
    print(f"SCORE: {score} (JA3 + JA4 + PeetPrint + GREASE + Akamai + TLS shape)")
    print(f"  • {br['base']}")
    print(f"  • {br['grease']}")
    print(f"  • {br['akamai']}")
    if br.get("tls_shape"):
        print(f"  • {br['tls_shape']}")
    if br.get("ja4_note"):
        print(f"  • {br['ja4_note']}")
    
    messages = {
        1: "NORMAL: Looks like a typical end-user browser (TLS / HTTP2 / ClientHello).",
        2: "MOSTLY NORMAL: Small anomalies; still plausibly a real browser.",
        3: "UNCERTAIN: Mixed or incomplete fingerprint signals.",
        4: "SUSPICIOUS: Library TLS, HTTP/2 mismatch, or thin ClientHello vs browser UA.",
        5: "AUTOMATION / BOT / VPN-CLIENT LIKELY: Script stack or browser UA with library fingerprints.",
    }
    
    # Intentionally do not print a standalone STATUS here: `run_all_detections.py` uses the
    # *last* SCORE line and the following few lines; this module prints a second SCORE later
    # in the full report, and STATUS should attach to that final composite score.
    print(f"ROLLUP: {messages.get(score)}")
    print("="*45)
    
    if score >= 4:
        print(
            "🚨 High score: traffic looks like a script, bot, or VPN/library TLS — "
            "not a normal home browser fingerprint."
        )



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

    tls_details = extract_tls_clienthello_details(tls)
    print("\n[4] TLS ClientHello (version / ciphers / extensions / curves / sigalgs)")
    print("-" * 76)
    print_kv("TLS version (record)", tls_details.get("record_label") or tls.get("tls_version_record"))
    print_kv("TLS version (negotiated)", tls_details.get("negotiated_label") or tls.get("tls_version_negotiated"))
    ciphers = tls.get("ciphers") or []
    print_kv("Cipher suites (count)", str(len(ciphers)) if isinstance(ciphers, list) else "0")
    print_kv("Extensions (count)", str(tls_details["extension_count"]))
    print_kv("Signature algorithms (count)", str(tls_details["sigalg_count"]))
    if tls_details["supported_versions"]:
        print_kv("Supported versions (ext)", ", ".join(tls_details["supported_versions"]))
    if tls_details["curves"]:
        curves_line = ", ".join(tls_details["curves"][:12])
        if len(tls_details["curves"]) > 12:
            curves_line += f" … (+{len(tls_details['curves']) - 12} more)"
        print_kv("Supported groups (curves)", curves_line, wrap_width=88)
    else:
        print_kv("Supported groups (curves)", "(none parsed)")
    if tls_details["extension_names"]:
        en = ", ".join(tls_details["extension_names"][:10])
        if len(tls_details["extension_names"]) > 10:
            en += f" … (+{len(tls_details['extension_names']) - 10} more)"
        print_kv("Extension names (sample)", en, wrap_width=88)

    print("\n[5] Akamai HTTP/2 Fingerprint")
    print("-" * 76)
    if akamai_fp:
        print_kv("Akamai Fingerprint", akamai_fp, wrap_width=88)
        print_kv("Akamai Fingerprint Hash", akamai_fp_hash)
    else:
        print("Akamai Fingerprint: (empty / not provided)")
        print("  This often means the HTTP/2 fingerprint data was not produced reliably for this request.")

    print("\n[6] Heuristics / Detection Signals")
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
        tls=tls,
    )

    print("\n[7] Composite score (JA3 + JA4 + PeetPrint + GREASE + Akamai + TLS shape)")
    print("-" * 76)
    print("  Scale: 1 = normal browser fingerprint · 5 = script / bot / VPN-library-like")
    print(f"SCORE: {composite}")
    messages = {
        1: "NORMAL: Looks like a typical end-user browser (TLS / HTTP2 / ClientHello).",
        2: "MOSTLY NORMAL: Small anomalies; still plausibly a real browser.",
        3: "UNCERTAIN: Mixed or incomplete fingerprint signals.",
        4: "SUSPICIOUS: Library TLS, HTTP/2 mismatch, or thin ClientHello vs browser UA.",
        5: "AUTOMATION / BOT / VPN-CLIENT LIKELY: Script stack or browser UA with library fingerprints.",
    }
    # Keep this on one line so HTML reports / batch runners can grab it as the STATUS comment.
    print(
        "STATUS: "
        + f"{messages.get(composite) or 'UNKNOWN:'} — {br.get('base') or ''}".strip(" —")
    )
    print(f"  • {br['base']}")
    print(f"  • {br['grease']}")
    print(f"  • {br['akamai']}")
    if br.get("tls_shape"):
        print(f"  • {br['tls_shape']}")
    if br.get("ja4_note"):
        print(f"  • {br['ja4_note']}")

    print("\n[8] Consistency / VPN Relevance (Heuristic Only)")
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