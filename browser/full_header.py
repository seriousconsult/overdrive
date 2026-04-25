#!/usr/bin/env python3
"""
Full HTTP request header + Client Hints consistency (browser)

Uses Selenium (Chromium) to perform a top-level navigation to a public echo endpoint
and inspects the **same** headers the real browser would send. Validates
User-Agent, **Sec-Fetch-*** (Mode / Site / User / Dest and combo vs request host),
**Sec-CH-UA*** (incl. Full-Version-List, Arch, Bitness, Form-Factors when present),
**grease/brand** structure, and common request lines (**Accept**, **Accept-Language**,
**Accept-Encoding**, **Upgrade-Insecure-Requests**, **DNT**, **Connection**,
**Cache-Control**, **Origin** / **Referer** where applicable).

Score (1–5, higher = more suspicious / inconsistent)
  1 — Coherent: UA, Sec-Fetch, and CH (when applicable) line up
  2 — Minor oddities; still plausibly a normal browser
  3 — Several mismatches or unclear (partial data, odd combo)
  4 — Strong signs of incoherent or non-browser / patched stack
  5 — Severe inconsistency (e.g. CH vs UA platform/version, mobile flag)

This does not replace TLS / JA3 checks (see vpn/TLS_handshake.py for transport-layer
signals). Optional: re-run in headed mode to compare with your UI profile.

Echo URLs (tried in order):
  - https://httpbin.org/get
  - https://postman-echo.com/get
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

# Selenium (same pattern as WebRTC.py)
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

ECHO_URLS = (
    "https://httpbin.org/get",
    "https://postman-echo.com/get",
)
TIMEOUT = 25


def _issue_weight(msg: str) -> int:
    m = msg.lower()
    if "non-browser" in m or "user-agent names" in m:
        return 50
    if "differ" in m and "version" in m:
        return 20
    if "platform" in m and "sec-ch" in m:
        return 22
    if "does not match" in m and "sec-ch" in m:
        return 24
    if "empty user-agent" in m:
        return 28
    if "sec-ch" in m and "missing" in m:
        return 12
    if "sec-fetch" in m and "unusual" in m:
        return 7
    if "sec-fetch" in m and "omit" in m:
        return 3
    if "sec-fetch" in m:
        return 8
    if "accept" in m and "language" in m:
        return 7
    if "accept-encoding" in m or "accept" in m:
        return 6
    if "sec-fetch-user" in m or "sec-fetch-site" in m:
        return 7
    if "grease" in m or "brand ent" in m or "chromium product" in m:
        return 6
    if "arch" in m or "bitness" in m or "form-factor" in m:
        return 9
    if "full-version" in m:
        return 8
    if "origin" in m and "get" in m:
        return 10
    if "dnt" in m or "upgrade-insecure" in m or "connection" in m:
        return 5
    return 5
UA_CHROME = re.compile(r"Chrome/(\d+)(?:\.\d+)*", re.I)
UA_EDG = re.compile(r"Edg/(\d+)(?:\.\d+)*", re.I)
# Semicolon-delimited "Brand";v="NN" pieces inside Sec-CH-UA
CH_any_ver = re.compile(r';v="(\d+)"')


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


def _norm_headers(raw: dict[str, str]) -> dict[str, str]:
    return {k.lower(): str(v) for k, v in raw.items()}


def _unwrap_ch_string(value: str) -> str:
    s = (value or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        s = s[1:-1]
    s = s.replace('\\"', '"')
    return s


def _browser_family(ua: str) -> str:
    u = ua or ""
    if re.search(r"\bEdg/\d", u):
        return "chromium"
    if "Chrome/" in u and "Edg" not in u:
        if "Chromium" in u or re.search(r"Chrome/\d", u):
            return "chromium"
    if "Firefox/" in u and "Chrome" not in u:
        return "firefox"
    if "Safari/" in u and "Chrome" not in u and "Chromium" not in u:
        return "webkit"
    if "Chrome" in u or "Chromium" in u:
        return "chromium"
    return "unknown"


def _ua_chrome_major(ua: str) -> int | None:
    m = UA_EDG.search(ua) or UA_CHROME.search(ua)
    if m:
        return int(m.group(1))
    return None


def _sec_ch_ua_max_brand_version(sec_ch: str) -> int | None:
    best: int | None = None
    for m in CH_any_ver.finditer(sec_ch):
        try:
            v = int(m.group(1))
            if best is None or v > best:
                best = v
        except ValueError:
            continue
    return best


def _sec_ch_ua_product_major(sec_ch: str) -> int | None:
    """First Chrome / Chromium / Edge major in Sec-CH-UA (avoids using grease/Not-A-Brand for UA compare)."""
    for name in ("Google Chrome", "Chromium", "Microsoft Edge"):
        m = re.search(rf'"{re.escape(name)}"\s*;\s*v="(\d+)"', sec_ch, re.I)
        if m:
            return int(m.group(1))
    for name in ("Opera", "Brave", "Oculus Browser"):
        m = re.search(rf'"{re.escape(name)}"\s*;\s*v="(\d+)"', sec_ch, re.I)
        if m:
            return int(m.group(1))
    return None


def _platform_from_ua(ua: str) -> str | None:
    if re.search(r"Windows|Win64|WOW64", ua, re.I):
        return "windows"
    if "Android" in ua:
        return "android"
    if re.search(r"iPhone|iPad|iPod", ua):
        return "ios"
    if "Macintosh" in ua or "Mac OS" in ua:
        return "macos"
    if "Linux" in ua and "Android" not in ua:
        return "linux"
    return None


def _platform_from_ch(ch_platform_raw: str) -> str | None:
    s = _unwrap_ch_string(ch_platform_raw).lower()
    if "windows" in s:
        return "windows"
    if "android" in s:
        return "android"
    if "iphone" in s or "ipad" in s or "ios" in s:
        return "ios"
    if "linux" in s and "android" not in s:
        return "linux"
    if "mac" in s or "macos" in s:
        return "macos"
    if "cros" in s or "chrome os" in s or "chromeos" in s:
        return "chromeos"
    return None


# --- Extended validation (standard headers, Sec-Fetch-*, full CH, brand rules) ---

_VALID_SEC_FETCH_SITE = frozenset({"same-origin", "same-site", "cross-site", "none"})


def _check_general_headers(ua: str, h: dict[str, str], *, sfm: str, sfd: str, request_https: bool) -> list[str]:
    """Accept-Language, Accept-Encoding, UIR, DNT, Connection, Cache-Control, Origin, Referer."""
    issues: list[str] = []

    al = h.get("accept-language", "")
    if not al.strip():
        issues.append("Accept-Language missing (real browsers send it virtually always)")
    elif not re.search(r"^[a-z*]", al.strip(), re.I):
        issues.append(f"Accept-Language {al[:40]!r}… has an unexpected lead token")

    ae = (h.get("accept-encoding", "") or "").lower()
    if sfm == "navigate" and sfd in ("", "document"):
        if "gzip" not in ae:
            issues.append("Accept-Encoding does not mention gzip (unusual for Chromium navigation)")
        if not any(x in ae for x in ("br", "brotli", "zstd", "deflate")) and _ua_chrome_major(ua) not in (None, 0):
            if (_ua_chrome_major(ua) or 0) >= 100:
                issues.append(
                    "Accept-Encoding: no br/deflate/zstd (possible but less typical for current Chrome); "
                    "low severity if intentional"
                )

    uir = (h.get("upgrade-insecure-requests", "") or "").strip()
    if uir and uir not in ("1",):
        if request_https and sfm == "navigate" and sfd in ("", "document"):
            issues.append(
                f"Upgrade-Insecure-Requests={uir!r} (expected 1 on HTTPS navigation; or omit header entirely)"
            )
        else:
            issues.append(f"Upgrade-Insecure-Requests={uir!r} (expected 1 or omitted)")

    dnt = (h.get("dnt", "") or "").strip()
    if dnt and dnt not in ("0", "1", "null"):
        issues.append(f"DNT has unexpected value {dnt!r} (use 0, 1, or null)")

    conn = (h.get("connection", "") or "").lower().strip()
    if conn == "close" and sfd == "document" and sfm == "navigate":
        issues.append("Connection: close on a top-level document GET (browsers more often use keep-alive or omit on HTTP/2)")

    cc = h.get("cache-control", "")
    if cc and re.fullmatch(r"no-cache", cc.strip(), flags=re.I) and h.get("pragma", "").lower() == "no-cache":
        pass

    orig = h.get("origin", "")
    if orig.strip() and sfm == "navigate" and sfd in ("", "document"):
        issues.append(
            "Origin set on a top-level document GET (browsers usually omit; suggests scripted/fetch client)"
        )

    ref = h.get("referer", "")
    if ref.strip().lower() in ("null", "about:blank", "about:client"):
        issues.append("Referer is a null-ish sentinel (suspicious for a normal top-level page load)")

    return issues


def _check_sec_fetch_full(
    h: dict[str, str], *, sfm: str, sfd: str, request_host: str, _request_path: str = ""
) -> list[str]:
    """
    All five Sec-Fetch-* tokens and mutual consistency. ``request_host`` is the
    target host of the echo URL (e.g. httpbin.org), no port.
    """
    issues: list[str] = []
    ua0 = (h.get("user-agent", "") or "").lower()
    chromelike = "chrome" in ua0 or "chromium" in ua0 or "edg" in ua0
    sfs = (h.get("sec-fetch-site", "") or "").strip().lower()
    sdest = h.get("sec-fetch-dest", "")
    dest_l = sdest.lower() if sdest else ""
    suser = h.get("sec-fetch-user", "")
    sfs_user_l = suser.replace(" ", "").lower()

    if sfs and sfs not in _VALID_SEC_FETCH_SITE:
        issues.append(f"sec-fetch-site={sfs!r} (not one of: same-origin, same-site, cross-site, none)")

    if chromelike and sfm in ("navigate", "nested-navigate") and dest_l in ("document", ""):
        if sfs == "same-origin" and request_host:
            issues.append(
                f"sec-fetch-site=same-origin is implausible for a first navigation to a new host ({request_host!r}) "
                "from automation/blank"
            )
        if suser and sfs_user_l in ("?0", "false", "0"):
            issues.append(
                "sec-fetch-user suggests non–user-activated navigation (?0) for a top-level document load (automation/privacy?)"
            )
    if not chromelike and sfm in ("navigate",) and sfd in ("document",) and sfs:
        if suser and sfs_user_l in ("?0", "false", "0"):
            issues.append("sec-fetch-user ?0 for document navigation (check if expected for this engine)")
    return issues


def _ch_brand_tokens(sec_ch: str) -> list[tuple[str, str]]:
    """Parse \"Brand\";v=\"NN\" token pairs (best effort)."""
    out: list[tuple[str, str]] = []
    for m in re.finditer(
        r'"((?:\\.|[^"\\])*)";\s*v="((?:\\.|[^"\\])*)"(?:,|$)?',
        sec_ch,
    ):
        out.append((m.group(1).replace('\\"', '"'), m.group(2).replace("\\", "")))
    if not out:
        for m in re.finditer(r'"([^"]+)"\s*;\s*v="([^"]+)"', sec_ch):
            out.append((m.group(1), m.group(2)))
    return out


def _check_sec_ch_ua_grease_and_brands(sec_ch: str, ua_maj: int | None) -> list[str]:
    """
    Chromium grease entry (Not)A;Brand / Not?A?Brand) and at least one Chrome/Chromium/Edge.
    See https://www.chromium.org/updates/ua-reduction/ and UACH brand lists.
    """
    issues: list[str] = []
    if not (sec_ch or "").strip():
        return issues
    t = _ch_brand_tokens(sec_ch)
    if len(t) < 2:
        issues.append("Sec-CH-UA: fewer than two brand;v= pairs (atypical for Chromium)")

    names = " ".join(n.lower() for n, _ in t)
    if not re.search(
        r"google chrome|chromium|microsoft edg|microsoft edge|opr\/|opera|brave",
        names,
        re.I,
    ):
        issues.append("Sec-CH-UA: no obvious Chromium/Chrome/Edge/Opera/Brave product brand")

    has_grease = bool(
        re.search(r"not[);!\s=]*A[;!\?]*\s*Brand|not\?A\?Brand|chromium\?\?\?", sec_ch, re.I)
    )
    if not has_grease and "Not" in sec_ch and "Brand" in sec_ch:
        has_grease = True
    if not has_grease and ua_maj and ua_maj >= 90:
        issues.append("Sec-CH-UA: no grease/Not?A?Brand style token (expected in modern Chromium)")

    return issues


def _check_ch_full_list_and_extras(ua: str, h: dict[str, str], major_ua: int | None) -> list[str]:
    """
    sec-ch-ua-full-version-list vs Sec-CH-UA / UA; Arch/Bitness vs UA; Form-Factors vs mobile.
    """
    issues: list[str] = []
    fvl = h.get("sec-ch-ua-full-version-list", "")
    if fvl and major_ua is not None:
        vm = re.search(
            r'"(?:Google Chrome|Chromium|Microsoft Edge)"\s*;\s*v="(\d+)"', fvl, re.I
        )
        if vm:
            try:
                vgc = int(vm.group(1))
                if abs(vgc - major_ua) > 1:
                    issues.append(
                        f"sec-ch-ua-full-version-list product major ({vgc}) vs User-Agent major ({major_ua}) >1"
                    )
            except ValueError:
                pass
    ual = (ua or "").lower()
    arch = _unwrap_ch_string(h.get("sec-ch-ua-arch", "")).lower()
    if arch:
        if "arm" in arch and "arm" not in ual and "aarch64" not in ual and "woa" not in ual and "m1" not in ual and "m2" not in ual:
            if "windows" in ual or "win64" in ual or "x86" in ual or "intel" in ual or "x64" in ual:
                issues.append("sec-ch-ua-arch suggests ARM but User-Agent string looks x86-64/Intel-only")

    b_raw = h.get("sec-ch-ua-bitness", "")
    bstr = _unwrap_ch_string(b_raw)
    looks_32 = bool(re.search(r"\?32|[^0-9]32[^0-9]|\b32\b", bstr)) and not re.search(
        r"64", bstr
    )
    if looks_32 and "win64" in ual and re.search(r"x64|wow64|win64; x64", ual, re.I):
        issues.append("sec-ch-ua-bitness suggests 32-bit on a Win64/x64 User-Agent (inconsistent)")

    ff = h.get("sec-ch-ua-form-factors", "")
    mff = re.search(r"Mobile|EInk|Tablet|Desktop", _unwrap_ch_string(ff), re.I)
    has_mobile_ua = bool(
        re.search(
            r"Mobile|Android|iPhone|iPad",
            ua,
            re.I,
        )
    )
    if mff and mff.group(0).lower() in ("eink", "mobile", "tablet") and not has_mobile_ua and "?0" in (
        h.get("sec-ch-ua-mobile", "") or ""
    ):
        issues.append("sec-ch-ua-form-factors or mobile class vs desktop UA/CH-Mobile (?0) mismatch")

    return issues


def _issues_chromium(ua: str, h: dict[str, str], request_url: str = "") -> list[str]:
    issues: list[str] = []
    ulow = (ua or "").lower()

    if "python" in ulow or "curl/" in ulow or "httpie" in ulow:
        issues.append("User-Agent names a non-browser client (unexpected for Selenium)")

    if not ua.strip():
        issues.append("empty User-Agent")

    if _browser_family(ua) not in ("chromium", "unknown") and "Chrome" not in (ua or ""):
        return issues

    if "Chrome" not in ua and "Chromium" not in ua and "Edg" not in ua:
        return issues

    major_ua = _ua_chrome_major(ua)
    sec_ch = h.get("sec-ch-ua", "")
    sfm = h.get("sec-fetch-mode", "")
    sfd = h.get("sec-fetch-dest", "")

    if not sfm and "chrome" in ulow:
        issues.append("missing Sec-Fetch-Mode (unusual for Chromium top-level document request)")

    if sfd in ("script", "style", "cors", "object") and sfm in ("navigate", "nested-navigate"):
        issues.append(
            f"Sec-Fetch-Dest={sfd!r} is unusual for a top-level page navigation (expected document)"
        )

    if major_ua and major_ua >= 89 and not sec_ch.strip():
        issues.append("missing Sec-CH-UA (expected for Chromium 89+ on HTTPS)")

    if sec_ch and major_ua is not None:
        ch_prod = _sec_ch_ua_product_major(sec_ch)
        if ch_prod is not None and abs(ch_prod - major_ua) > 1:
            issues.append(
                f"Sec-CH-UA product brand major ({ch_prod}) vs User-Agent major ({major_ua}) differ by more than 1"
            )

    p_ua = _platform_from_ua(ua)
    p_ch = _platform_from_ch(h.get("sec-ch-ua-platform", ""))
    if p_ua and p_ch and p_ua != p_ch:
        if p_ua in ("ios", "macos") and p_ch in ("ios", "macos"):
            pass
        else:
            issues.append(
                f"sec-ch-ua-platform ({p_ch!s}) vs UA-inferred platform ({p_ua!s})"
            )

    m_ch = h.get("sec-ch-ua-mobile", "")
    mobile_ua = bool(
        re.search(
            r"Mobile|Android|iPhone|iPad|webOS|BlackBerry|IEMobile|Opera Mini",
            ua,
            re.I,
        )
    )
    is_mobile_tok = bool(m_ch and "?1" in m_ch)
    is_desk_tok = bool(m_ch and "?0" in m_ch)
    if m_ch and ((mobile_ua and is_desk_tok) or ((not mobile_ua) and is_mobile_tok)):
        issues.append("sec-ch-ua-mobile does not match mobile vs desktop User-Agent pattern")

    acc = h.get("accept", "")
    if acc and sfm == "navigate" and sfd in ("document", "empty", "") and "text/html" not in acc:
        issues.append("Accept does not request text/html for a document-like navigation")

    pu = urlparse(request_url) if request_url else None
    req_host = (pu.hostname or "") if pu else ""
    req_path = (pu.path or "/") if pu else "/"
    if not pu or not (getattr(pu, "scheme", None) or ""):
        req_https = True
    else:
        req_https = pu.scheme == "https"

    issues.extend(
        _check_general_headers(ua, h, sfm=sfm, sfd=sfd or "document", request_https=req_https)
    )
    issues.extend(
        _check_sec_fetch_full(
            h, sfm=sfm, sfd=sfd or "document", request_host=req_host, _request_path=req_path
        )
    )
    issues.extend(_check_sec_ch_ua_grease_and_brands(sec_ch, major_ua))
    issues.extend(_check_ch_full_list_and_extras(ua, h, major_ua))

    return issues


def _issues_firefox(ua: str, h: dict[str, str], request_url: str = "") -> list[str]:
    issues: list[str] = []
    if "python" in (ua or "").lower():
        issues.append("User-Agent names a non-browser client")
    if not h.get("accept"):
        issues.append("missing Accept (unusual)")

    if h.get("sec-ch-ua"):
        issues.append("Sec-CH-UA present on claimed Firefox (unexpected; UA spoof or embedded Chromium?)")
    sfm = h.get("sec-fetch-mode", "")
    sfd = h.get("sec-fetch-dest", "")
    if not sfm and "Firefox" in (ua or ""):
        issues.append("missing Sec-Fetch-Mode (Firefox may omit; low severity for document loads)")

    pu = urlparse(request_url) if request_url else None
    req_h = (pu.hostname or "") if pu else ""
    req_p = (pu.path or "/") if pu else "/"
    if not pu or not (getattr(pu, "scheme", None) or ""):
        req_https = True
    else:
        req_https = pu.scheme == "https"
    issues.extend(
        _check_general_headers(ua, h, sfm=sfm, sfd=sfd or "document", request_https=req_https)
    )
    issues.extend(
        _check_sec_fetch_full(
            h, sfm=sfm, sfd=sfd or "document", request_host=req_h, _request_path=req_p
        )
    )
    return issues


def analyze_headers(
    headers: dict[str, str], request_url: str | None = None
) -> tuple[int, str, list[str], dict[str, Any]]:
    """
    Returns (score, summary, issues, details).
    ``request_url`` is the page whose headers were captured (e.g. echo URL) for Sec-Fetch / Site heuristics.
    """
    h = _norm_headers(headers)
    ua = h.get("user-agent", "")

    family = _browser_family(ua)
    details: dict[str, Any] = {
        "browser_family": family,
        "user_agent": ua[:400],
        "header_names": sorted(h.keys()),
        "request_url": request_url,
    }

    rurl = request_url or ""
    if family == "chromium":
        iss = _issues_chromium(ua, h, rurl)
    elif family == "firefox":
        iss = _issues_firefox(ua, h, rurl)
    else:
        iss = _issues_chromium(ua, h, rurl) if "Chrome" in ua or "Chromium" in ua else []
        if family == "unknown" and not iss:
            iss = ["unknown browser family; limited Client Hints checks applied"]

    weight = sum(_issue_weight(m) for m in iss)

    if not iss and family in ("chromium", "firefox"):
        score = 1
    elif not iss and family in ("webkit", "unknown"):
        score = 2
    elif iss:
        w = int(min(100, weight))
        if w <= 12:
            score = 2
        elif w <= 30:
            score = 3
        elif w <= 55:
            score = 4
        else:
            score = 5
    else:
        score = 2

    if iss:
        summary = f"{len(iss)} issue(s). Worst: {iss[0]}"
    else:
        summary = "Request headers and Client Hints look internally consistent for the detected family."

    return score, summary, iss, details


def fetch_headers_via_browser() -> tuple[dict[str, str] | None, str | None, str | None]:
    last_err: str | None = None
    for url in ECHO_URLS:
        driver = None
        try:
            driver = build_driver()
            driver.get(url)
            wait = WebDriverWait(driver, TIMEOUT)
            pre = wait.until(EC.presence_of_element_located((By.TAG_NAME, "pre")))
            text = pre.text
            data = json.loads(text)
            hdrs: dict[str, str] = {}
            if "headers" in data:
                hdrs = {str(k): str(v) for k, v in data["headers"].items()}
            else:
                last_err = f"{url}: no 'headers' in JSON"
                continue
            return hdrs, None, url
        except Exception as e:
            last_err = f"{url}: {type(e).__name__}: {e}"
            continue
        finally:
            if driver is not None:
                try:
                    driver.quit()
                except Exception:
                    pass
    return None, last_err, None


def check_full_header_consistency() -> tuple[int, str]:
    hdrs, err, echo_url = fetch_headers_via_browser()
    if not hdrs:
        return 3, f"Could not load echo page or parse headers. {err or 'unknown error'}"

    score, summary, issues, _details = analyze_headers(hdrs, echo_url)
    parts: list[str] = [summary, f"echo={echo_url or '?'}"]
    for i, msg in enumerate(issues[:5], 1):
        parts.append(f"issue {i}: {msg}")
    if len(issues) > 5:
        parts.append(f"… and {len(issues) - 5} more")
    return score, " | ".join(parts)


def main() -> None:
    print("=" * 64)
    print("Full header + Client Hints consistency (Selenium / echo endpoint)")
    print("=" * 64)
    print()

    hdrs, err, echo_url = fetch_headers_via_browser()
    if not hdrs:
        print("SCORE: 3")
        print(f"STATUS: Could not obtain browser headers. {err or 'unknown error'}")
        print()
        print("=" * 64)
        return

    h = _norm_headers(hdrs)
    score, summary, issues, details = analyze_headers(hdrs, echo_url)

    print(f"Echo URL:  {echo_url}")
    print(f"User-Agent: {details.get('user_agent', 'N/A')!s}")
    print(f"Family:     {details.get('browser_family', '?')}")
    print()
    std_keys = [
        k
        for k in (
            "accept",
            "accept-language",
            "accept-encoding",
            "upgrade-insecure-requests",
            "dnt",
            "connection",
            "cache-control",
            "referer",
            "origin",
        )
        if k in h
    ]
    if std_keys:
        print("Standard request-line headers (sample):")
        for k in std_keys:
            v = h[k]
            vdisp = (v[:120] + "…") if len(v) > 120 else v
            print(f"  {k}: {vdisp}")
        print()
    ch_keys = [k for k in sorted(h.keys()) if k.startswith("sec-ch-") or k.startswith("sec-fetch")]
    if ch_keys:
        print("Sec-Fetch- / Sec-CH-UA* headers (sample):")
        for k in ch_keys:
            v = h[k]
            vdisp = (v[:160] + "…") if len(v) > 160 else v
            print(f"  {k}: {vdisp}")
    else:
        print("(no sec-ch- / sec-fetch- headers seen in response)")
    print()
    if issues:
        for msg in issues:
            print(f"  — {msg}")
    else:
        print("  (no specific inconsistencies flagged)")
    print()
    print(f"SCORE: {score}")
    print(f"STATUS: {summary} | echo={echo_url}")
    print()
    print("=" * 64)


if __name__ == "__main__":
    main()
