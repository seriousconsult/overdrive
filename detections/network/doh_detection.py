#!/usr/bin/env python3
"""
DNS-over-HTTPS (DoH) Detection.

This probe inspects local OS, browser, and resolver-proxy configuration for
specific DoH evidence. It intentionally distinguishes:
  - confirmed DoH templates/endpoints
  - browser Secure DNS/TRR modes
  - local DNS proxies that forward upstream over HTTPS
  - DoT-only signals, which are encrypted DNS but not DoH
  - plain/public DNS addresses, which are not proof of DoH by themselves

Host-authenticity score:
  1 - No DoH evidence found; plain OS/router DNS appears more likely.
  2 - DoH disabled, off-by-default, or only weak/ambiguous traces.
  3 - Inconclusive: no readable config, conflicting data, or only DoT/unknown encrypted DNS.
  4 - Probable DoH: automatic/opportunistic browser or proxy configuration.
  5 - Confirmed DoH: strict browser mode, OS DoH template, or explicit HTTPS DNS upstream.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_local import is_wsl_local
from detections.common.common_utils import dedupe_preserve_order


DOH_HOST_HINTS = {
    "cloudflare-dns.com": "Cloudflare DoH",
    "mozilla.cloudflare-dns.com": "Mozilla/Cloudflare DoH",
    "dns.google": "Google DoH",
    "dns.quad9.net": "Quad9 DoH",
    "doh.opendns.com": "OpenDNS DoH",
    "dns.nextdns.io": "NextDNS DoH",
    "nextdns.io": "NextDNS DoH",
    "dns.adguard-dns.com": "AdGuard DoH",
    "doh.cleanbrowsing.org": "CleanBrowsing DoH",
    "dns.mullvad.net": "Mullvad DoH/DoT endpoint",
    "base.dns.mullvad.net": "Mullvad DoH",
    "adblock.dns.mullvad.net": "Mullvad DoH",
    "family.dns.mullvad.net": "Mullvad DoH",
    "freedns.controld.com": "ControlD DoH",
    "p2.freedns.controld.com": "ControlD DoH",
}

COMMON_DOH_PATH_HINTS = (
    "/dns-query",
    "/query",
    "/resolve",
    "/doh/",
)

CONFIG_PATHS = (
    "/etc/cloudflared/config.yml",
    "/etc/cloudflared/config.yaml",
    "/usr/local/etc/cloudflared/config.yml",
    "/etc/dnscrypt-proxy/dnscrypt-proxy.toml",
    "/etc/dnscrypt-proxy.toml",
    "/etc/AdGuardHome.yaml",
    "/opt/AdGuardHome/AdGuardHome.yaml",
    "/etc/nextdns.conf",
    "/etc/systemd/resolved.conf",
    "/etc/systemd/resolved.conf.d/*.conf",
    "/etc/stubby/stubby.yml",
    "/etc/stubby/stubby.yaml",
)


@dataclass
class Evidence:
    source: str
    severity: int
    protocol: str
    status: str
    detail: str
    path: str | None = None


def _short(value: str, width: int = 160) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    if len(value) <= width:
        return value
    return value[: max(0, width - 3)] + "..."


def _read_text(path: Path) -> str | None:
    try:
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        pass
    return None


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _glob(root: Path, pattern: str) -> list[Path]:
    try:
        return list(root.glob(pattern))
    except OSError:
        return []


def _glob_config_paths() -> list[Path]:
    out: list[Path] = []
    for pattern in CONFIG_PATHS:
        matches = sorted(Path("/").glob(pattern.lstrip("/"))) if "*" in pattern else [Path(pattern)]
        for path in matches:
            if _is_file(path) and path not in out:
                out.append(path)
    return out


def _extract_urls(text: str) -> list[str]:
    return dedupe_preserve_order(re.findall(r"https://[^\s\"'<>\\]+", text or "", re.I))


def _provider_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    for hint, label in DOH_HOST_HINTS.items():
        if host == hint or host.endswith("." + hint):
            return label
    if any(p in path for p in COMMON_DOH_PATH_HINTS):
        return f"DoH endpoint ({host or 'unknown host'})"
    return None


def _url_protocol(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return "unknown"
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    if "dns-query" in path or any(host == h or host.endswith("." + h) for h in DOH_HOST_HINTS):
        return "DoH"
    return "HTTPS"


def _browser_profile_dirs() -> list[Path]:
    home = Path.home()
    dirs: list[Path] = []
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        localappdata = os.environ.get("LOCALAPPDATA")
        if appdata:
            dirs.append(Path(appdata))
        if localappdata:
            dirs.append(Path(localappdata))
        return dirs
    dirs.append(home)
    if is_wsl_local():
        users = Path("/mnt/c/Users")
        if _is_dir(users):
            for user_dir in sorted(users.iterdir(), key=lambda p: p.name.lower()):
                if not _is_dir(user_dir) or user_dir.name.lower() in {"public", "default", "default user", "all users"}:
                    continue
                for child in (user_dir / "AppData" / "Roaming", user_dir / "AppData" / "Local"):
                    if _is_dir(child):
                        dirs.append(child)
    return dirs


def _firefox_pref_paths() -> list[Path]:
    paths: list[Path] = []
    for base in _browser_profile_dirs():
        candidates = [
            base / ".mozilla" / "firefox",
            base / "Mozilla" / "Firefox" / "Profiles",
            base / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
            base / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox",
        ]
        for root in candidates:
            paths.extend(_glob(root, "*/prefs.js"))
            paths.extend(_glob(root, "*/user.js"))
    return sorted(set(paths))


def _pref_int(text: str, key: str) -> int | None:
    m = re.search(
        rf'user_pref\s*\(\s*["\']{re.escape(key)}["\']\s*,\s*(-?\d+)\s*\)',
        text,
    )
    return int(m.group(1)) if m else None


def _pref_string(text: str, key: str) -> str | None:
    m = re.search(
        rf'user_pref\s*\(\s*["\']{re.escape(key)}["\']\s*,\s*["\']([^"\']*)["\']\s*\)',
        text,
    )
    return m.group(1) if m else None


def _firefox_evidence() -> list[Evidence]:
    out: list[Evidence] = []
    for path in _firefox_pref_paths():
        text = _read_text(path)
        if text is None:
            continue
        mode = _pref_int(text, "network.trr.mode")
        uri = _pref_string(text, "network.trr.uri")
        bootstrap = _pref_string(text, "network.trr.bootstrapAddress")
        if mode is None and uri is None:
            continue

        provider = _provider_from_url(uri or "") if uri else None
        uri_detail = f", uri={uri}" if uri else ""
        bootstrap_detail = f", bootstrap={bootstrap}" if bootstrap else ""
        profile = path.parent.name

        if mode == 3:
            out.append(Evidence("Firefox TRR", 5, "DoH", "strict", f"{profile}: network.trr.mode=3 (TRR only){uri_detail}{bootstrap_detail}", str(path)))
        elif mode == 2:
            out.append(Evidence("Firefox TRR", 4, "DoH", "enabled", f"{profile}: network.trr.mode=2 (DoH first/fallback allowed){uri_detail}{bootstrap_detail}", str(path)))
        elif mode == 1:
            out.append(Evidence("Firefox TRR", 4, "DoH", "opportunistic", f"{profile}: network.trr.mode=1 (DoH race/heuristic){uri_detail}{bootstrap_detail}", str(path)))
        elif mode == 0:
            out.append(Evidence("Firefox TRR", 1, "plain", "off", f"{profile}: network.trr.mode=0 (DoH disabled){uri_detail}", str(path)))
        elif mode == 5:
            out.append(Evidence("Firefox TRR", 1, "plain", "off-by-choice", f"{profile}: network.trr.mode=5 (DoH explicitly off by user/policy){uri_detail}", str(path)))
        elif mode is not None:
            out.append(Evidence("Firefox TRR", 3, "DoH?", "unknown", f"{profile}: network.trr.mode={mode}{uri_detail}", str(path)))
        elif uri:
            sev = 5 if provider else 4
            out.append(Evidence("Firefox TRR", sev, "DoH", "template-present", f"{profile}: TRR URI configured: {uri}", str(path)))
    return out


def _chromium_local_state_paths() -> list[Path]:
    paths: list[Path] = []
    for base in _browser_profile_dirs():
        candidates = [
            base / ".config" / "google-chrome" / "Local State",
            base / ".config" / "chromium" / "Local State",
            base / ".config" / "microsoft-edge" / "Local State",
            base / ".config" / "BraveSoftware" / "Brave-Browser" / "Local State",
            base / ".config" / "vivaldi" / "Local State",
            base / ".var" / "app" / "com.google.Chrome" / "config" / "google-chrome" / "Local State",
            base / "Google" / "Chrome" / "User Data" / "Local State",
            base / "Microsoft" / "Edge" / "User Data" / "Local State",
            base / "BraveSoftware" / "Brave-Browser" / "User Data" / "Local State",
        ]
        paths.extend([p for p in candidates if _is_file(p)])
    return sorted(set(paths))


def _find_dicts_with_key(obj: Any, key: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(obj, dict):
        if key in obj:
            found.append(obj)
        for value in obj.values():
            found.extend(_find_dicts_with_key(value, key))
    elif isinstance(obj, list):
        for value in obj:
            found.extend(_find_dicts_with_key(value, key))
    return found


def _json_file(path: Path) -> dict[str, Any] | None:
    text = _read_text(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _json_policy_files(patterns: tuple[str, ...]) -> list[Path]:
    files: list[Path] = []
    for pattern in patterns:
        matches = sorted(Path("/").glob(pattern.lstrip("/"))) if "*" in pattern else [Path(pattern)]
        for path in matches:
            if _is_file(path) and path not in files:
                files.append(path)
    return files


def _chromium_policy_evidence() -> list[Evidence]:
    patterns = (
        "/etc/chromium/policies/managed/*.json",
        "/etc/chromium/policies/recommended/*.json",
        "/etc/chromium-browser/policies/managed/*.json",
        "/etc/chromium-browser/policies/recommended/*.json",
        "/etc/opt/chrome/policies/managed/*.json",
        "/etc/opt/chrome/policies/recommended/*.json",
        "/etc/brave/policies/managed/*.json",
        "/etc/brave/policies/recommended/*.json",
    )
    out: list[Evidence] = []
    for path in _json_policy_files(patterns):
        data = _json_file(path)
        if not data:
            continue
        mode = data.get("DnsOverHttpsMode")
        templates = data.get("DnsOverHttpsTemplates")
        if mode is None and templates is None:
            continue
        mode_text = str(mode or "").lower()
        template_text = " ".join(str(x) for x in templates) if isinstance(templates, list) else str(templates or "")
        urls = _extract_urls(template_text)
        detail = f"policy mode={mode_text or '(unset)'}, templates={_short(template_text or '(none)')}"
        if mode_text == "secure":
            out.append(Evidence("Chromium Policy", 5, "DoH", "strict", detail, str(path)))
        elif mode_text in {"automatic", "auto"}:
            out.append(Evidence("Chromium Policy", 5 if urls else 4, "DoH", "automatic", detail, str(path)))
        elif mode_text in {"off", "disabled"}:
            out.append(Evidence("Chromium Policy", 1, "plain", "off", detail, str(path)))
        elif urls:
            out.append(Evidence("Chromium Policy", 5, "DoH", "template-present", detail, str(path)))
        else:
            out.append(Evidence("Chromium Policy", 3, "DoH?", "unknown", detail, str(path)))
    return out


def _firefox_policy_evidence() -> list[Evidence]:
    patterns = (
        "/etc/firefox/policies/policies.json",
        "/usr/lib/firefox/distribution/policies.json",
        "/usr/lib64/firefox/distribution/policies.json",
        "/usr/share/firefox/distribution/policies.json",
        "/snap/firefox/current/usr/lib/firefox/distribution/policies.json",
    )
    out: list[Evidence] = []
    for path in _json_policy_files(patterns):
        data = _json_file(path)
        if not data:
            continue
        policies = data.get("policies") if isinstance(data.get("policies"), dict) else data
        doh = policies.get("DNSOverHTTPS") if isinstance(policies, dict) else None
        if not isinstance(doh, dict):
            continue
        enabled = doh.get("Enabled")
        provider = str(doh.get("ProviderURL") or doh.get("ProviderUrl") or doh.get("Provider") or "").strip()
        locked = doh.get("Locked")
        fallback = doh.get("Fallback")
        detail = f"DNSOverHTTPS policy enabled={enabled}, provider={provider or '(none)'}, locked={locked}, fallback={fallback}"
        if enabled is True:
            out.append(Evidence("Firefox Policy", 5 if provider else 4, "DoH", "managed-enabled", detail, str(path)))
        elif enabled is False:
            out.append(Evidence("Firefox Policy", 1, "plain", "managed-disabled", detail, str(path)))
        elif provider:
            out.append(Evidence("Firefox Policy", 5, "DoH", "provider-present", detail, str(path)))
        else:
            out.append(Evidence("Firefox Policy", 3, "DoH?", "managed-unknown", detail, str(path)))
    return out


def _chromium_evidence() -> list[Evidence]:
    out: list[Evidence] = []
    for path in _chromium_local_state_paths():
        text = _read_text(path)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            out.append(Evidence("Chromium Secure DNS", 3, "DoH?", "parse-error", f"Could not parse Local State JSON: {path}", str(path)))
            continue

        browser = path.parent.parent.name if path.parent.name == "User Data" else path.parent.name
        blocks = _find_dicts_with_key(data, "dns_over_https")
        if not blocks:
            continue
        for block_parent in blocks:
            block = block_parent.get("dns_over_https")
            if not isinstance(block, dict):
                out.append(Evidence("Chromium Secure DNS", 3, "DoH?", "unknown", f"{browser}: dns_over_https present but not object: {_short(str(block))}", str(path)))
                continue
            mode = str(block.get("mode") or "").lower()
            templates = block.get("templates") or block.get("template") or block.get("server_templates") or ""
            if isinstance(templates, list):
                template_text = " ".join(str(t) for t in templates)
            else:
                template_text = str(templates)
            urls = _extract_urls(template_text)
            providers = [p for url in urls if (p := _provider_from_url(url))]
            detail = f"{browser}: mode={mode or '(unset)'}, templates={_short(template_text or '(none)')}"
            if mode == "secure":
                out.append(Evidence("Chromium Secure DNS", 5, "DoH", "strict", detail, str(path)))
            elif mode in {"automatic", "auto"}:
                sev = 5 if urls and providers else 4
                out.append(Evidence("Chromium Secure DNS", sev, "DoH", "automatic", detail, str(path)))
            elif mode in {"off", "disabled"}:
                out.append(Evidence("Chromium Secure DNS", 1, "plain", "off", detail, str(path)))
            elif urls:
                sev = 5 if providers else 4
                out.append(Evidence("Chromium Secure DNS", sev, "DoH", "template-present", detail, str(path)))
            else:
                out.append(Evidence("Chromium Secure DNS", 3, "DoH?", "unknown", detail, str(path)))
    return out


def _powershell_exes() -> list[str]:
    return ["powershell.exe", "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"]


def _windows_doh_servers() -> tuple[list[dict[str, Any]], str | None]:
    ps = (
        "try { "
        "Get-DnsClientDohServerAddress -ErrorAction Stop | "
        "Select-Object ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade | "
        "ConvertTo-Json -Compress "
        "} catch { '[]' }"
    )
    last_error: str | None = None
    for exe in _powershell_exes():
        try:
            out = subprocess.run(
                [exe, "-NoProfile", "-NoLogo", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=18,
                encoding="utf-8",
                errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
            last_error = str(exc)
            continue
        raw = (out.stdout or "").strip()
        if not raw:
            return [], None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            return [], f"PowerShell JSON parse failed: {exc}"
        if isinstance(parsed, dict):
            return [parsed], None
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)], None
        return [], "unexpected PowerShell JSON shape"
    return [], last_error


def _windows_evidence() -> list[Evidence]:
    if sys.platform != "win32" and not is_wsl_local():
        return []
    rows, err = _windows_doh_servers()
    if err:
        return [Evidence("Windows DoH", 3, "DoH?", "query-error", f"Windows DoH query failed: {err}")]
    if not rows:
        return [Evidence("Windows DoH", 1, "plain", "none", "No Windows DoH server templates reported.")]

    out: list[Evidence] = []
    for row in rows:
        server = str(row.get("ServerAddress") or row.get("serverAddress") or "").strip()
        template = str(row.get("DohTemplate") or row.get("dohTemplate") or "").strip()
        allow_fallback = row.get("AllowFallbackToUdp")
        auto_upgrade = row.get("AutoUpgrade")
        provider = _provider_from_url(template) if template else None
        status = "template"
        if str(auto_upgrade).lower() in {"true", "1"}:
            status = "auto-upgrade"
        if str(allow_fallback).lower() in {"false", "0"}:
            status += "/no-udp-fallback"
        sev = 5 if template else 4
        detail = f"server={server or '(unknown)'}, template={template or '(none)'}, provider={provider or '(unknown)'}, fallback_udp={allow_fallback}, auto_upgrade={auto_upgrade}"
        out.append(Evidence("Windows DoH", sev, "DoH", status, detail))
    return out


def _linux_proxy_evidence() -> list[Evidence]:
    out: list[Evidence] = []
    for path in _glob_config_paths():
        text = _read_text(path)
        if text is None:
            continue
        lower = text.lower()
        urls = _extract_urls(text)
        doh_urls = [url for url in urls if _url_protocol(url) == "DoH" or _provider_from_url(url)]

        name = path.name.lower()
        source = str(path)
        if "cloudflared" in source.lower():
            if doh_urls:
                out.append(Evidence("cloudflared", 5, "DoH", "https-upstream", "DoH upstream(s): " + "; ".join(doh_urls[:4]), source))
            elif "https://" in lower:
                out.append(Evidence("cloudflared", 4, "HTTPS DNS?", "https-upstream", "HTTPS upstream configured but endpoint not recognized as DoH: " + _short("; ".join(urls[:4])), source))
            else:
                out.append(Evidence("cloudflared", 2, "unknown", "config-present", "cloudflared config present but no HTTPS DNS upstream found.", source))
            continue

        if "dnscrypt" in source.lower():
            if re.search(r"\bdoh_servers\s*=\s*true", lower):
                out.append(Evidence("dnscrypt-proxy", 5, "DoH", "doh-servers-enabled", "dnscrypt-proxy has doh_servers=true.", source))
            elif "doh_servers" in lower:
                out.append(Evidence("dnscrypt-proxy", 2, "DoH?", "doh-mentioned", "dnscrypt-proxy mentions doh_servers but not enabled.", source))
            if "dnscrypt_servers = true" in lower:
                out.append(Evidence("dnscrypt-proxy", 3, "DNSCrypt", "dnscrypt-enabled", "DNSCrypt enabled; encrypted DNS but not DoH.", source))
            continue

        if "adguardhome" in source.lower():
            if doh_urls:
                out.append(Evidence("AdGuardHome", 5, "DoH", "bootstrap/upstream", "HTTPS DNS upstream(s): " + "; ".join(doh_urls[:4]), source))
            elif "https://" in lower:
                out.append(Evidence("AdGuardHome", 4, "HTTPS DNS?", "https-upstream", "HTTPS upstream configured: " + _short("; ".join(urls[:4])), source))
            continue

        if "nextdns" in source.lower():
            out.append(Evidence("NextDNS", 5, "DoH", "client-config", "NextDNS CLI config present; NextDNS normally forwards over DoH/DoT.", source))
            continue

        if name.startswith("resolved") or "resolved.conf" in source.lower():
            if re.search(r"^\s*dnsovertls\s*=\s*(yes|opportunistic)\b", lower, re.M):
                out.append(Evidence("systemd-resolved", 3, "DoT", "dnsovertls", "DNSOverTLS is enabled/opportunistic; encrypted DNS but not DoH.", source))
            continue

        if "stubby" in source.lower():
            if "tls_auth_name" in lower or "tls_authentication" in lower:
                out.append(Evidence("stubby", 3, "DoT", "dot-config", "stubby config present; DNS-over-TLS, not DoH.", source))
            continue
    return out


def _resolv_conf_evidence() -> list[Evidence]:
    path = Path("/etc/resolv.conf")
    text = _read_text(path)
    if text is None:
        return []
    nameservers = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("nameserver "):
            parts = line.split()
            if len(parts) >= 2:
                nameservers.append(parts[1])
    if not nameservers:
        return [Evidence("resolv.conf", 3, "unknown", "no-nameserver", "No nameserver entries found.", str(path))]
    detail = "nameserver(s): " + ", ".join(dedupe_preserve_order(nameservers))
    if any(ns.startswith("127.") or ns == "::1" for ns in nameservers):
        return [Evidence("resolv.conf", 3, "proxy?", "loopback-stub", detail + " (local resolver stub; upstream protocol unknown)", str(path))]
    if any(ns.startswith("10.255.255.") for ns in nameservers):
        return [Evidence("resolv.conf", 3, "Windows-forwarded", "wsl-tunnel", detail + " (WSL DNS tunnel; inspect Windows DoH settings)", str(path))]
    return [Evidence("resolv.conf", 1, "plain?", "direct-nameserver", detail + " (plain DNS likely unless another local proxy/browser setting overrides it)", str(path))]


def _process_evidence() -> list[Evidence]:
    try:
        ret = subprocess.run(
            ["ps", "-eo", "comm,args"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    text = (ret.stdout or "").lower()
    out: list[Evidence] = []
    if "cloudflared" in text:
        out.append(Evidence("process", 4, "DoH?", "cloudflared-running", "cloudflared process is running; inspect config for upstream URL."))
    if "dnscrypt-proxy" in text:
        out.append(Evidence("process", 3, "DNSCrypt/DoH?", "dnscrypt-running", "dnscrypt-proxy process is running; protocol depends on config."))
    if "nextdns" in text:
        out.append(Evidence("process", 5, "DoH", "nextdns-running", "nextdns process is running; commonly uses encrypted DNS upstream."))
    if "adguardhome" in text:
        out.append(Evidence("process", 4, "DoH?", "adguardhome-running", "AdGuardHome process is running; inspect upstream config."))
    return out


def collect_evidence() -> list[Evidence]:
    evidence: list[Evidence] = []
    evidence.extend(_windows_evidence())
    evidence.extend(_firefox_policy_evidence())
    evidence.extend(_firefox_evidence())
    evidence.extend(_chromium_policy_evidence())
    evidence.extend(_chromium_evidence())
    evidence.extend(_linux_proxy_evidence())
    evidence.extend(_process_evidence())
    evidence.extend(_resolv_conf_evidence())
    return evidence


def score_evidence(evidence: list[Evidence]) -> tuple[int, str]:
    if not evidence:
        return 3, "No readable OS/browser/proxy DNS configuration found; DoH status unknown."

    confirmed = [e for e in evidence if e.severity >= 5]
    probable = [e for e in evidence if e.severity == 4]
    inconclusive = [e for e in evidence if e.severity == 3]
    disabled = [e for e in evidence if e.severity <= 1]
    weak = [e for e in evidence if e.severity == 2]
    forwarding_only = [
        e
        for e in inconclusive
        if e.status in {"wsl-tunnel", "loopback-stub", "direct-nameserver", "dnsovertls", "dot-config"}
    ]
    hard_unknown = [e for e in inconclusive if e not in forwarding_only]

    if confirmed:
        primary = confirmed[0]
        return 5, f"Confirmed DoH: {primary.source} {primary.status} - {primary.detail}"
    if probable:
        primary = probable[0]
        return 4, f"Probable DoH: {primary.source} {primary.status} - {primary.detail}"
    if hard_unknown and not disabled and not weak:
        return 3, "Only inconclusive encrypted-DNS/proxy signals were found: " + " | ".join(f"{e.source}: {e.detail}" for e in hard_unknown[:3])
    if weak and not confirmed and not probable:
        return 2, "Weak or disabled DoH traces only: " + " | ".join(f"{e.source}: {e.detail}" for e in (weak + disabled)[:4])
    if disabled and not confirmed and not probable and not hard_unknown and not weak:
        extra = " Forwarding/stub context: " + " | ".join(f"{e.source}: {e.status}" for e in forwarding_only[:3]) if forwarding_only else ""
        return 1, "No DoH evidence found; explicit off/plain DNS signals: " + " | ".join(f"{e.source}: {e.detail}" for e in disabled[:4]) + extra
    if forwarding_only and not confirmed and not probable and not hard_unknown and not weak:
        return 3, "Only forwarding/stub/DoT context was found; DoH status depends on upstream configuration: " + " | ".join(f"{e.source}: {e.detail}" for e in forwarding_only[:4])
    return 3, "Mixed DNS evidence; no confirmed DoH: " + " | ".join(f"{e.source}: {e.status}" for e in evidence[:5])


def print_evidence(evidence: list[Evidence]) -> None:
    if not evidence:
        print("Evidence: none")
        return
    print("Evidence:")
    print(f"{'SEV':<3} {'SOURCE':<24} {'PROTO':<12} {'STATUS':<18} DETAIL")
    print("-" * 100)
    for item in sorted(evidence, key=lambda e: (-e.severity, e.source, e.status)):
        path = f" [{item.path}]" if item.path else ""
        print(f"{item.severity:<3} {_short(item.source, 24):<24} {_short(item.protocol, 12):<12} {_short(item.status, 18):<18} {_short(item.detail + path, 220)}")


def check_doh_usage() -> tuple[int, str]:
    return score_evidence(collect_evidence())


def main() -> int:
    print("=" * 60)
    print("DNS-over-HTTPS (DoH) Detection")
    print("=" * 60)

    evidence = collect_evidence()
    print()
    print_evidence(evidence)
    score, description = score_evidence(evidence)

    print("\n" + "-" * 40)
    print(f"SCORE: {score}")
    print(f"STATUS: {description}")
    print("-" * 40)
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
