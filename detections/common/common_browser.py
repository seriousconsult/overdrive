#!/usr/bin/env python3
"""Shared browser detection helpers for ``detections/browser/*.py`` scripts."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import Any

try:
    import requests
except ImportError:  # Minimal guests may only need direct Chromium browser probes.
    requests = None  # type: ignore[assignment]

__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_PAGE_LOAD_TIMEOUT",
    "DEFAULT_SCRIPT_TIMEOUT",
    "DRIVER_COMMAND_TIMEOUT",
    "DEFAULT_REPORT_WIDTH",
    "EXTERNAL_BROWSER_PROBES_ENV",
    "fetch_json",
    "fetch_browser_json",
    "confirm_external_browser_probe",
    "prompt_suite_external_browser_access",
    "set_external_browser_probe_decision",
    "is_browser_timeout_error",
    "normalize_ip_fields",
    "ipv4_like_strings",
    "is_private_ipv4",
    "print_browser_detection_header",
    "print_browser_detection_score_footer",
    "print_browser_probe_error",
    "browser_runtime_diagnostics",
]

_IS_LINUX = sys.platform.startswith("linux")
EXTERNAL_BROWSER_PROBES_ENV = "OVERDRIVE_ALLOW_EXTERNAL_BROWSER_PROBES"


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


DEFAULT_TIMEOUT = _env_int("OVERDRIVE_BROWSER_TIMEOUT", 500, minimum=0)
DEFAULT_PAGE_LOAD_TIMEOUT = _env_int("OVERDRIVE_BROWSER_PAGE_LOAD_TIMEOUT", 500, minimum=0)
DEFAULT_SCRIPT_TIMEOUT = _env_int("OVERDRIVE_BROWSER_SCRIPT_TIMEOUT", 500, minimum=0)
DRIVER_COMMAND_TIMEOUT = _env_int(
    "OVERDRIVE_BROWSER_DRIVER_COMMAND_TIMEOUT",
    500,
    minimum=0,
)
DEFAULT_REPORT_WIDTH = 60


def _parse_external_probe_env(raw: str) -> bool | None:
    value = raw.strip().lower()
    if value in {"1", "y", "yes", "true", "on", "allow"}:
        return True
    if value in {"0", "n", "no", "false", "off", "deny"}:
        return False
    return None


def set_external_browser_probe_decision(allowed: bool) -> None:
    """Publish a suite-level Y/N decision for probe subprocesses."""
    os.environ[EXTERNAL_BROWSER_PROBES_ENV] = "1" if allowed else "0"


def prompt_suite_external_browser_access(
    *,
    script_names: list[str] | None = None,
    force: bool | None = None,
) -> bool:
    """
    Ask once at suite start whether external-internet browser probes may run.

    Returns True when external probes are allowed. When ``force`` is set, skip the
    prompt and publish that decision. Probe subprocesses inherit the decision via
    ``OVERDRIVE_ALLOW_EXTERNAL_BROWSER_PROBES`` (their stdin is typically DEVNULL).
    """
    if force is not None:
        set_external_browser_probe_decision(force)
        print(
            "[*] External internet browser probes: "
            + ("allowed (--allow-external)." if force else "denied (--deny-external).")
        )
        return force

    existing = _parse_external_probe_env(os.environ.get(EXTERNAL_BROWSER_PROBES_ENV) or "")
    if existing is not None:
        print(
            "[*] External internet browser probes: "
            + ("allowed" if existing else "denied")
            + f" (from {EXTERNAL_BROWSER_PROBES_ENV})."
        )
        return existing

    names = script_names or []
    external_scripts = [
        name
        for name in names
        if name
        in {
            "HTML5_Geolocation_API.py",
            "HTTP2_settings.py",
            "HTTP3_QUIC.py",
        }
    ]
    if not external_scripts:
        set_external_browser_probe_decision(False)
        return False

    print("[*] Some browser probes can contact the public internet:")
    for name in external_scripts:
        if name == "HTML5_Geolocation_API.py":
            print("    - HTML5_Geolocation_API.py  (GeoIP providers)")
        elif name == "HTTP2_settings.py":
            print("    - HTTP2_settings.py         (only if a non-local endpoint is configured)")
        elif name == "HTTP3_QUIC.py":
            print("    - HTTP3_QUIC.py             (only if a non-local endpoint is configured)")
    print()

    if not sys.stdin.isatty():
        set_external_browser_probe_decision(False)
        print(
            "[!] No TTY for Y/N confirmation; external internet probes will be skipped. "
            "Re-run with --allow-external or --deny-external."
        )
        return False

    try:
        answer = input(
            "Allow external internet browser probes for this run? Type Y or N: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        set_external_browser_probe_decision(False)
        print("[!] External probe confirmation interrupted; skipping external probes.")
        return False

    allowed = answer in {"y", "yes"}
    set_external_browser_probe_decision(allowed)
    print(
        "[*] External internet browser probes: "
        + ("allowed." if allowed else "denied; those probes will report N/A.")
    )
    print()
    return allowed


def confirm_external_browser_probe(probe_name: str, targets: list[str] | tuple[str, ...] | str) -> tuple[bool, str | None]:
    """
    Require an explicit confirmation before contacting internet endpoints.

    Prefer the suite-level decision in ``OVERDRIVE_ALLOW_EXTERNAL_BROWSER_PROBES``.
    Fall back to an interactive Y/N prompt only when that env var is unset and a
    TTY is available (standalone probe runs).
    """
    if isinstance(targets, str):
        target_text = targets
    else:
        target_text = ", ".join(str(target) for target in targets)

    env_decision = _parse_external_probe_env(os.environ.get(EXTERNAL_BROWSER_PROBES_ENV) or "")
    if env_decision is True:
        return True, None
    if env_decision is False:
        return False, "external probe denied for this suite run"

    if not sys.stdin.isatty():
        return False, "interactive Y/N confirmation is required before external internet probes"

    prompt = (
        f"{probe_name} will contact external internet endpoint(s): {target_text}\n"
        "Run this external probe now? Type Y or N: "
    )
    try:
        answer = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False, "external probe was not confirmed"
    if answer in {"y", "yes"}:
        return True, None
    return False, "user declined external internet probe"


def _first_existing_path(*candidates: str) -> str | None:
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _chromium_binary() -> str | None:
    """Locate Chrome/Chromium for direct DevTools browser probes."""
    env = (os.environ.get("CHROME_BIN") or os.environ.get("CHROMIUM_BIN") or "").strip()
    if env and os.path.isfile(env):
        return env
    which = (
        shutil.which("chromium-browser")
        or shutil.which("chromium")
        or shutil.which("google-chrome")
        or shutil.which("google-chrome-stable")
    )
    if which:
        return which
    return _first_existing_path(
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
    )


def _command_version(binary: str | None) -> str:
    if not binary:
        return "(missing)"
    try:
        out = subprocess.check_output(
            [binary, "--version"],
            text=True,
            timeout=5,
            stderr=subprocess.STDOUT,
        )
        return out.strip() or "(no version output)"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"(version check failed: {type(exc).__name__}: {exc})"


def browser_runtime_diagnostics() -> dict[str, str]:
    chromium = _chromium_binary()
    return {
        "chromium": chromium or "(missing)",
        "chromium_version": _command_version(chromium),
    }


def fetch_json(
    url: str,
    params: dict[str, Any] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """GET JSON from a URL with a stable User-Agent (GeoIP / API probes)."""
    if requests is None:
        raise RuntimeError("The requests package is required for fetch_json()")
    # timeout<=0 means "no suite kill"; HTTP still needs a finite socket timeout.
    request_timeout = 15 if not timeout or timeout <= 0 else timeout
    r = requests.get(
        url,
        params=params,
        timeout=request_timeout,
        headers={"User-Agent": "geo-leak-check/1.0"},
    )
    r.raise_for_status()
    return r.json()


def fetch_browser_json(
    url: str,
    *,
    timeout: int = 25,
    cache_bust: bool = False,
    ignore_certificate_errors: bool = False,
) -> tuple[dict[str, Any] | None, str | None]:
    """
    Load a JSON-rendering page through Chromium DevTools and parse body text.

    Returns ``(data, error)``. This is useful for probes that need the browser's
    real transport/header behavior rather than ``requests``.
    """
    try:
        from detections.common.direct_chromium import fetch_browser_json as direct_fetch_browser_json
    except Exception as exc:
        return None, f"direct Chromium helpers unavailable: {type(exc).__name__}: {exc}"

    return direct_fetch_browser_json(
        url,
        timeout=timeout,
        cache_bust=cache_bust,
        ignore_certificate_errors=ignore_certificate_errors,
    )


def normalize_ip_fields(provider: str, raw: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize GeoIP-style fields across ipapi.co, ip-api.com, and ipapi.is.
    Output dicts always include ``provider`` for downstream summaries.
    """
    asn_raw = raw.get("asn")
    asn_val = None
    org_from_asn = None
    if isinstance(asn_raw, dict):
        asn_val = asn_raw.get("asn")
        org_from_asn = asn_raw.get("org")

    if provider == "ipapi.is":
        loc = raw.get("location", {})
        comp = raw.get("company", {})
        cc = loc.get("country")
        if isinstance(cc, str):
            cc = cc.strip().upper() if len(cc) == 2 else None
        return {
            "provider": provider,
            "ip": raw.get("ip"),
            "city": loc.get("city"),
            "region": loc.get("state"),
            "country": loc.get("country"),
            "country_code": cc,
            "timezone": loc.get("timezone"),
            "lat": loc.get("latitude"),
            "lon": loc.get("longitude"),
            "asn": asn_val,
            "org": comp.get("name") or org_from_asn,
        }

    cc_raw = raw.get("country_code") or raw.get("countryCode")
    cc = None
    if isinstance(cc_raw, str) and len(cc_raw.strip()) == 2:
        cc = cc_raw.strip().upper()
    cname = raw.get("country_name") or raw.get("country")
    return {
        "provider": provider,
        "ip": raw.get("ip") or raw.get("query"),
        "city": raw.get("city") or raw.get("cityName"),
        "country": cname,
        "country_code": cc,
        "region": raw.get("region") or raw.get("regionName"),
        "timezone": raw.get("timezone"),
        "lat": raw.get("latitude") or raw.get("lat"),
        "lon": raw.get("longitude") or raw.get("lon"),
        "asn": asn_val or raw.get("as"),
        "org": raw.get("org") or raw.get("isp") or org_from_asn,
    }


def ipv4_like_strings(text: str) -> list[str]:
    """Extract IPv4-like strings from text using regex."""
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")


def is_private_ipv4(ip: str) -> bool:
    """
    True if ``ip`` is in RFC1918 private ranges (10/8, 172.16/12, 192.168/16).
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
    except (ValueError, TypeError):
        return False


def print_browser_detection_header(title: str, *, width: int = DEFAULT_REPORT_WIDTH) -> None:
    """Standard ``====`` banner + title (matches placeholder browser scripts)."""
    bar = "=" * width
    print(bar)
    print(title)
    print(bar)
    print()


def print_browser_detection_score_footer(
    score: int,
    description: str,
    *,
    width: int = DEFAULT_REPORT_WIDTH,
) -> None:
    """Print ``Score:`` / description / closing bar."""
    print(f"Score: {score}")
    print(f"  {description}")
    print()
    print("=" * width)


def is_browser_timeout_error(message: str | None) -> bool:
    """True when a probe failure string looks like a timeout / hung browser."""
    if not message:
        return False
    text = message.lower()
    if any(
        needle in text
        for needle in (
            "chromium exited early",
            "chrome exited early",
            "devtools websocket closed",
            "zygote_host_impl_linux",
            "running as root without --no-sandbox",
            "failed to start message bus",
            "failed to bind socket",
            "failed to read machine uuid",
            "machine-id",
            "dbus-daemon",
            "dbus-run-session",
            "gl_display.cc",
            "libangle",
            "requested gl implementation",
            "vkcreateinstance",
            "vulkan",
        )
    ):
        return False
    return any(
        needle in text
        for needle in (
            "timeout",
            "timed out",
            "read timed out",
            "did not start within",
            "did not finish within",
        )
    )


def print_browser_probe_error(reason: str, *, width: int = DEFAULT_REPORT_WIDTH) -> int:
    """
    Report a non-scorable probe failure.

    Timeouts and browser crashes are not authenticity scores (1-5). Prints
    ``SCORE: Error`` and returns exit code 2 for the suite runner.
    """
    label = "TIMEOUT" if is_browser_timeout_error(reason) else "ERROR"
    print(f"SCORE: Error")
    print(f"STATUS: {label}: {reason}")
    print()
    print("=" * width)
    return 2
