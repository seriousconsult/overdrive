#!/usr/bin/env python3
"""Shared VPN helper utilities for the vpn scripts."""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests

DEFAULT_TIMEOUT = 10
DEFAULT_UA = {"User-Agent": "overdrive-vpn-utils/1.0"}

IPV4_URL = "https://api.ipify.org?format=json"
IPV6_URL = "https://api6.ipify.org?format=json"
IPAPI_URL_AUTO = "https://ipapi.co/json/"
IPAPI_URL_IP = "https://ipapi.co/{ip}/json/"
IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_AUTO_URL = "http://ip-api.com/json/?fields=status,message,timezone"

IANA_TZ_RE = re.compile(r"^[A-Za-z0-9_\-/+]+$")


def run(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return ""


def is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    try:
        with open("/proc/version", encoding="utf-8", errors="ignore") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def wsl_windows_host_ip() -> str | None:
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0 and out.stdout:
            m = re.search(r"default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})", out.stdout)
            if m:
                return m.group(1)
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    ip = parts[1]
                    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip) and not ip.startswith("127."):
                        return ip
    except OSError:
        pass

    return None


def fetch_json(url: str, timeout: int = DEFAULT_TIMEOUT, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    try:
        r = requests.get(url, headers=headers or DEFAULT_UA, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError, TypeError):
        return None


def public_ipv4(timeout: int = DEFAULT_TIMEOUT) -> str | None:
    data = fetch_json(IPV4_URL, timeout=timeout, headers=DEFAULT_UA)
    if not data:
        return None
    ip = data.get("ip")
    if not ip or ":" in str(ip):
        return None
    return str(ip).strip()


def get_public_ipv4(timeout: int = DEFAULT_TIMEOUT) -> str | None:
    """Backward-compatible alias for scripts that used the older helper name."""
    return public_ipv4(timeout=timeout)


def public_ipv6(timeout: int = DEFAULT_TIMEOUT) -> str | None:
    data = fetch_json(IPV6_URL, timeout=timeout, headers=DEFAULT_UA)
    if not data:
        return None
    ip = data.get("ip")
    if not ip or ":" not in str(ip):
        return None
    return str(ip).strip()


def fetch_ipapi(ip: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any] | None:
    url = IPAPI_URL_IP.format(ip=ip) if ip else IPAPI_URL_AUTO
    try:
        r = requests.get(url, headers=DEFAULT_UA, timeout=timeout)
        if r.status_code == 429:
            return {"error": True, "reason": "Rate limited (429)"}
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError):
        return None


def fetch_ip_api(ip: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    try:
        r = requests.get(IP_API_URL.format(ip=ip), headers=DEFAULT_UA, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError):
        return {"status": "fail", "message": "request error"}


def ip_metadata(ip: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    if not ip or ":" in ip:
        return {}
    data = fetch_ip_api(ip, timeout=timeout)
    return data if isinstance(data, dict) else {}


def _looks_like_error_blob(s: str) -> bool:
    t = (s or "").strip().lower()
    if not t:
        return True
    if t.startswith("{") or t.startswith("<!doctype") or t.startswith("<html"):
        return True
    if "rate" in t and "limit" in t:
        return True
    if "please contact us" in t or "sign up" in t or "pricing" in t:
        return True
    if "error" in t and ("http" in t or "trial" in t):
        return True
    return False


def normalize_iana_tz(name: str | None) -> str | None:
    if not name:
        return None
    tz = str(name).strip().strip('"').strip("'")
    if not tz or _looks_like_error_blob(tz):
        return None
    tz = tz.replace(" ", "_")
    if not IANA_TZ_RE.match(tz) or "/" not in tz:
        return None
    try:
        ZoneInfo(tz)
    except ZoneInfoNotFoundError:
        return None
    except Exception:
        return None
    return tz


def get_ip_timezone() -> tuple[str | None, str]:
    ip = public_ipv4()
    if ip:
        ip_api_data = fetch_ip_api(ip)
        if isinstance(ip_api_data, dict):
            tz = ip_api_data.get("timezone")
            if tz:
                norm = normalize_iana_tz(str(tz))
                if norm:
                    return norm, f"ip-api.com (ip={ip})"

    ipapi_data = fetch_ipapi(ip)
    if isinstance(ipapi_data, dict):
        tz = ipapi_data.get("timezone")
        if tz:
            norm = normalize_iana_tz(str(tz))
            if norm:
                return norm, f"ipapi.co json (ip={ip or 'auto'})"

    if ip:
        ipapi_auto = fetch_ipapi(None)
        if isinstance(ipapi_auto, dict):
            tz2 = ipapi_auto.get("timezone")
            if tz2:
                norm = normalize_iana_tz(str(tz2))
                if norm:
                    return norm, "ipapi.co json (auto endpoint)"

    try:
        r = requests.get(IP_API_AUTO_URL, headers=DEFAULT_UA, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and data.get("status") == "success":
            tz3 = normalize_iana_tz(str(data.get("timezone") or ""))
            if tz3:
                return tz3, "ip-api.com (auto endpoint)"
    except (requests.RequestException, ValueError):
        pass

    return None, f"all providers failed (ip={ip or 'unknown'})"
