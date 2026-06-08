"""Small cross-domain utility helpers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from detections.common.common_runner import file_contains_token, file_matches_pattern, run_step

__all__ = [
    "dedupe_preserve_order",
    "env_proxy_info",
    "file_contains_token",
    "file_matches_pattern",
    "normalize_address",
    "reexec_with_repo_venv",
    "repo_venv_python",
    "run_command",
    "run_step",
    "split_address_port",
]


def run_command(cmd: list[str], *, timeout: float = 15) -> tuple[int, str]:
    """Run a command and return ``(returncode, stdout)``; return ``(-1, "")`` on launch failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode, result.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return -1, ""


def repo_venv_python(repo_root: str | Path) -> Path | None:
    """Return a repo-local virtualenv interpreter if one exists."""
    root = Path(repo_root)
    candidates = (
        root / "virtual_env" / "bin" / "python",
        root / "virtual_env" / "Scripts" / "python.exe",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def reexec_with_repo_venv(
    repo_root: str | Path,
    *,
    reason: str,
    env_disable: str = "OVERDRIVE_NO_VENV_REEXEC",
) -> None:
    """Re-exec this script with the repo virtualenv Python when available."""
    if os.environ.get(env_disable):
        return
    venv_python = repo_venv_python(repo_root)
    if not venv_python:
        return
    try:
        current = Path(sys.executable).resolve()
        target = venv_python.resolve()
    except OSError:
        current = Path(sys.executable)
        target = venv_python
    if current == target:
        return
    print(
        f"[*] {reason}; re-running with {target}.",
        file=sys.stderr,
    )
    os.execv(str(target), [str(target), *sys.argv])


def split_address_port(endpoint: str) -> tuple[str, int | None]:
    """Split ``host:port`` or ``[ipv6]:port`` without raising on malformed input."""
    endpoint = endpoint.strip()
    if endpoint.startswith("[") and "]" in endpoint:
        host, _, port = endpoint.rpartition("]:")
        host = host + "]"
    else:
        host, _, port = endpoint.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return endpoint, None


def normalize_address(addr: str) -> str:
    """Drop an IPv6 zone suffix and trim whitespace."""
    return addr.split("%", 1)[0].strip()


def dedupe_preserve_order(items: list[str]) -> list[str]:
    """Return stripped, non-empty items with first-seen order preserved."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        value = item.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def env_proxy_info() -> tuple[bool, list[str]]:
    """Summarize HTTP(S)/ALL proxy environment variables without exposing full URLs."""
    found: list[str] = []
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        value = os.environ.get(key)
        if not value:
            continue
        try:
            host = urlparse(value).hostname or value[:40]
        except Exception:
            host = value[:40]
        found.append(f"{key}={host}")
    return bool(found), found
