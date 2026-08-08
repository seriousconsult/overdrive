"""Short-TTL JSON result caches for detection scripts (keyed by egress IP)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

__all__ = [
    "env_cache_disabled",
    "env_cache_ttl_s",
    "read_ip_score_cache",
    "write_ip_score_cache",
]


def env_cache_ttl_s(env_name: str, default: int = 120) -> int:
    """Read a non-negative integer TTL from ``env_name``, else ``default``."""
    raw = (os.environ.get(env_name) or "").strip()
    if raw.isdigit():
        return max(0, int(raw))
    return default


def env_cache_disabled(env_name: str) -> bool:
    """True when ``env_name`` is set to a truthy disable flag (1/true/yes)."""
    return (os.environ.get(env_name) or "").strip().lower() in {"1", "true", "yes"}


def read_ip_score_cache(
    path: Path,
    *,
    ip: str,
    ttl_s: int,
    disabled: bool = False,
) -> dict[str, Any] | None:
    """
    Load a score cache file if it matches ``ip`` and is within ``ttl_s``.

    Expected JSON keys: ``ip``, ``ts``, ``score``, ``description`` (plus optional extras).
    """
    if disabled or ttl_s <= 0:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("ip") != ip:
        return None
    try:
        ts = float(data["ts"])
        int(data["score"])
        str(data["description"])
    except (KeyError, TypeError, ValueError):
        return None
    if time.time() - ts > ttl_s:
        return None
    return data


def write_ip_score_cache(
    path: Path,
    *,
    ip: str,
    score: int,
    description: str,
    disabled: bool = False,
    ttl_s: int = 1,
    **extra: Any,
) -> None:
    """Atomically write a score cache payload (``ip``/``ts``/``score``/``description`` + extras)."""
    if disabled or ttl_s <= 0:
        return
    payload: dict[str, Any] = {
        "ip": ip,
        "ts": time.time(),
        "score": score,
        "description": description,
        **extra,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass
