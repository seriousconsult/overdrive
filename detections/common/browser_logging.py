#!/usr/bin/env python3
"""Structured logging for browser detection probes and Chromium startup."""

from __future__ import annotations

import atexit
import json
import logging
import os
import sys
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_LOG_DIR = _REPO_ROOT / "run" / "logs" / "browser"

LOG_DIR_ENV = "OVERDRIVE_BROWSER_LOG_DIR"
LOG_LEVEL_ENV = "OVERDRIVE_BROWSER_LOG_LEVEL"
LOG_DISABLE_ENV = "OVERDRIVE_BROWSER_LOG_DISABLE"

_SESSION_ID: str | None = None
_LOG_PATH: Path | None = None
_LOGGER: logging.Logger | None = None


def _truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() in {"1", "true", "yes", "on"}


def logging_enabled() -> bool:
    if _truthy(os.environ.get(LOG_DISABLE_ENV)):
        return False
    return True


def _resolve_log_dir() -> Path:
    raw = (os.environ.get(LOG_DIR_ENV) or "").strip()
    if raw:
        return Path(raw).expanduser()
    return _DEFAULT_LOG_DIR


def _resolve_level() -> int:
    raw = (os.environ.get(LOG_LEVEL_ENV) or "DEBUG").strip().upper()
    return getattr(logging, raw, logging.DEBUG)


def init_browser_log_session(*, label: str = "browser-suite") -> Path | None:
    """Create a timestamped log file for one browser suite run."""
    global _SESSION_ID, _LOG_PATH, _LOGGER
    if not logging_enabled():
        return None
    if _LOGGER is not None:
        return _LOG_PATH

    log_dir = _resolve_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    _SESSION_ID = f"{label}_{stamp}"
    _LOG_PATH = log_dir / f"{_SESSION_ID}.log"

    logger = logging.getLogger("overdrive.browser")
    logger.handlers.clear()
    logger.setLevel(_resolve_level())
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s.%(msecs)03dZ %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    file_handler = logging.FileHandler(_LOG_PATH, encoding="utf-8")
    file_handler.setFormatter(fmt)
    file_handler.setLevel(_resolve_level())
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(fmt)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)

    _LOGGER = logger
    atexit.register(finish_browser_log_session)
    blog_info(
        "browser log session started",
        label=label,
        log_path=str(_LOG_PATH),
        pid=os.getpid(),
        cwd=str(Path.cwd()),
    )
    return _LOG_PATH


def finish_browser_log_session() -> None:
    global _LOGGER
    if _LOGGER is None:
        return
    blog_info("browser log session finished", log_path=str(_LOG_PATH) if _LOG_PATH else "")
    for handler in list(_LOGGER.handlers):
        handler.close()
        _LOGGER.removeHandler(handler)
    _LOGGER = None


def _logger() -> logging.Logger | None:
    return _LOGGER


def _format_fields(fields: dict[str, Any]) -> str:
    if not fields:
        return ""
    try:
        return " " + json.dumps(fields, sort_keys=True, default=str)
    except TypeError:
        return " " + str(fields)


def blog_debug(message: str, **fields: Any) -> None:
    logger = _logger()
    if logger:
        logger.debug("%s%s", message, _format_fields(fields))


def blog_info(message: str, **fields: Any) -> None:
    logger = _logger()
    if logger:
        logger.info("%s%s", message, _format_fields(fields))
    elif logging_enabled():
        print(f"[browser] {message}", file=sys.stderr)


def blog_warning(message: str, **fields: Any) -> None:
    logger = _logger()
    if logger:
        logger.warning("%s%s", message, _format_fields(fields))
    elif logging_enabled():
        print(f"[browser][warn] {message}", file=sys.stderr)


def blog_error(message: str, *, exc: BaseException | None = None, **fields: Any) -> None:
    if exc is not None:
        fields = {**fields, "exc_type": type(exc).__name__, "exc": str(exc)}
        fields.setdefault("traceback", traceback.format_exc())
    logger = _logger()
    if logger:
        logger.error("%s%s", message, _format_fields(fields))
    else:
        print(f"[browser][error] {message}", file=sys.stderr)


def blog_probe_start(script_name: str, *, timeout_sec: int | None, extra: dict[str, Any] | None = None) -> float:
    fields = {"script": script_name, "timeout_sec": timeout_sec}
    if extra:
        fields.update(extra)
    blog_info("probe start", **fields)
    return time.monotonic()


def blog_probe_end(
    script_name: str,
    *,
    started_at: float,
    score: str,
    comment: str = "",
    error: str | None = None,
) -> None:
    elapsed = time.monotonic() - started_at
    fields: dict[str, Any] = {
        "script": script_name,
        "score": score,
        "elapsed_sec": round(elapsed, 2),
    }
    if comment:
        fields["comment"] = comment[:500]
    if error:
        fields["error"] = error[:500]
    level = blog_error if str(score).lower() == "error" or error else blog_info
    level("probe end", **fields)


def blog_chromium_event(event: str, **fields: Any) -> None:
    blog_info(f"chromium {event}", **fields)


def tail_file(path: Path | str | None, *, limit: int = 80) -> str:
    if not path:
        return ""
    p = Path(path)
    if not p.is_file():
        return ""
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-limit:])


def blog_file_tail(label: str, path: Path | str | None, *, limit: int = 80) -> None:
    tail = tail_file(path, limit=limit)
    if not tail:
        blog_debug(f"{label} log tail empty", path=str(path) if path else "")
        return
    blog_debug(f"{label} log tail", path=str(path), tail=tail)


@contextmanager
def log_probe(script_name: str, *, timeout_sec: int | None = None) -> Iterator[None]:
    started = blog_probe_start(script_name, timeout_sec=timeout_sec)
    try:
        yield
    except Exception as exc:
        blog_probe_end(script_name, started_at=started, score="Error", error=str(exc))
        blog_error("probe raised", exc=exc, script=script_name)
        raise
    else:
        blog_probe_end(script_name, started_at=started, score="ok")


def current_log_path() -> Path | None:
    return _LOG_PATH
