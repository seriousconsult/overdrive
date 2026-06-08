"""Helpers shared by runner/orchestration scripts."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


def run_step(
    command: list[str],
    *,
    cwd: str | Path,
    dry_run: bool,
    name: str | None = None,
) -> int:
    """Print and optionally run a command, returning its exit code."""
    print()
    if name:
        print(f"=== {name} ===")
    print("[run] " + " ".join(command))
    if dry_run:
        return 0
    return subprocess.run(command, cwd=str(cwd), check=False).returncode


def file_contains_token(path: str | Path, token: str) -> bool:
    """Return True when a text file contains a token; missing/unreadable files return False."""
    try:
        return token in Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False


def file_matches_pattern(path: str | Path, pattern: re.Pattern[str]) -> bool:
    """Return True when a text file matches a compiled regex pattern."""
    try:
        return pattern.search(Path(path).read_text(encoding="utf-8", errors="ignore")) is not None
    except OSError:
        return False
