#!/usr/bin/env python3
"""Run the VirtualBox lab setup scripts, then verify the lab wiring.

This is intentionally separate from ``detections/run_detections.py`` because VM
creation scripts mutate VirtualBox state and can start GUI guests.

Verbose child output goes to a timestamped log under ``run/logs/``; the console
shows a short, orderly progress summary.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import TextIO

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_runner import file_contains_token


RUN_DIR = Path(__file__).resolve().parent
REPO_ROOT = RUN_DIR.parent
SCRIPT_DIR = REPO_ROOT / "VM"
LOG_DIR = RUN_DIR / "logs"

PREFERRED_CREATE_ORDER = (
    "openwrt_router/create_VM_OpenWrt_router.py",
)
DEFAULT_SKIP_CREATE_SCRIPTS = frozenset(
    {
        "alpine_client/create_VM_client_browser_pipe_alpine.py",
    }
)
VERIFY_SCRIPT = "verify_lab_from_host.py"

STEP_LABELS = {
    "create_VM_OpenWrt_router.py": "OpenWrt router + Alpine client",
    VERIFY_SCRIPT: "Verify lab wiring",
}

LABEL_WIDTH = 36
TAIL_LINES_ON_FAILURE = 24


def script_has_todo(script_path: Path) -> bool:
    return file_contains_token(script_path, "TODO")


def step_label(script_path: Path) -> str:
    return STEP_LABELS.get(script_path.name, script_path.name)


def format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {secs:02d}s"


def console_is_tty() -> bool:
    return sys.stdout.isatty()


def progress_line(step: int, total: int, label: str, status: str) -> str:
    return f"  [{step}/{total}] {label:<{LABEL_WIDTH}}  {status}"


def write_progress(step: int, total: int, label: str, status: str) -> None:
    """Update the current step line in place when stdout is a TTY."""
    line = progress_line(step, total, label, status)
    if console_is_tty():
        print(f"\r{line:<100}", end="", flush=True)
    else:
        # Non-TTY: avoid spam; only the final finish_progress line is printed.
        return


def finish_progress(step: int, total: int, label: str, status: str) -> None:
    line = progress_line(step, total, label, status)
    if console_is_tty():
        print(f"\r{line:<100}", flush=True)
    else:
        print(line, flush=True)


def discover_create_scripts(
    *,
    include_todo: bool,
    log: TextIO,
) -> list[Path]:
    """Return create_VM_*.py scripts in lab-friendly order."""
    all_scripts = {
        p.relative_to(SCRIPT_DIR).as_posix(): p
        for p in SCRIPT_DIR.rglob("create_VM_*.py")
        if p.is_file()
    }
    ordered: list[Path] = []

    for name in PREFERRED_CREATE_ORDER:
        path = all_scripts.pop(name, None)
        if path is not None:
            ordered.append(path)

    ordered.extend(all_scripts[name] for name in sorted(all_scripts))

    runnable: list[Path] = []
    for path in ordered:
        rel = path.relative_to(SCRIPT_DIR).as_posix()
        if rel in DEFAULT_SKIP_CREATE_SCRIPTS:
            log.write(f"[skip] {rel}: handled by router orchestration\n")
            continue
        if not include_todo and script_has_todo(path):
            log.write(f"[skip] {path.name}: contains TODO\n")
            continue
        runnable.append(path)
    log.flush()
    return runnable


def clear_previous_logs() -> None:
    """Remove prior run_VMs logs so each run starts with a clean log directory."""
    if not LOG_DIR.is_dir():
        return
    for path in LOG_DIR.glob("run_VMs_*.log"):
        try:
            path.unlink()
        except OSError:
            pass


def open_run_log() -> tuple[Path, TextIO]:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    clear_previous_logs()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = LOG_DIR / f"run_VMs_{stamp}.log"
    handle = path.open("w", encoding="utf-8", errors="replace")
    handle.write(f"run_VMs started {datetime.now().isoformat(timespec='seconds')}\n")
    handle.write(f"cwd={REPO_ROOT}\n")
    handle.write(f"python={sys.executable}\n")
    handle.write(f"argv={' '.join(sys.argv)}\n\n")
    handle.flush()
    return path, handle


def run_logged_step(
    command: list[str],
    *,
    cwd: Path,
    log: TextIO,
    log_path: Path,
    label: str,
    step: int,
    total: int,
    dry_run: bool,
) -> int:
    """Run a command; tee all output to the log; show a single progress line."""
    banner = (
        f"\n{'=' * 72}\n"
        f"STEP {step}/{total}: {label}\n"
        f"CMD: {' '.join(command)}\n"
        f"{'=' * 72}\n"
    )
    log.write(banner)
    log.flush()

    if dry_run:
        log.write("[dry-run] skipped execution\n")
        log.flush()
        finish_progress(step, total, label, "dry-run")
        return 0

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    started = time.monotonic()
    write_progress(step, total, label, "running …")

    proc = subprocess.Popen(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    assert proc.stdout is not None
    stop_pulse = threading.Event()

    def pump_output() -> None:
        for line in proc.stdout:
            log.write(line)
            log.flush()

    def pulse() -> None:
        while not stop_pulse.wait(0.5):
            elapsed = format_duration(time.monotonic() - started)
            write_progress(step, total, label, f"running … {elapsed}")

    reader = threading.Thread(target=pump_output, name="run_VMs-log", daemon=True)
    reader.start()
    pulser = threading.Thread(target=pulse, name="run_VMs-pulse", daemon=True)
    if console_is_tty():
        pulser.start()

    rc = proc.wait()
    stop_pulse.set()
    reader.join(timeout=5)
    if console_is_tty():
        pulser.join(timeout=1)

    elapsed = format_duration(time.monotonic() - started)
    if rc == 0:
        finish_progress(step, total, label, f"ok  ({elapsed})")
        log.write(f"\n[ok] exit=0 elapsed={elapsed}\n")
    else:
        finish_progress(step, total, label, f"FAILED  ({elapsed})")
        log.write(f"\n[fail] exit={rc} elapsed={elapsed}\n")
        print(f"         See log: {log_path}")
        _print_log_tail(log_path)
    log.flush()
    return rc


def _print_log_tail(log_path: Path) -> None:
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    tail = lines[-TAIL_LINES_ON_FAILURE:]
    if not tail:
        return
    print("         --- last log lines ---")
    for line in tail:
        print(f"         {line}")
    print("         ---------------------")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create/refresh the OpenWrt lab VMs, then verify host-side wiring.",
    )
    parser.add_argument(
        "--include-todo",
        action="store_true",
        help="Also run create_VM_*.py scripts whose source contains TODO.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue to later scripts even if one step fails.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the commands without running them.",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Run VM creation scripts but skip verify_lab_from_host.py.",
    )
    parser.add_argument(
        "--include-client",
        action="store_true",
        help="Deprecated no-op; the client VM and serial pipe are always required.",
    )
    args = parser.parse_args()

    log_path, log = open_run_log()
    try:
        try:
            log_display = log_path.relative_to(REPO_ROOT)
        except ValueError:
            log_display = log_path

        print("Lab VM setup")
        print(f"  Log  {log_display}")
        print()

        scripts = discover_create_scripts(
            include_todo=args.include_todo,
            log=log,
        )
        if not scripts:
            print("  No runnable create_VM_*.py scripts found.")
            log.write("[!] No runnable create_VM_*.py scripts found.\n")
            return 1

        steps: list[tuple[str, list[str], Path]] = []
        for script in scripts:
            command = [sys.executable, str(script)]
            if script.name == "create_VM_OpenWrt_router.py":
                command.extend(
                    ["--start-type", "gui", "--wan-mode", "nat", "--start-alpine-client"]
                )
            steps.append((step_label(script), command, script))

        if not args.skip_verify:
            verify_path = SCRIPT_DIR / VERIFY_SCRIPT
            steps.append(
                (
                    step_label(verify_path),
                    [sys.executable, str(verify_path)],
                    verify_path,
                )
            )

        total = len(steps)
        failures: list[tuple[str, int]] = []

        for index, (label, command, script) in enumerate(steps, start=1):
            rc = run_logged_step(
                command,
                cwd=REPO_ROOT,
                log=log,
                log_path=log_path,
                label=label,
                step=index,
                total=total,
                dry_run=args.dry_run,
            )
            if rc != 0:
                failures.append((script.name, rc))
                if not args.keep_going:
                    print()
                    print(f"Stopped after step {index}/{total} failed (exit {rc}).")
                    print(f"Full log: {log_path}")
                    return rc

        print()
        if failures:
            print("Completed with failures:")
            for name, rc in failures:
                print(f"  - {name}: exit {rc}")
            print(f"Full log: {log_path}")
            return failures[0][1]

        print("Done. Lab VMs are ready.")
        print(f"Full log: {log_path}")
        log.write("\n[+] VM setup and verification completed successfully.\n")
        return 0
    finally:
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
