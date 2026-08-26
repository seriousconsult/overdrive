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
import shlex
import shutil
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
from detections.common.common_vm import ensure_kvm_accessible


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
TMUX_SESSION_BASE = "overdrive-vms"
TMUX_ENV_FLAG = "OVERDRIVE_RUN_VMS_TMUX"
TMUX_SESSION_ENV = "OVERDRIVE_RUN_VMS_TMUX_SESSION"
TMUX_SERIAL_READY_ENV = "OVERDRIVE_RUN_VMS_SERIAL_READY_FILE"


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


def _shell_join(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _bash_command(body: str) -> str:
    return "bash -lc " + shlex.quote(body)


def _tmux_session_exists(session_name: str) -> bool:
    return (
        subprocess.run(
            ["tmux", "has-session", "-t", session_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def _cleanup_legacy_tmux_serial_panes() -> None:
    """Stop serial panes created by older run_VMs versions with infinite retry loops."""
    result = subprocess.run(
        ["tmux", "list-panes", "-a", "-F", "#{pane_id}\t#{pane_start_command}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return

    legacy_needles = (
        "Retrying in 5s",
        "create_VM_OpenWrt_router.py --serial-here",
        "create_VM_client_browser_pipe_alpine.py --serial-here",
    )
    for line in result.stdout.splitlines():
        try:
            pane_id, start_command = line.split("\t", 1)
        except ValueError:
            continue
        if "Retrying in 5s" not in start_command:
            continue
        if not any(needle in start_command for needle in legacy_needles[1:]):
            continue
        subprocess.run(["tmux", "kill-pane", "-t", pane_id], check=False)
        print(f"[tmux] Stopped legacy serial retry pane {pane_id}.")


def _available_tmux_session_name() -> str:
    if not _tmux_session_exists(TMUX_SESSION_BASE):
        return TMUX_SESSION_BASE
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{TMUX_SESSION_BASE}-{stamp}"


def _tmux_serial_loop(title: str, command: list[str], *, ready_file: Path) -> str:
    return _bash_command(
        "\n".join(
            [
                f"cd {_shell_join([str(REPO_ROOT)])}",
                f"printf '\\033]2;{title}\\033\\\\'",
                f"ready_file={shlex.quote(str(ready_file))}",
                "until [ -e \"$ready_file\" ]; do",
                "  clear",
                f"  echo '[overdrive] {title}'",
                "  echo 'Host setup is still configuring VMs and using serial for bootstrap.'",
                "  echo 'This pane will attach as soon as the host releases the serial endpoints.'",
                "  sleep 3",
                "done",
                "  clear",
                f"  echo '[overdrive] {title}'",
                "  echo 'Attaching to the VM serial endpoint.'",
                "  echo 'Press Ctrl-] to detach. This pane will not auto-reconnect.'",
                "  echo",
                f"  {_shell_join(command)}",
                "  rc=$?",
                "  echo",
                f"  echo '[overdrive] {title} exited with status '\"$rc\"'.'",
                "  echo 'Run the attach command again when you want to reconnect.'",
                "  exec bash -l",
            ]
        )
    )


def _tmux_host_command(session_name: str, argv: list[str], *, ready_file: Path) -> str:
    child_args = [arg for arg in argv if arg != "--tmux"]
    child_command = [
        sys.executable,
        str(Path(__file__).resolve()),
        *child_args,
    ]
    env_prefix = (
        f"{TMUX_ENV_FLAG}=1 "
        f"{TMUX_SESSION_ENV}={shlex.quote(session_name)} "
        f"{TMUX_SERIAL_READY_ENV}={shlex.quote(str(ready_file))} "
        "PYTHONUNBUFFERED=1"
    )
    return _bash_command(
        "\n".join(
            [
                f"cd {_shell_join([str(REPO_ROOT)])}",
                "printf '\\033]2;overdrive host\\033\\\\'",
                f"{env_prefix} {_shell_join(child_command)}",
                "rc=$?",
                "echo",
                "echo \"[overdrive] run_VMs exited with status $rc\"",
                f"echo \"Detach: Ctrl-b d    Reattach: tmux attach -t {session_name}\"",
                "echo \"This host pane stays open. Type exit to close only this pane.\"",
                "echo",
                # Keep the layout alive after setup; do not exit on Enter.
                "exec bash -i",
            ]
        )
    )


def print_tmux_host_help() -> None:
    session_name = os.environ.get(TMUX_SESSION_ENV, TMUX_SESSION_BASE)
    print("tmux layout")
    print("  top:    host runner, logs, verification")
    print("  bottom: left Alpine client serial, right OpenWrt router serial")
    print()
    print("Move between panes (prefix is Ctrl-b: press it, release, then the next key)")
    print("  mouse click         focus a pane")
    print("  Ctrl-b then o       cycle to the next pane")
    print("  Ctrl-b then h/j/k/l left / down / up / right")
    print("  Ctrl-b then q       show pane numbers; type a number to jump")
    print()
    print("Copy / paste")
    print("  Shift+drag          select text (Windows Terminal / Cursor native copy)")
    print("  Ctrl-b then [       tmux copy mode; y copies to Windows clipboard")
    print("  right-click/Ctrl-v  paste (terminal paste)")
    print()
    print("Other")
    print("  Ctrl-b then z       zoom/unzoom the active pane")
    print("  Ctrl-b then d       detach from tmux")
    print("  exit (in host pane) close only the host pane")
    print(f"  tmux attach -t {session_name}")
    print(f"  tmux kill-session -t {session_name}")
    print()
    print(f"Host run log: run/logs/ (latest run_VMs_*.log under {REPO_ROOT / 'run' / 'logs'})")
    print()


def _configure_tmux_session(session_name: str) -> None:
    """Session options/bindings that work better under WSL/Windows terminals."""
    # Arrow keys after the prefix often never arrive from Windows Terminal / Cursor.
    # Prefer mouse, hjkl, and pane-number jump.
    subprocess.run(
        ["tmux", "set-option", "-t", session_name, "mouse", "on"],
        check=False,
    )
    subprocess.run(
        ["tmux", "set-option", "-t", session_name, "-w", "xterm-keys", "on"],
        check=False,
    )
    subprocess.run(
        ["tmux", "set-option", "-g", "set-clipboard", "on"],
        check=False,
    )
    # Mouse drag in copy-mode → Windows clipboard (clip.exe). Native select still
    # works with Shift+drag when the terminal steals the mouse from tmux.
    for table in ("copy-mode-vi", "copy-mode"):
        subprocess.run(
            [
                "tmux",
                "bind-key",
                "-T",
                table,
                "MouseDragEnd1Pane",
                "send-keys",
                "-X",
                "copy-pipe-and-cancel",
                "clip.exe",
            ],
            check=False,
        )
        subprocess.run(
            [
                "tmux",
                "bind-key",
                "-T",
                table,
                "y",
                "send-keys",
                "-X",
                "copy-pipe-and-cancel",
                "clip.exe",
            ],
            check=False,
        )
    for key, direction in (
        ("h", "-L"),
        ("j", "-D"),
        ("k", "-U"),
        ("l", "-R"),
    ):
        subprocess.run(
            ["tmux", "bind-key", "-T", "prefix", key, "select-pane", direction],
            check=False,
        )


def mark_tmux_serial_ready(log: TextIO) -> None:
    ready_file = os.environ.get(TMUX_SERIAL_READY_ENV)
    if not ready_file:
        return
    path = Path(ready_file)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    except OSError as exc:
        log.write(f"[!] Could not mark tmux serial panes ready at {path}: {exc}\n")
        log.flush()
        print(f"[!] Could not wake tmux serial panes: {exc}")
        return
    log.write(f"[tmux] serial panes ready marker: {path}\n")
    log.flush()
    print(f"[tmux] Serial panes may now attach ({path}).")


def launch_tmux_layout(argv: list[str]) -> int | None:
    if os.environ.get(TMUX_ENV_FLAG):
        return None
    if shutil.which("tmux") is None:
        print("[!] tmux is not installed or not on PATH; continuing without tmux layout.")
        return None
    if not sys.stdout.isatty():
        return None

    _cleanup_legacy_tmux_serial_panes()
    session_name = _available_tmux_session_name()
    ready_file = Path("/tmp") / f"overdrive-{session_name}-serial-ready"
    try:
        ready_file.unlink()
    except FileNotFoundError:
        pass
    host_command = _tmux_host_command(session_name, argv, ready_file=ready_file)
    client_command = _tmux_serial_loop(
        "Alpine client serial :2325",
        [
            sys.executable,
            str(SCRIPT_DIR / "alpine_client" / "create_VM_client_browser_pipe_alpine.py"),
            "--serial-here",
            "--force-interactive-serial",
            "--serial-port",
            "2325",
        ],
        ready_file=ready_file,
    )
    router_command = _tmux_serial_loop(
        "OpenWrt router serial :2324",
        [
            sys.executable,
            str(SCRIPT_DIR / "openwrt_router" / "create_VM_OpenWrt_router.py"),
            "--serial-here",
            "--force-interactive-serial",
        ],
        ready_file=ready_file,
    )

    # Detached sessions need an explicit size; tmux 3.4 also dropped split -p
    # (use -l with a % suffix). Without both, split-window fails with "size missing".
    cols, rows = shutil.get_terminal_size(fallback=(120, 40))
    cols = max(cols, 100)
    rows = max(rows, 30)

    subprocess.run(
        [
            "tmux",
            "new-session",
            "-d",
            "-s",
            session_name,
            "-n",
            "lab",
            "-x",
            str(cols),
            "-y",
            str(rows),
            "-c",
            str(REPO_ROOT),
            host_command,
        ],
        check=True,
    )
    host_pane = (
        subprocess.check_output(
            ["tmux", "display-message", "-p", "-t", f"{session_name}:lab", "#{pane_id}"],
            text=True,
        )
        .strip()
    )
    try:
        client_pane = (
            subprocess.check_output(
                [
                    "tmux",
                    "split-window",
                    "-P",
                    "-F",
                    "#{pane_id}",
                    "-t",
                    host_pane,
                    "-v",
                    "-l",
                    "35%",
                    "-c",
                    str(REPO_ROOT),
                    client_command,
                ],
                text=True,
            )
            .strip()
        )
        router_pane = (
            subprocess.check_output(
                [
                    "tmux",
                    "split-window",
                    "-P",
                    "-F",
                    "#{pane_id}",
                    "-t",
                    client_pane,
                    "-h",
                    "-l",
                    "50%",
                    "-c",
                    str(REPO_ROOT),
                    router_command,
                ],
                text=True,
            )
            .strip()
        )
    except subprocess.CalledProcessError:
        subprocess.run(["tmux", "kill-session", "-t", session_name], check=False)
        raise
    for pane, title in (
        (host_pane, "host"),
        (client_pane, "client serial"),
        (router_pane, "router serial"),
    ):
        subprocess.run(["tmux", "select-pane", "-t", pane, "-T", title], check=True)
    subprocess.run(["tmux", "select-pane", "-t", host_pane], check=True)
    _configure_tmux_session(session_name)

    if os.environ.get("TMUX"):
        subprocess.run(["tmux", "switch-client", "-t", session_name], check=True)
    else:
        subprocess.run(["tmux", "attach-session", "-t", session_name], check=True)
    return 0


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
        "--tmux",
        dest="tmux",
        action="store_true",
        default=True,
        help="Run inside the managed tmux layout when stdout is interactive. Default: on.",
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
    ensure_kvm_accessible()
    if args.tmux:
        tmux_rc = launch_tmux_layout(sys.argv[1:])
        if tmux_rc is not None:
            return tmux_rc

    log_path, log = open_run_log()
    try:
        try:
            log_display = log_path.relative_to(REPO_ROOT)
        except ValueError:
            log_display = log_path

        print("Lab VM setup")
        print(f"  Log  {log_display}")
        print()
        if os.environ.get(TMUX_ENV_FLAG):
            print_tmux_host_help()

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
                    [
                        "--start-type",
                        "gui",
                        "--start-alpine-client",
                    ]
                )
                if os.environ.get(TMUX_ENV_FLAG) or not sys.stdout.isatty():
                    command.append("--no-connect-serial")
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
        created_vms = False

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
                    if os.environ.get(TMUX_ENV_FLAG) and created_vms:
                        mark_tmux_serial_ready(log)
                    print()
                    print(f"Stopped after step {index}/{total} failed (exit {rc}).")
                    print(f"Full log: {log_path}")
                    return rc
            elif script.name == "create_VM_OpenWrt_router.py":
                created_vms = True

        print()
        if os.environ.get(TMUX_ENV_FLAG) and created_vms:
            mark_tmux_serial_ready(log)

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
