#!/usr/bin/env python3
"""Run the VM lab, then run browser detections inside the Alpine client.

The client is intentionally hardened without SSH/Guest Additions, so this uses
the VirtualBox serial console to log in and launch the in-guest browser runner.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import select
import shlex
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detections.common.common_vm import (  # noqa: E402
    SERIAL_TCP_HOST,
    serial_tcp_host_candidates,
)
from VM.alpine_client.client_config import ALPINE_SERIAL_TCP_PORT  # noqa: E402
from VM.vm_config import alpine_client_root_password  # noqa: E402


RUN_DIR = Path(__file__).resolve().parent
LOG_DIR = RUN_DIR / "logs"
RUN_VMS = RUN_DIR / "run_VMs.py"

DEFAULT_BROWSER_TIMEOUT = 75
DEFAULT_CLIENT_READY_TIMEOUT = 180
DEFAULT_BROWSER_RUN_TIMEOUT = 900
TAIL_LINES_ON_FAILURE = 24
ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes, secs = divmod(total, 60)
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def open_log() -> tuple[Path, object]:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = LOG_DIR / f"client_browser_after_vms_{stamp}.log"
    handle = path.open("w", encoding="utf-8", errors="replace")
    handle.write(f"started={datetime.now().isoformat(timespec='seconds')}\n")
    handle.write(f"cwd={REPO_ROOT}\n")
    handle.write(f"python={sys.executable}\n")
    handle.write(f"argv={' '.join(sys.argv)}\n\n")
    handle.flush()
    return path, handle


def stream_command(
    command: list[str],
    *,
    timeout: int | None,
    log,
) -> int:
    print(f"[*] Running: {' '.join(shlex.quote(part) for part in command)}")
    started = time.monotonic()
    proc = subprocess.Popen(
        command,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout if timeout else None
    os.set_blocking(proc.stdout.fileno(), False)

    while True:
        if deadline is not None and time.monotonic() > deadline:
            proc.kill()
            log.write("\n[!] child timed out\n")
            log.flush()
            return 124
        readable, _, _ = select.select([proc.stdout], [], [], 0.5)
        if proc.stdout in readable:
            chunk = proc.stdout.read()
            if chunk:
                log.write(chunk)
                log.flush()
                print(chunk, end="")
                continue
        rc = proc.poll()
        if rc is not None:
            break
        time.sleep(0.1)

    rest = proc.stdout.read()
    if rest:
        log.write(rest)
        print(rest, end="")
    log.flush()
    elapsed = format_duration(time.monotonic() - started)
    print(f"[*] run_VMs exited {proc.returncode} after {elapsed}")
    return int(proc.returncode or 0)


def print_log_tail(log_path: Path) -> None:
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    print("--- log tail ---")
    for line in lines[-TAIL_LINES_ON_FAILURE:]:
        print(line)
    print("----------------")


@contextmanager
def serial_attach_lock(port: int):
    lock_path = Path("/tmp") / f"overdrive-serial-{port}.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                f"Serial TCP :{port} is already attached. Close the client serial pane/window first."
            ) from exc
        os.ftruncate(fd, 0)
        os.write(fd, f"pid={os.getpid()}\n".encode("ascii"))
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def open_client_serial(port: int, *, timeout_s: float) -> socket.socket:
    candidates = serial_tcp_host_candidates(SERIAL_TCP_HOST)
    deadline = time.monotonic() + timeout_s
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        for host in candidates:
            try:
                sock = socket.create_connection((host, port), timeout=1.0)
                sock.setblocking(False)
                return sock
            except OSError as exc:
                last_error = exc
        time.sleep(0.5)
    raise RuntimeError(f"Could not connect to client serial TCP :{port}: {last_error}")


def serial_drain(sock: socket.socket, *, wait_s: float = 0.3) -> str:
    buf = bytearray()
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        readable, _, _ = select.select([sock], [], [], min(0.25, remaining))
        if sock not in readable:
            continue
        try:
            chunk = sock.recv(8192)
        except BlockingIOError:
            continue
        if not chunk:
            break
        buf.extend(chunk)
        deadline = time.monotonic() + wait_s
    return buf.decode("utf-8", errors="replace")


def serial_send(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\r").encode("utf-8", errors="replace"))


def line_has_marker(buf: str, marker: str) -> bool:
    return any(line.strip() == marker for line in buf.replace("\r", "\n").splitlines())


def strip_ansi_control(text: str) -> str:
    return ANSI_CSI_RE.sub("", text)


def wait_for_client_shell(
    sock: socket.socket,
    *,
    password: str,
    timeout_s: float,
    log,
) -> None:
    print("[*] Waiting for Alpine client serial login...")
    deadline = time.monotonic() + timeout_s
    collected = ""
    next_enter_at = 0.0
    sent_login = False
    sent_password = False

    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_enter_at:
            serial_send(sock, "")
            next_enter_at = now + 2.0
        chunk = serial_drain(sock, wait_s=0.5)
        if chunk:
            log.write(chunk)
            log.flush()
            collected += chunk
        tail = collected[-1000:]
        visible_tail = strip_ansi_control(tail)
        lower = visible_tail.lower()
        if re.search(r"(^|\n)[^\n]*[#] ?$", visible_tail):
            serial_send(sock, "stty -echo")
            serial_drain(sock, wait_s=0.2)
            print("[*] Client shell is ready.")
            return
        if "login:" in lower and not sent_login:
            serial_send(sock, "root")
            sent_login = True
            sent_password = False
            continue
        if "password:" in lower and not sent_password:
            serial_send(sock, password)
            sent_password = True
            continue
        if "login incorrect" in lower or "authentication failure" in lower:
            sent_login = False
            sent_password = False
        time.sleep(0.2)

    raise RuntimeError(f"Client serial shell did not become ready. Last output:\n{collected[-1500:]}")


def run_client_browser_detections(
    sock: socket.socket,
    *,
    browser_timeout: int,
    browser_args: list[str],
    run_timeout: int,
    log,
) -> tuple[int, str]:
    marker = f"ODBR{int(time.time()) % 100000}"
    start_marker = f"{marker}START"
    end_marker = f"{marker}END"
    remote_cmd = [
        "python3",
        "detections/run_browser_detections.py",
        "--timeout",
        str(browser_timeout),
        *browser_args,
    ]
    command = "cd /root && " + " ".join(shlex.quote(part) for part in remote_cmd)

    print("[*] Running browser detections inside the client...")
    serial_drain(sock, wait_s=0.3)
    serial_send(sock, f"echo {start_marker}")

    started_seen = False
    output = ""
    deadline = time.monotonic() + run_timeout
    serial_send(sock, f"{command}; rc=$?; echo {end_marker}:$rc")

    while time.monotonic() < deadline:
        chunk = serial_drain(sock, wait_s=0.6)
        if chunk:
            log.write(chunk)
            log.flush()
            output += chunk
            if not started_seen and line_has_marker(output, start_marker):
                started_seen = True
        for line in output.replace("\r", "\n").splitlines():
            match = re.match(rf"^\s*{re.escape(end_marker)}:(\d+)\s*$", line)
            if match:
                return int(match.group(1)), output
        time.sleep(0.1)

    raise TimeoutError(f"Browser detection command did not finish within {run_timeout}s")


def extract_summary(output: str) -> list[str]:
    lines = [line.rstrip() for line in output.replace("\r", "\n").splitlines()]
    summary_start = None
    for index, line in enumerate(lines):
        if line.strip() == "SUMMARY":
            summary_start = index
    if summary_start is None:
        return []

    summary: list[str] = []
    for line in lines[summary_start + 1 :]:
        stripped = line.strip()
        if stripped.startswith("HTML report:") or stripped.startswith("Elapsed:"):
            summary.append(stripped)
            continue
        if stripped.startswith("BROWSER:") or re.match(r"^[A-Za-z0-9_./-]+\.py:", stripped):
            summary.append(line)
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run run_VMs.py, then run browser detections inside the test client.",
    )
    parser.add_argument(
        "--skip-vms",
        action="store_true",
        help="Skip run_VMs.py and only run browser detections on the running client.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Pass --keep-going through to run_VMs.py.",
    )
    parser.add_argument(
        "--vm-start-type",
        choices=("gui", "headless", "separate", "none"),
        default=os.environ.get("OVERDRIVE_VM_START_TYPE", "gui"),
        help=(
            "VirtualBox frontend passed to run_VMs.py. Default: gui. "
            "Browser probes still run under private Xvfb/headless Chromium; "
            "use headless only on hosts where the VirtualBox headless frontend works."
        ),
    )
    parser.add_argument(
        "--vm-timeout",
        type=int,
        default=3600,
        help="Seconds to allow run_VMs.py; use 0 for no timeout.",
    )
    parser.add_argument(
        "--client-ready-timeout",
        type=int,
        default=DEFAULT_CLIENT_READY_TIMEOUT,
        help="Seconds to wait for the client serial login.",
    )
    parser.add_argument(
        "--browser-timeout",
        type=int,
        default=DEFAULT_BROWSER_TIMEOUT,
        help="Per-probe timeout passed to run_browser_detections.py.",
    )
    parser.add_argument(
        "--browser-run-timeout",
        type=int,
        default=DEFAULT_BROWSER_RUN_TIMEOUT,
        help="Seconds to allow the full browser suite inside the client.",
    )
    parser.add_argument(
        "--browser-arg",
        action="append",
        default=[],
        help="Extra argument passed to run_browser_detections.py; repeat as needed.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(line_buffering=True)
        sys.stderr.reconfigure(line_buffering=True)
    except AttributeError:
        pass

    args = parse_args(argv)
    log_path, log = open_log()
    try:
        print("Overdrive VM + client browser run")
        print(f"  Log: {log_path.relative_to(REPO_ROOT)}")
        print()

        if not args.skip_vms:
            vm_command = [
                sys.executable,
                str(RUN_VMS),
                "--no-tmux",
                "--start-type",
                args.vm_start_type,
            ]
            if args.keep_going:
                vm_command.append("--keep-going")
            rc = stream_command(
                vm_command,
                timeout=None if args.vm_timeout <= 0 else args.vm_timeout,
                log=log,
            )
            if rc != 0:
                print()
                print(f"[!] run_VMs.py failed with exit {rc}.")
                if args.vm_start_type == "headless":
                    try:
                        log_text = log_path.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        log_text = ""
                    if "0xc0000005" in log_text or "terminated unexpectedly during startup" in log_text:
                        print(
                            "[!] VirtualBox headless frontend crashed before guest boot. "
                            "Use --vm-start-type gui on this host, or repair VirtualBox headless support."
                        )
                print_log_tail(log_path)
                return rc

        password = alpine_client_root_password()
        with serial_attach_lock(ALPINE_SERIAL_TCP_PORT):
            with open_client_serial(
                ALPINE_SERIAL_TCP_PORT,
                timeout_s=args.client_ready_timeout,
            ) as sock:
                wait_for_client_shell(
                    sock,
                    password=password,
                    timeout_s=args.client_ready_timeout,
                    log=log,
                )
                rc, output = run_client_browser_detections(
                    sock,
                    browser_timeout=args.browser_timeout,
                    browser_args=args.browser_arg,
                    run_timeout=args.browser_run_timeout,
                    log=log,
                )

        print()
        print("Client Browser Results")
        summary = extract_summary(output)
        if summary:
            for line in summary:
                print(line)
        else:
            print("(summary block not found; see full serial transcript in the log)")
        print()
        print(f"Client browser runner exited {rc}.")
        print(f"Full transcript: {log_path}")
        return rc
    except KeyboardInterrupt:
        print()
        print("[!] Interrupted.")
        print(f"Full transcript: {log_path}")
        return 130
    except Exception as exc:
        log.write(f"\n[!] {type(exc).__name__}: {exc}\n")
        log.flush()
        print()
        print(f"[!] {type(exc).__name__}: {exc}")
        print(f"Full transcript: {log_path}")
        print_log_tail(log_path)
        return 2
    finally:
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
