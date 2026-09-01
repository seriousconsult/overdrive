#!/usr/bin/env python3
"""Push timeout fixes + run one guest browser probe for diagnosis."""

from __future__ import annotations

import base64
import re
import socket
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
PORT = 2325

FILES = [
    "detections/run_detections.py",
    "detections/run_browser_detections.py",
    "detections/common/common_browser.py",
    "detections/common/direct_chromium.py",
]


def drain(sock: socket.socket, wait: float = 1.0) -> str:
    end = time.time() + wait
    buf = bytearray()
    while time.time() < end:
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf.extend(chunk)
            end = time.time() + 0.15
        except (TimeoutError, socket.timeout):
            pass
    return buf.decode("utf-8", "replace")


def send(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\r").encode())


def wait_marker(sock: socket.socket, marker: str, timeout: float) -> str:
    out = ""
    end = time.time() + timeout
    while time.time() < end:
        out += drain(sock, 0.8)
        if marker in out:
            return out
    raise TimeoutError(f"missing {marker}; tail={out[-1000:]!r}")


def run_cmd(sock: socket.socket, cmd: str, marker: str, timeout: float = 30.0) -> str:
    done = f"OD{marker}DONE"
    send(sock, f"{cmd}; echo {done}")
    return wait_marker(sock, done, timeout)


def push_file(sock: socket.socket, rel: str) -> None:
    data = (REPO / rel).read_bytes()
    b64 = base64.b64encode(data).decode("ascii")
    remote = f"/root/{rel}"
    print(f"[*] push {rel} ({len(data)} bytes)", flush=True)
    run_cmd(sock, f"mkdir -p $(dirname {remote}); : > /tmp/odf.b64", "F0", 10)
    chunk = 700
    for i in range(0, len(b64), chunk):
        piece = b64[i : i + chunk]
        run_cmd(sock, f"printf '%s' '{piece}' >> /tmp/odf.b64", f"F{i // chunk}", 10)
    run_cmd(
        sock,
        f"base64 -d /tmp/odf.b64 > {remote} && rm -f /tmp/odf.b64 && "
        f"test -s {remote} && echo OK_{rel}",
        "FX",
        30,
    )


def main() -> int:
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    sock.settimeout(0.5)
    print("[*] connected", flush=True)
    send(sock, "")
    drain(sock, 0.6)
    send(sock, "stty -echo")
    drain(sock, 0.3)

    print(run_cmd(sock, "grep -n 'BROWSER_SCRIPT_TIMEOUT_SEC =' /root/detections/run_detections.py", "PRE", 15)[-400:], flush=True)

    for rel in FILES:
        push_file(sock, rel)

    print(
        run_cmd(
            sock,
            "grep -n 'BROWSER_SCRIPT_TIMEOUT_SEC =' /root/detections/run_detections.py; "
            "grep -n 'DEFAULT_PROBE_EXPIRATION =' /root/detections/common/direct_chromium.py",
            "VER",
            15,
        )[-500:],
        flush=True,
    )

    # Quick chromium smoke + one probe
    print("[*] smoke: shared chromium startup via one probe", flush=True)
    marker = "ODSMOKEEND"
    send(
        sock,
        "cd /root && /root/virtual_env/bin/python detections/browser/cookie_tracking.py "
        f"--timeout 120; echo {marker}:$?",
    )
    out = ""
    end = time.time() + 300
    while time.time() < end:
        chunk = drain(sock, 1.0)
        if chunk:
            sys.stdout.write(chunk)
            sys.stdout.flush()
            out += chunk
        if re.search(rf"{re.escape(marker)}:\d+", out):
            break
    else:
        print("\n[!] smoke timeout", flush=True)

    print("\n[*] full suite", flush=True)
    marker = "ODFULLEND"
    send(
        sock,
        "cd /root && /root/virtual_env/bin/python detections/run_browser_detections.py "
        f"--deny-external --timeout 500; echo {marker}:$?",
    )
    out = ""
    end = time.time() + 900
    while time.time() < end:
        chunk = drain(sock, 1.2)
        if chunk:
            sys.stdout.write(chunk)
            sys.stdout.flush()
            out += chunk
        if re.search(rf"{re.escape(marker)}:\d+", out):
            break
    else:
        print("\n[!] suite timeout", flush=True)
        sock.close()
        return 2

    print("\n[*] report", flush=True)
    print(
        run_cmd(
            sock,
            "grep -E 'badge err|EXPIRED|Error|STATUS|badge n' "
            "/root/detections/browser/browser_detection_results.html | head -80",
            "REP",
            20,
        )[-5000:],
        flush=True,
    )
    sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
