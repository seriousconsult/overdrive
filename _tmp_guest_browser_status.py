#!/usr/bin/env python3
from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

from VM.alpine_client.client_config import ALPINE_SERIAL_TCP_PORT
from VM.vm_config import alpine_client_root_password


def main() -> int:
    password = alpine_client_root_password()
    print("password_len", len(password), "port", ALPINE_SERIAL_TCP_PORT, flush=True)
    sock = socket.create_connection(("127.0.0.1", ALPINE_SERIAL_TCP_PORT), timeout=5)
    sock.settimeout(0.5)
    print("connected", flush=True)

    def drain(wait: float = 1.0) -> str:
        end = time.time() + wait
        buf = bytearray()
        while time.time() < end:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    print("peer closed", flush=True)
                    break
                buf.extend(chunk)
                end = time.time() + 0.25
            except TimeoutError:
                pass
            except socket.timeout:
                pass
        return buf.decode("utf-8", "replace")

    def send(line: str) -> None:
        data = (line + "\r").encode()
        sock.sendall(data)

    collected = ""
    started = time.time()
    for i in range(40):
        try:
            send("")
        except OSError as exc:
            print("send_fail", i, exc, flush=True)
            break
        chunk = drain(0.6)
        if chunk:
            print(f"i={i} chunk={chunk!r}", flush=True)
            collected += chunk
        low = collected[-1500:].lower()
        if "login:" in low:
            print("sending root", flush=True)
            send("root")
            continue
        if "password:" in low:
            print("sending password", flush=True)
            send(password)
            continue
        if "#" in collected[-120:]:
            print("shell ready", flush=True)
            break
    else:
        print("timeout_no_shell elapsed", round(time.time() - started, 1), flush=True)
        print("collected_repr", repr(collected[-2000:]), flush=True)
        sock.close()
        return 3

    send("stty -echo")
    drain(0.3)
    marker = "ODxDONE"
    send(
        "echo ===REPORT===; "
        "ls -la /root/detections/browser/browser_detection_results.html 2>&1; "
        "grep -E 'badge err|EXPIRED|Error|STATUS' "
        "/root/detections/browser/browser_detection_results.html 2>/dev/null | head -100; "
        "echo ===PS===; ps w | head -40; "
        "echo ===TO===; "
        "grep -n BROWSER_SCRIPT_TIMEOUT_SEC /root/detections/run_detections.py 2>&1 | head; "
        f"echo {marker}"
    )
    out = ""
    end = time.time() + 25
    while time.time() < end:
        out += drain(1.0)
        if marker in out:
            break
    print(out, flush=True)
    sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
