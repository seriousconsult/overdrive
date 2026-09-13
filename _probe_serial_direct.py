#!/usr/bin/env python3
"""Direct TCP serial probe of lab guests (bypass detached tmux panes)."""
from __future__ import annotations

import re
import socket
import time
from pathlib import Path


def _read_env() -> dict[str, str]:
    env: dict[str, str] = {}
    path = Path("/mnt/c/code/overdrive/VM/.env")
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def serial_transact(port: int, commands: list[str], *, login_user: str, password: str, settle: float = 0.8) -> str:
    sock = socket.create_connection(("127.0.0.1", port), timeout=8)
    sock.settimeout(0.4)
    buf = bytearray()

    def recv_for(seconds: float) -> None:
        end = time.time() + seconds
        while time.time() < end:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
            except socket.timeout:
                pass

    def send(data: str) -> None:
        sock.sendall(data.encode("utf-8", errors="ignore"))

    # Wake console
    send("\r\n")
    recv_for(1.5)
    text = buf.decode("utf-8", errors="replace")
    if "login:" in text.lower() or re.search(r"login:", text, re.I):
        send(login_user + "\r\n")
        recv_for(1.2)
        send(password + "\r\n")
        recv_for(1.5)
    elif "Password:" in text:
        send(password + "\r\n")
        recv_for(1.5)
    else:
        # Maybe already logged in — send a marker
        send("\r\n")
        recv_for(0.5)

    marker = f"__END_{port}__"
    for cmd in commands:
        send(cmd + "\r\n")
        recv_for(settle)
    send(f"echo {marker}\r\n")
    # Wait until marker appears or timeout
    end = time.time() + 25
    while time.time() < end:
        recv_for(0.5)
        if marker.encode() in buf:
            # get a little more after marker
            recv_for(0.8)
            break

    sock.close()
    return buf.decode("utf-8", errors="replace")


def main() -> None:
    env = _read_env()
    router_pw = env.get("OPENWRT_ROOT_PASSWORD", "")
    kali_pw = env.get("KALI_CLIENT_ROOT_PASSWORD", "k")
    alpine_pw = env.get("ALPINE_CLIENT_ROOT_PASSWORD", "d")

    router_cmds = [
        "echo =====ROUTER=====",
        "ip -4 addr",
        "ip -4 route",
        "ifstatus wan 2>/dev/null | head -40",
        "ping -c2 -W3 10.0.2.2; ping -c2 -W3 8.8.8.8",
        "nslookup google.com 127.0.0.1",
        "ping -c2 -W3 google.com",
        "wget -qO- --timeout=5 http://1.1.1.1/cdn-cgi/trace 2>&1 | head -6",
        "wget -qO- --timeout=5 http://detectportal.firefox.com/success.txt 2>&1; echo WGET:$?",
        "iptables -t nat -S 2>/dev/null | head -25",
        "iptables -S FORWARD 2>/dev/null | head -25",
        "uci show firewall.@zone[1] 2>/dev/null; uci get firewall.@defaults[0].forward 2>/dev/null",
        "uci show network.wan; uci show network.lan | head -20",
        "cat /tmp/dhcp.leases 2>/dev/null | head -20",
    ]
    print("######## ROUTER :2324 ########")
    print(serial_transact(2324, router_cmds, login_user="root", password=router_pw, settle=1.0))

    kali_cmds = [
        "echo =====CLIENTK=====",
        "ip -br -4 addr; ip route; cat /etc/resolv.conf",
        "ping -c2 -W2 192.168.50.1; ping -c2 -W3 8.8.8.8; ping -c2 -W3 google.com",
        "curl -sI --max-time 5 http://1.1.1.1 2>&1 | head -5",
        "curl -sI --max-time 5 https://example.com 2>&1 | head -5",
        "systemctl is-active lab-net-up.service 2>&1; systemctl is-failed lab-net-up.service 2>&1",
    ]
    print("######## CLIENTK :2326 ########")
    print(serial_transact(2326, kali_cmds, login_user="root", password=kali_pw, settle=1.2))

    alpine_cmds = [
        "echo =====CLIENTA=====",
        "ip -br -4 addr; ip route; cat /etc/resolv.conf",
        "ping -c2 -W2 192.168.50.1; ping -c2 -W3 8.8.8.8; ping -c2 -W3 google.com",
        "wget -qO- -T5 http://detectportal.firefox.com/success.txt 2>&1; echo WGET:$?",
    ]
    print("######## CLIENTA :2325 ########")
    print(serial_transact(2325, alpine_cmds, login_user="root", password=alpine_pw, settle=1.0))


if __name__ == "__main__":
    main()
