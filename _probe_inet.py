#!/usr/bin/env python3
"""Probe OpenWrt WAN + one client for internet path."""
from __future__ import annotations

import subprocess
import time

ROUTER = "%18"
CLIENTK = "%14"
CLIENTA = "%16"


def send(pane: str, cmd: str, wait: float = 0.3) -> None:
    subprocess.run(["tmux", "send-keys", "-t", pane, cmd, "C-m"], check=True)
    time.sleep(wait)


def capture(pane: str, lines: int = 60) -> str:
    return subprocess.check_output(
        ["tmux", "capture-pane", "-t", pane, "-p", "-S", f"-{lines}"],
        text=True,
    )


# --- Router ---
send(ROUTER, "echo =====ROUTER=====")
send(ROUTER, "ip -4 addr; echo ---; ip -4 route")
send(ROUTER, "ping -c2 -W3 10.0.2.2; ping -c2 -W3 8.8.8.8; ping -c2 -W3 1.1.1.1")
send(ROUTER, "nslookup google.com 127.0.0.1; ping -c2 -W3 google.com")
send(ROUTER, "wget -qO- --timeout=5 http://1.1.1.1/cdn-cgi/trace 2>&1 | head -8; echo WGET_IP:$?")
send(ROUTER, "wget -qO- --timeout=5 http://detectportal.firefox.com/success.txt 2>&1; echo WGET_DNS:$?")
send(ROUTER, "iptables -t nat -S 2>/dev/null | head -30; echo ---; iptables -S FORWARD 2>/dev/null | head -30")
send(ROUTER, "uci show firewall | head -40; fw4 print 2>/dev/null | head -5 || fw3 print 2>/dev/null | head -5 || true")
send(ROUTER, "ifstatus wan | head -60")
time.sleep(22)
print("======== ROUTER ========")
print(capture(ROUTER, 90))

# --- Clientk ---
send(CLIENTK, "echo =====CLIENTK=====")
send(CLIENTK, "ip -br -4 addr; ip route; cat /etc/resolv.conf 2>&1")
send(CLIENTK, "ping -c2 -W2 192.168.50.1; ping -c2 -W3 8.8.8.8; ping -c2 -W3 google.com")
send(CLIENTK, "curl -sI --max-time 5 https://1.1.1.1 2>&1 | head -5; curl -sI --max-time 5 https://example.com 2>&1 | head -5")
time.sleep(16)
print("======== CLIENTK ========")
print(capture(CLIENTK, 50))

# --- Clienta ---
send(CLIENTA, "echo =====CLIENTA=====")
send(CLIENTA, "ip -br -4 addr; ip route; cat /etc/resolv.conf 2>&1")
send(CLIENTA, "ping -c2 -W2 192.168.50.1; ping -c2 -W3 8.8.8.8; ping -c2 -W3 google.com")
time.sleep(12)
print("======== CLIENTA ========")
print(capture(CLIENTA, 40))
