#!/usr/bin/env python3


'''TCP Stack Fingerprinting (Layer 4)

Every OS (Windows, Linux, iOS) handles TCP packets slightly differently
 (initial window size, TTL, etc.). Some VPNs change these values to look like a different OS.
If your IP says "Linux Server" (VPN) but your TCP fingerprint says "iPhone," 
a site may flag you for "Proxy Usage."

Because this is below packet level Python is not the ideal tool.

NOTE:scapy needs sudo however sudo does not use the Python virtual env. So you need to run like this: 
sudo /mnt/c/code/overdrive/virtual_env/bin/python /mnt/c/code/overdrive/vpn/TCP_stack.py

'''
#!/usr/bin/env python3
"""
TCP SYN stack inspection + comparison vs actual OS environment.

- Reads wsl_syn.pcap
- For each outgoing SYN packet:
  - extracts TTL, TCP window, and TCP options (MSS, WScale, Timestamp, SACK/SAckOK)
  - classifies as Linux-like vs Windows-like (heuristic)
- Detects the actual runtime OS/kernel environment (Windows/Linux/WSL)
- Compares: captured SYN classification vs actual OS expectation

"""
#!/usr/bin/env python3
"""
TCP SYN stack inspection + comparison vs actual OS environment (WSL focused).

Run (note: scapy capture needs sudo):
  sudo /mnt/c/code/overdrive/virtual_env/bin/python /mnt/c/code/overdrive/vpn/TCP_stack.py

This version:
- Captures outgoing TCP SYN packets using AsyncSniffer
- Generates IPv4-only TCP SYN traffic using a Python subprocess (NO curl)
- Tries each Scapy-discovered interface until it captures packets
"""

import os
import platform
import subprocess
from collections import Counter
import time

from scapy.all import (
    sniff, TCP, IP, conf, L3RawSocket, get_if_list, AsyncSniffer
)

# --- CONFIGURATION ---
conf.L3socket = L3RawSocket

TARGET_HOST = "google.com"   # IPv4-only connect will be attempted
TARGET_PORT = 443            # change to 80/443/etc if desired
TRAFFIC_SUBPROCESS_TIMEOUT = 10
CAPTURE_PACKET_COUNT = 3
CAPTURE_TIMEOUT = 10


def get_linux_distro_info():
    if platform.system() != "Linux":
        return {"error": "System is not Linux", "os": platform.system()}

    try:
        result = subprocess.run(
            ["cat", "/etc/os-release"],
            capture_output=True,
            text=True,
            check=True,
        )
        data = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value.strip('"')
        return data
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to retrieve OS info: {e}"}
    except FileNotFoundError:
        return {"error": "/etc/os-release not found."}


def detect_runtime_os():
    sysname = platform.system().lower()
    is_wsl = False
    try:
        if os.environ.get("WSL_DISTRO_NAME"):
            is_wsl = True
        else:
            with open("/proc/version", "r", encoding="utf-8", errors="ignore") as f:
                if "microsoft" in f.read().lower():
                    is_wsl = True
    except Exception:
        pass

    if "windows" in sysname:
        return ("Windows", "Windows-like")
    if sysname == "linux" and is_wsl:
        return ("Linux (WSL)", "Linux-like")
    return ("Linux", "Linux-like")


def extract_syn_features(pkt):
    ip = pkt[IP]
    tcp = pkt[TCP]
    opts = tcp.options or []
    mss = next((val for name, val in opts if name == "MSS"), None)

    return {
        "ip_src": ip.src,
        "ip_dst": ip.dst,
        "ip_ttl": int(ip.ttl),
        "tcp_win": int(tcp.window),
        "mss": mss,
        "opts": opts,
    }


def classify_linux_vs_windows(ip_ttl, tcp_win, opts_list):
    opt_names = [str(item[0]) if isinstance(item, tuple) else str(item) for item in (opts_list or [])]

    linux_score = 0
    windows_score = 0

    if ip_ttl <= 70:
        linux_score += 3
    if ip_ttl >= 100:
        windows_score += 3

    for opt in ["WScale", "Timestamp", "SAckOK", "MSS"]:
        if opt in opt_names:
            linux_score += 1
            windows_score += 1

    if tcp_win <= 70000:
        linux_score += 1

    if linux_score > windows_score + 1:
        return "Linux-like", "medium-high", linux_score, windows_score
    if windows_score > linux_score + 1:
        return "Windows-like", "medium-high", linux_score, windows_score
    return "Uncertain", "low", linux_score, windows_score


def traffic_subprocess_ipv4_connect(host: str, port: int):
    """
    Generates outbound IPv4 TCP SYNs by attempting a TCP connect.
    Implemented as a subprocess to match your requirement.
    """
    # Force IPv4 (AF_INET), connect, then close immediately.
    # We keep it quick so the capture window is focused.
    traffic_code = r"""
import socket, sys
host = sys.argv[1]
port = int(sys.argv[2])
addrinfos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
# try first IPv4 address
af, socktype, proto, canonname, sa = addrinfos[0]
s = socket.socket(af, socktype, proto)
s.settimeout(3.0)
try:
    s.connect(sa)
except Exception:
    pass
finally:
    try:
        s.close()
    except Exception:
        pass
"""
    cmd = [
        "python3",
        "-c",
        traffic_code,
        host,
        str(port),
    ]
    subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=TRAFFIC_SUBPROCESS_TIMEOUT,
        check=False,
    )


def capture_live_syn_inline_subprocess(packet_count=3, timeout=30):
    """
    Captures outgoing TCP SYN packets (IPv4-only) while generating traffic via a subprocess.
    Tries each interface until packets are captured.
    """
    # Required: standard working expression + IPv4 restriction
    syn_filter = "ip and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"

    ifaces = get_if_list() or []
    print(f"[*] Using filter: {syn_filter}")
    print(f"[*] Interfaces discovered by scapy: {ifaces}")

    if not ifaces:
        print("[-] Error: no interfaces discovered via scapy.get_if_list().")
        return []

    # Prefer non-loopback first
    candidates = [i for i in ifaces if i != "lo"]
    if "lo" in ifaces:
        candidates.append("lo")

    print(f"[*] Interface attempt order: {candidates}")

    for iface in candidates:
        print(f"[*] Starting sniffer on iface='{iface}' ...")
        sniffer = AsyncSniffer(
            iface=iface,
            filter=syn_filter,
            store=True,
        )
        sniffer.start()

        # Give the sniffer a moment to arm before traffic generation
        time.sleep(0.3)

        print(f"[*] Generating IPv4 TCP traffic to {TARGET_HOST}:{TARGET_PORT} (subprocess) ...")
        traffic_subprocess_ipv4_connect(TARGET_HOST, TARGET_PORT)

        # Allow a small grace period for packets to arrive
        time.sleep(0.5)

        # Stop sniffer and collect results
        sniffer.stop()

        pkts = sniffer.results or []
        # Optionally trim to expected count
        if packet_count and len(pkts) > packet_count:
            pkts = pkts[:packet_count]

        print(f"    -> captured {len(pkts)} packet(s) on iface='{iface}'")
        if pkts:
            return pkts

    return []


def main():
    runtime_label, expected_stack = detect_runtime_os()
    print("=== TCP Stack Inspection (Live WSL) ===")
    print(f"Runtime: {runtime_label} | Expected: {expected_stack}\n")

    pkts = capture_live_syn_inline_subprocess(
        packet_count=CAPTURE_PACKET_COUNT,
        timeout=CAPTURE_TIMEOUT,
    )

    os_info = get_linux_distro_info()
    if "error" in os_info:
        print(f"Alert: {os_info['error']}")
    else:
        print(f"Successfully identified OS: {os_info.get('PRETTY_NAME')}")

    if not pkts:
        print("[-] Error: No packets captured.")
        print("    Suggestions:")
        print("    - Change TARGET_HOST / TARGET_PORT (e.g., 1.1.1.1:443 or example.com:80).")
        print("    - If you still see 0 packets on all interfaces, verify with tcpdump ground truth.")
        return

    syn_results = []
    for p in pkts:
        if IP in p and TCP in p:
            feats = extract_syn_features(p)
            label, conf_lvl, l_score, w_score = classify_linux_vs_windows(
                feats["ip_ttl"], feats["tcp_win"], feats["opts"]
            )
            syn_results.append(label)

            print(f"\n[SYN] {feats['ip_src']} -> {feats['ip_dst']}")
            print(f"  TTL: {feats['ip_ttl']} | Win: {feats['tcp_win']} | MSS: {feats['mss']}")
            print(f"  OS Label: {label} | scores Linux={l_score} Windows={w_score} | conf={conf_lvl}")

    if syn_results:
        counts = Counter(syn_results)
        consensus, _ = counts.most_common(1)[0]

        print(f"\n--- CONSENSUS ---")
        print(f"Captured: {consensus} | Expected: {expected_stack}")
        if consensus.split("-")[0] == expected_stack.split("-")[0]:
            print("Result: ✅ MATCH")
        else:
            print("Result: 🚨 MISMATCH")


if __name__ == "__main__":
    main()