#!/mnt/c/code/overdrive/virtual_env/bin/python


'''TCP Stack Fingerprinting (Layer 4)

Every OS (Windows, Linux, iOS) handles TCP packets slightly differently
 (initial window size, TTL, etc.). Some VPNs change these values to look like a different OS.
If your IP says "Linux Server" (VPN) but your TCP fingerprint says "iPhone," 
a site may flag you for "Proxy Usage."

Because this is below packet level Python is not the ideal tool.

NOTE:scapy needs sudo however sudo does not use the Python virtual env. So you need to run like this: 
sudo /mnt/c/code/overdrive/virtual_env/bin/python /mnt/c/code/overdrive/vpn/TCP_stack.py

TCP SYN stack inspection + comparison vs actual OS environment.

- Reads wsl_syn.pcap
- For each outgoing SYN packet:
  - extracts TTL, TCP window, and TCP options (MSS, WScale, Timestamp, SACK/SAckOK)
  - classifies as Linux-like vs Windows-like (heuristic)
- Detects the actual runtime OS/kernel environment (Windows/Linux/WSL)
- Compares: captured SYN classification vs actual OS expectation

This version:
- Captures outgoing TCP SYN packets using AsyncSniffer
- Generates IPv4-only TCP SYN traffic using a Python subprocess (NO curl)
- Tries each Scapy-discovered interface until it captures packets
'''

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

def calculate_stack_score(consensus, expected):
    """
    Risk-style score (aligned with most Overdrive scripts):
      1 — Low suspicion: captured SYN stack matches this machine’s OS family.
      3 — Inconclusive capture / uncertain classification.
      5 — High suspicion: captured SYN stack disagrees with OS (VPN/proxy/NAT rewrite, spoofing, etc.).
    """
    if consensus == "Uncertain":
        return 3 # Neutral/Probable match but inconclusive
    
    # Extract the base family (e.g., "Linux" from "Linux-like")
    consensus_family = consensus.split("-")[0]
    expected_family = expected.split("-")[0]
    
    if consensus_family == expected_family:
        return 1  # Coherent — low suspicion
    else:
        return 5  # Family mismatch — high suspicion (often tunnel / translation / spoof)

def main():
    runtime_label, expected_stack = detect_runtime_os()
    print("=== TCP Stack Fingerprint Analysis ===")
    print(f"Runtime Environment: {runtime_label}")
    print(f"Expected Network Signature: {expected_stack}\n")

    pkts = capture_live_syn_inline_subprocess(
        packet_count=CAPTURE_PACKET_COUNT,
        timeout=CAPTURE_TIMEOUT,
    )

    if not pkts:
        print("[-] Error: No packets captured for analysis.")
        return

    syn_results = []
    for p in pkts:
        if IP in p and TCP in p:
            feats = extract_syn_features(p)
            label, conf_lvl, l_score, w_score = classify_linux_vs_windows(
                feats["ip_ttl"], feats["tcp_win"], feats["opts"]
            )
            syn_results.append(label)

    # Determine Consensus and Score
    counts = Counter(syn_results)
    consensus, _ = counts.most_common(1)[0]
    score = calculate_stack_score(consensus, expected_stack)

    print("\n" + "="*40)
    print(f" SCORE: {score}")
    
    descriptions = {
        1: "MATCH: Captured TCP SYN stack matches this OS family (low suspicion).",
        2: "LIKELY MATCH: Minor ambiguity; still mostly consistent with this OS.",
        3: "UNCERTAIN: Could not definitively classify SYN stack vs OS.",
        4: "PROBABLE MISMATCH: SYN stack plausibly altered vs this OS (investigate).",
        5: "HARD MISMATCH: SYN stack disagrees with this OS (VPN/proxy/spoof/translator signal).",
    }
    
    print(f" STATUS: {descriptions.get(score)}")
    print("="*40)
    
    if score >= 4:
        print("💡 ALERT: A remote observer may infer OS/stack masking or tunneling from this mismatch.")

if __name__ == "__main__":
    main()