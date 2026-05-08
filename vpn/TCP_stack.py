#!/mnt/c/code/overdrive/virtual_env/bin/python


'''TCP Stack Fingerprinting (Layer 3)

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
import time
from collections import Counter

from scapy.all import TCP, IP, conf, get_if_list, AsyncSniffer, L3RawSocket

# Prefer Linux socket implementation if available
try:
    from scapy.arch.linux import L3PacketSocket
except ImportError:
    L3PacketSocket = L3RawSocket

# For mirrored mode in your setup, libpcap works reliably
conf.L3socket = L3PacketSocket
conf.use_pcap = True

TARGET_HOST = "google.com"
TARGET_PORT = 443

CAPTURE_PACKET_COUNT = 3
CAPTURE_TIMEOUT = 10          # overall timeout per interface attempt
TRAFFIC_BURST_ATTEMPTS = 12
TRAFFIC_DELAY_S = 0.08
TRAFFIC_SUBPROCESS_TIMEOUT = 8


def get_iface_operstate(ifname: str) -> str:
    try:
        with open(f"/sys/class/net/{ifname}/operstate", "r") as f:
            return f.read().strip().lower()
    except Exception:
        return "unknown"


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


def is_syn_noack(p) -> bool:
    if IP not in p or TCP not in p:
        return False
    flags = int(p[TCP].flags)
    SYN = 0x02
    ACK = 0x10
    return (flags & SYN) != 0 and (flags & ACK) == 0


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


def traffic_subprocess_ipv4_connect(host: str, port: int, attempts: int, delay_s: float):
    traffic_code = r"""
import socket, sys, time
host = sys.argv[1]
port = int(sys.argv[2])
attempts = int(sys.argv[3])
delay_s = float(sys.argv[4])

addrinfos = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
af, socktype, proto, canonname, sa = addrinfos[0]

for _ in range(attempts):
    s = socket.socket(af, socktype, proto)
    s.settimeout(1.0)
    try:
        s.connect(sa)
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    time.sleep(delay_s)
"""
    cmd = [
        "python3",
        "-c",
        traffic_code,
        host,
        str(port),
        str(attempts),
        str(delay_s),
    ]
    subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=TRAFFIC_SUBPROCESS_TIMEOUT,
        check=False,
    )


def capture_live_tcp_then_filter_syn(packet_count: int, timeout: int):
    """
    Multi-interface auto-detect:
      - Sniff TCP on each candidate interface (libpcap)
      - Filter SYN,no-ACK in Python
      - Stop early as soon as we have packet_count SYN packets
    """
    ifaces = get_if_list() or []
    if not ifaces:
        print("[-] Error: no interfaces discovered.")
        return []

    up_ifaces = [i for i in ifaces if get_iface_operstate(i) == "up"]
    candidates = []
    if "lo" in ifaces:
        candidates.append("lo")
    candidates += [i for i in up_ifaces if i != "lo"]
    if not candidates:
        candidates = ifaces

    print("[*] Candidate interfaces (operstate=up): " + ", ".join(candidates))

    tcp_filter = "tcp"
    deadline_global = time.time() + (timeout * max(1, len(candidates)))

    for iface in candidates:
        if time.time() > deadline_global:
            break

        print(f"[*] Sniffing (tcp) on iface='{iface}' ...")

        try:
            sniffer = AsyncSniffer(
                iface=iface,
                filter=tcp_filter,
                store=True
            )
            sniffer.start()
            time.sleep(0.35)  # warmup so we don't miss the burst

            # Generate a burst while sniffing
            traffic_subprocess_ipv4_connect(
                TARGET_HOST,
                TARGET_PORT,
                attempts=TRAFFIC_BURST_ATTEMPTS,
                delay_s=TRAFFIC_DELAY_S,
            )

            # Stop early when enough SYNs are captured
            t_end = time.time() + timeout
            while time.time() < t_end:
                pkts = sniffer.results or []
                tcp_pkts = [p for p in pkts if IP in p and TCP in p]
                syn_pkts = [p for p in tcp_pkts if is_syn_noack(p)]
                if len(syn_pkts) >= packet_count:
                    sniffer.stop()
                    return syn_pkts[:packet_count]
                time.sleep(0.05)

            # Timeout for this interface
            pkts = sniffer.stop() or []
            pkts = sniffer.results or pkts

            tcp_pkts = [p for p in pkts if IP in p and TCP in p]
            syn_pkts = [p for p in tcp_pkts if is_syn_noack(p)]
            print(f"    -> captured {len(tcp_pkts)} TCP, SYN,no-ACK matched: {len(syn_pkts)}")

            if syn_pkts:
                return syn_pkts[:packet_count]

        except Exception as e:
            print(f"    [!] Error on iface {iface}: {e}")
            continue

    return []


def calculate_stack_score(consensus, expected):
    if consensus == "Uncertain":
        return 3
    consensus_family = consensus.split("-")[0]
    expected_family = expected.split("-")[0]
    return 1 if consensus_family == expected_family else 5


def main():
    runtime_label, expected_stack = detect_runtime_os()
    print("=== TCP Stack Fingerprint Analysis ===")
    print(f"Runtime Environment: {runtime_label}")
    print(f"Expected Network Signature: {expected_stack}")
    print(f"Scapy conf.use_pcap={conf.use_pcap}\n")

    pkts = capture_live_tcp_then_filter_syn(
        packet_count=CAPTURE_PACKET_COUNT,
        timeout=CAPTURE_TIMEOUT,
    )

    if not pkts:
        print("[-] Error: No SYN,no-ACK packets captured for analysis.")
        return

    print("\nCaptured SYN packets (debug):")
    for i, p in enumerate(pkts, 1):
        feats = extract_syn_features(p)
        print(
            f"  pkt{i}: {p.summary()} | TTL={feats['ip_ttl']} WIN={feats['tcp_win']} "
            f"MSS={feats['mss']} OPTS={feats['opts']}"
        )

    syn_results = []
    for p in pkts:
        feats = extract_syn_features(p)
        label, _, _, _ = classify_linux_vs_windows(feats["ip_ttl"], feats["tcp_win"], feats["opts"])
        syn_results.append(label)

    counts = Counter(syn_results)
    consensus, _ = counts.most_common(1)[0]
    score = calculate_stack_score(consensus, expected_stack)

    print("\n" + "=" * 40)
    print(f"SCORE: {score}")

    descriptions = {
        1: "MATCH: Captured TCP SYN stack matches this OS family (low suspicion).",
        2: "LIKELY MATCH: Minor ambiguity; still mostly consistent with this OS.",
        3: "UNCERTAIN: Could not definitively classify SYN stack vs OS.",
        4: "PROBABLE MISMATCH: SYN stack plausibly altered vs this OS (investigate).",
        5: "HARD MISMATCH: SYN stack disagrees with this OS (VPN/proxy/spoof/translator signal).",
    }
    print(f"STATUS: {descriptions.get(score)}")
    print("=" * 40)

    if score >= 4:
        print("💡 ALERT: A remote observer may infer OS/stack masking or tunneling from this mismatch.")


if __name__ == "__main__":
    main()