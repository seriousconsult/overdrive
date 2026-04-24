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

Run:
  python3 TCP_parser.py
"""

import os
import platform
from scapy.all import rdpcap, TCP, IP

PCAP_PATH = "wsl_syn.pcap"


def detect_runtime_os():
    """
    Returns a tuple: (runtime_label, expected_tcp_stack_label)
    Where expected_tcp_stack_label is the heuristic 'what you'd expect' for SYN.
    """
    sysname = platform.system().lower()  # 'linux' or 'windows' etc.

    # Detect WSL
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
    if sysname == "linux":
        return ("Linux", "Linux-like")
    return (platform.system(), "Unknown")


def classify_linux_vs_windows(ip_ttl, tcp_win, opts_list):
    """
    Heuristic classifier based on:
    - TTL bands (<=70 Linux-like, >=100 Windows-like)
    - presence of common TCP options (MSS, WScale, Timestamp, SAckOK/SACK)

    Returns dict with label/confidence/scores/signals.
    """
    opt_names = []
    for item in (opts_list or []):
        # scapy options look like: ('MSS', 1338), ('Timestamp', (t1,t2)), ('WScale', 7)...
        if isinstance(item, tuple) and len(item) >= 1:
            opt_names.append(str(item[0]))
        else:
            opt_names.append(str(item))

    has_mss = "MSS" in opt_names
    has_ts = "Timestamp" in opt_names
    has_sack = "SAckOK" in opt_names or "SACK" in opt_names
    has_wscale = "WScale" in opt_names

    linux_ttl = (ip_ttl is not None) and (ip_ttl <= 70)
    windows_ttl = (ip_ttl is not None) and (ip_ttl >= 100)

    linux_score = 0
    windows_score = 0

    if linux_ttl:
        linux_score += 3
    if windows_ttl:
        windows_score += 3

    if has_wscale:
        linux_score += 1
        windows_score += 1
    if has_ts:
        linux_score += 1
        windows_score += 1
    if has_sack:
        linux_score += 1
        windows_score += 1

    if has_mss:
        linux_score += 1
        windows_score += 1

    # Keep WIN weak weight (it varies a lot).
    if tcp_win is not None and tcp_win <= 70000:
        linux_score += 1

    if linux_score > windows_score + 1:
        label = "Linux-like TCP stack (heuristic)"
        confidence = "medium-high"
    elif windows_score > linux_score + 1:
        label = "Windows-like TCP stack (heuristic)"
        confidence = "medium-high"
    else:
        label = "Uncertain TCP stack (heuristic)"
        confidence = "low"

    signals = []
    if linux_ttl:
        signals.append("TTL<=70 suggests Linux-like")
    if windows_ttl:
        signals.append("TTL>=100 suggests Windows-like")
    if has_mss:
        signals.append("MSS present")
    if has_wscale:
        signals.append("Window Scale present")
    if has_ts:
        signals.append("Timestamps present")
    if has_sack:
        signals.append("SACK/SAckOK present")

    return {
        "label": label,
        "confidence": confidence,
        "linux_score": linux_score,
        "windows_score": windows_score,
        "signals": signals,
    }


def extract_syn_features(pkt):
    """
    Extracts features for an outgoing SYN packet:
    TTL, window, MSS, and option names list
    """
    ip = pkt[IP]
    tcp = pkt[TCP]

    ip_ttl = int(ip.ttl) if hasattr(ip, "ttl") else None
    tcp_win = int(tcp.window) if hasattr(tcp, "window") else None
    opts = tcp.options or []

    mss = None
    for name, val in opts:
        if name == "MSS":
            mss = val

    return {
        "ip_src": ip.src,
        "ip_dst": ip.dst,
        "ip_ttl": ip_ttl,
        "tcp_win": tcp_win,
        "mss": mss,
        "opts": opts,
    }


def main():
    runtime_label, expected_stack = detect_runtime_os()

    print("============================================================")
    print("TCP SYN TCP-Stack Inspection (single script)")
    print("============================================================")
    print(f"Runtime environment: {runtime_label}")
    print(f"Expected TCP stack:  {expected_stack}")
    print(f"PCAP file:           {PCAP_PATH}")
    print("------------------------------------------------------------")

    pkts = rdpcap(PCAP_PATH)
    print(f"Loaded packets: {len(pkts)}")
    print("------------------------------------------------------------")

    syn_results = []

    for i, p in enumerate(pkts, 1):
        if IP not in p or TCP not in p:
            continue
        tcp = p[TCP]
        flags = str(tcp.flags)

        # Only outgoing SYN (not SYN-ACK)
        if flags != "S":
            continue

        feats = extract_syn_features(p)
        cls = classify_linux_vs_windows(
            ip_ttl=feats["ip_ttl"],
            tcp_win=feats["tcp_win"],
            opts_list=feats["opts"],
        )

        syn_results.append((feats, cls))

        print(f"\n--- Outgoing SYN #{len(syn_results)} (packet idx {i}) ---")
        print(f"{feats['ip_src']} -> {feats['ip_dst']}")
        print(f"TTL:      {feats['ip_ttl']}")
        print(f"WIN:      {feats['tcp_win']}")
        print(f"MSS:      {feats['mss']}")
        print(f"Options:  {feats['opts']}")
        print("\nHeuristic TCP-stack classification:")
        print(f"  Label:      {cls['label']}")
        print(f"  Confidence: {cls['confidence']}")
        print(f"  Scores:     Linux={cls['linux_score']} Windows={cls['windows_score']}")
        print("  Signals:")
        for s in cls["signals"]:
            print(f"   - {s}")

    if not syn_results:
        print("\nNo outgoing SYN packets were found in the PCAP.")
        return

    # Decide overall captured-stack label from majority
    linux_like = sum(1 for _, cls in syn_results if "Linux-like" in cls["label"])
    windows_like = sum(1 for _, cls in syn_results if "Windows-like" in cls["label"])
    uncertain = len(syn_results) - linux_like - windows_like

    if linux_like > windows_like:
        captured_stack = "Linux-like"
    elif windows_like > linux_like:
        captured_stack = "Windows-like"
    else:
        captured_stack = "Uncertain"

    print("\n------------------------------------------------------------")
    print("CONSENSUS RESULT")
    print("------------------------------------------------------------")
    print(f"Captured SYN consensus: {captured_stack}")
    print(f"Expected TCP stack:     {expected_stack}")

    match = False
    if captured_stack == "Linux-like" and expected_stack.startswith("Linux"):
        match = True
    if captured_stack == "Windows-like" and expected_stack.startswith("Windows"):
        match = True

    if match:
        print("Result: ✅ Captured outgoing SYN looks consistent with the runtime OS/kernel.")
    else:
        print("Result: 🚨 MISMATCH (heuristic).")
        print("Hint: This can happen due to heuristic thresholds, different capture points,")
        print("      or because path/NAT/VPN changes TTL/hop behavior. MSS/options are the more actionable signals.")

    print("\nDone.")
    print("============================================================")


if __name__ == "__main__":
    main()