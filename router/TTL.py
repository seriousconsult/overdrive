#!/usr/bin/env python3
'''
(Layer 3)
The TTL "Signature" (Time-to-Live)
Every operating system has a default TTL value (a counter that tells a packet how many "hops" it can take before being deleted).
Linux/Mac/Android: Usually start at 64.
Windows: Usually starts at 128.
Cisco/Generic Routers: Often start at 255.
If you are analyzing traffic and see a packet with a TTL of 254 or 255, it’s a massive clue that you’re 
talking directly to a piece of networking hardware (like a router) rather than a PC or a phone.
'''

#!/usr/bin/env python3
import argparse
import json
import time
from collections import defaultdict

from scapy.all import sniff, IP, conf

conf.verb = 0  # scapy quiet

def compute_suspicion(ttls):
    """
    TTL-based suspicion scoring (heuristic).
    Returns: (label, score0to10, stats)
    """
    ttls = list(map(int, ttls))
    ttls_sorted = sorted(ttls)
    n = len(ttls_sorted)
    median = ttls_sorted[n // 2] if n % 2 == 1 else (ttls_sorted[n//2 - 1] + ttls_sorted[n//2]) / 2
    min_ttl = ttls_sorted[0]
    max_ttl = ttls_sorted[-1]

    score = 0
    label = "Unknown/Modified TTL (heuristic)"

    # Router-ish suspicion: extremely high TTLs are a clue (NOT proof)
    if median >= 240:
        score += 5
        label = "Likely Network Hardware (router-ish TTL suspicion)"
    if max_ttl >= 254:
        score += 4
        label = "Very Suspicious: router-ish / network hardware suspicion"

    # OS-ish heuristics (also NOT proof)
    if 110 <= median <= 140:
        score += 2
        label = label if score > 0 else "Possible Windows-ish stack (heuristic TTL)"
    elif 40 <= median <= 80:
        score += 1
        label = label if score > 0 else "Possible Linux/mac/IoT-ish stack (heuristic TTL)"

    # Clamp
    score = min(score, 10)

    stats = {
        "count": n,
        "median_ttl": median,
        "min_ttl": min_ttl,
        "max_ttl": max_ttl,
    }
    return label, score, stats

def main():
    ap = argparse.ArgumentParser(description="Capture IPv4 TTL and evaluate Top Suspects (heuristic scoring).")
    ap.add_argument("--iface", default=None, help="Interface (e.g., eth0). Optional.")
    ap.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = run until Ctrl+C).")
    ap.add_argument("--bpf", default="ip", help="BPF filter. Default: ip")
    ap.add_argument("--min-samples", type=int, default=8, help="Packets per src_ip before scoring it.")
    ap.add_argument("--top", type=int, default=10, help="How many suspects to display.")
    ap.add_argument("--local-ip", default=None, help="If set, enables inbound/outbound filtering + labeling.")
    ap.add_argument("--mode", choices=["both", "inbound", "outbound"], default="both",
                    help="Direction relative to --local-ip (only used if --local-ip is provided).")
    ap.add_argument("--print-interval", type=int, default=10,
                    help="Seconds between interim prints (0 disables interim prints).")
    ap.add_argument("--out-jsonl", default=None, help="Optional: also append captured packets as JSONL.")
    args = ap.parse_args()

    ttl_by_src = defaultdict(list)
    seen_any = False

    out_f = None
    if args.out_jsonl:
        out_f = open(args.out_jsonl, "a", buffering=1)

    print("=== TTL Suspect Capture (heuristic) ===")
    print(f"iface={args.iface or '(auto)'} count={args.count} min_samples={args.min_samples} top={args.top}")
    print(f"bpf='{args.bpf}' local-ip={args.local_ip or '(none)'} mode={args.mode}")

    start = time.time()
    last_print = start

    def maybe_print(final=False):
        nonlocal last_print
        # Build suspects from src IPs that have enough samples
        suspects = []
        for src, ttls in ttl_by_src.items():
            if len(ttls) >= args.min_samples:
                label, score, stats = compute_suspicion(ttls)
                suspects.append((score, src, label, stats))

        suspects.sort(reverse=True)  # by score then src tuple ordering
        suspects = suspects[: args.top]

        tag = "FINAL" if final else "INTERIM"
        print(f"\n--- {tag} Suspect Report ---")
        if not suspects:
            print("No suspects yet (need more samples per src_ip).")
        else:
            for i, (score, src, label, stats) in enumerate(suspects, 1):
                elapsed = time.time() - start
                print(f"{i:02d}. score={score} src={src} label={label}")
                print(f"    samples={stats['count']} median_ttl={stats['median_ttl']} min={stats['min_ttl']} max={stats['max_ttl']}")

        last_print = time.time()

    def on_pkt(pkt):
        nonlocal seen_any
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        src = ip.src

        # Direction filtering if local-ip is set
        if args.local_ip:
            if args.mode == "inbound" and ip.dst != args.local_ip:
                return
            if args.mode == "outbound" and ip.src != args.local_ip:
                return
            # If mode==both, keep all relative to local-ip (no extra filtering here)

        ttl = int(ip.ttl)
        ttl_by_src[src].append(ttl)

        if out_f:
            rec = {
                "ts": time.time(),
                "src": ip.src,
                "dst": ip.dst,
                "ttl": ttl,
                "proto": int(ip.proto),
            }
            out_f.write(json.dumps(rec) + "\n")

        seen_any = True

        # Interim printing
        if args.print_interval and (time.time() - last_print) >= args.print_interval:
            maybe_print(final=False)

    print("Starting capture... (Ctrl+C to stop)")
    try:
        sniff(
            iface=args.iface,
            filter=args.bpf,
            prn=on_pkt,
            store=False,
            count=args.count if args.count > 0 else 0
        )
    except KeyboardInterrupt:
        pass
    finally:
        if out_f:
            out_f.close()

    if seen_any:
        maybe_print(final=True)
    else:
        print("No IPv4 packets captured. Check permissions/iface/BPF filter.")

if __name__ == "__main__":
    main()