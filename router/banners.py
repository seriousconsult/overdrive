#!/usr/bin/env python3
'''
(Layer 7)
Port 80/443 "Banners"
Most home routers have a web-based management page so you can change your Wi-Fi password. 
Even if they don't let you log in from the "outside" (the WAN side), they often leak information:
Service Banners: If you send a request to the device, it might respond with a header 
like Server: httpd/2.0 (AsusWRT) or Server: TP-LINK HTTPD.
MAC Address OUI: If you are on the same local network, the first half of the device's 
MAC address (the OUI) is registered to a manufacturer. A MAC starting with C0:56:27 
immediately tells you, "I am a NETGEAR device."
'''
#!/usr/bin/env python3
import argparse
import json
import urllib3
from typing import Dict, Any, List, Optional

import requests

# Keep warnings enabled by default; only disable if user opts into --insecure.
ROUTER_SERVER_KEYWORDS = [
    "httpd", "wrt", "tp-link", "netgear", "asuswrt", "asustek", "gateway",
    "cisco", "router", "boa", "lighttpd"
]

# Header keys we will consider as “banner-like” (still Layer-7 headers only)
BANNER_HEADERS = ["Server", "X-Powered-By", "WWW-Authenticate", "Location", "Content-Type"]


def score_server_banner(server_value: Optional[str]) -> (int, List[str]):
    if not server_value:
        return 0, []

    sv = server_value.lower()
    matched = [kw for kw in ROUTER_SERVER_KEYWORDS if kw in sv]
    # Simple weighting: more keyword matches => higher suspicion.
    score = min(10, 2 * len(matched) + (5 if matched else 0))
    return score, matched


def request_with_method(session: requests.Session, method: str, url: str, timeout: float,
                         insecure: bool) -> Dict[str, Any]:
    resp = session.request(
        method=method,
        url=url,
        timeout=timeout,
        verify=(not insecure),
        allow_redirects=False,  # keep it banner/headers-focused
        headers={
            "User-Agent": "banner-probe/1.0",
            "Accept": "*/*",
            "Connection": "close",
        },
    )

    headers = dict(resp.headers)
    server = headers.get("Server")

    score, matched = score_server_banner(server)

    banner_subset = {k: headers.get(k) for k in BANNER_HEADERS if k in headers}

    return {
        "method": method,
        "url": url,
        "status_code": resp.status_code,
        "server": server,
        "matched_keywords": matched,
        "banner_headers": banner_subset,
        "score": score,
    }


def probe(ip: str, port: int, path: str, timeout: float, insecure: bool, max_tries: int = 2) -> Dict[str, Any]:
    scheme = "https" if port in (443,) else "http"
    url = f"{scheme}://{ip}:{port}{path}"

    session = requests.Session()
    results: List[Dict[str, Any]] = []

    # Try HEAD first, then GET if:
    # - HEAD failed, or
    # - HEAD returned no meaningful Server header.
    tried = 0
    for method in ["HEAD", "GET"]:
        tried += 1
        try:
            r = request_with_method(session, method, url, timeout=timeout, insecure=insecure)
            results.append(r)

            # If we got a Server header on HEAD, we can stop early.
            if method == "HEAD" and r.get("server"):
                break

        except requests.RequestException as e:
            results.append({
                "method": method,
                "url": url,
                "error": str(e),
            })

        if tried >= max_tries:
            break

    # Combine evidence: max score observed among attempts.
    final_score = max((r.get("score", 0) for r in results if isinstance(r, dict)), default=0)
    return {
        "ip": ip,
        "port": port,
        "scheme": scheme,
        "path": path,
        "attempts": results,
        "final_score": final_score,
    }


def main():
    ap = argparse.ArgumentParser(description="Banner-only router likelihood probe (HTTP(S) headers only).")
    ap.add_argument("--ip", required=True, help="Target IP (e.g., 192.168.1.1)")
    ap.add_argument("--paths", nargs="+", default=["/"], help="Paths to request (default: /)")
    ap.add_argument("--ports", nargs="+", type=int, default=[80, 443], help="Ports to probe (default: 80 443)")
    ap.add_argument("--timeout", type=float, default=2.5, help="Request timeout (seconds).")
    ap.add_argument("--insecure", action="store_true",
                    help="Allow insecure HTTPS (self-signed certs). Banner-only headers; user-controlled.")
    ap.add_argument("--out-json", default=None, help="Optional JSON output file.")
    args = ap.parse_args()

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    evidence: Dict[str, Any] = {
        "target_ip": args.ip,
        "ports": args.ports,
        "paths": args.paths,
        "timeout": args.timeout,
        "insecure": args.insecure,
        "results": [],
        "overall_score": 0,
        "verdict": "Unknown/Insufficient banner evidence",
    }

    overall = 0
    for port in args.ports:
        for path in args.paths:
            r = probe(
                ip=args.ip,
                port=port,
                path=path,
                timeout=args.timeout,
                insecure=args.insecure
            )
            evidence["results"].append(r)
            overall = max(overall, r["final_score"])

    evidence["overall_score"] = overall

    # Heuristic verdict only from header banners we extracted.
    if overall >= 8:
        evidence["verdict"] = "High suspicion: router-like banner headers (heuristic)"
    elif overall >= 4:
        evidence["verdict"] = "Moderate suspicion: router-like banner headers (heuristic)"
    elif overall >= 1:
        evidence["verdict"] = "Low suspicion: some banner evidence, not strong (heuristic)"

    # Human output
    print(f"--- Banner-only probe for {args.ip} ---")
    print(f"Verdict: {evidence['verdict']} | overall_score={evidence['overall_score']}")
    for r in evidence["results"]:
        print(f"\n[{r['scheme']}://{r['ip']}:{r['port']}{r['path']}] score={r['final_score']}")
        for a in r["attempts"]:
            if "error" in a:
                print(f"  - {a['method']}: ERROR: {a['error']}")
                continue
            print(f"  - {a['method']}: status={a['status_code']} Server={a.get('server')!r}")
            if a.get("matched_keywords"):
                print(f"    matched_keywords={a['matched_keywords']}")
            if a.get("banner_headers"):
                print(f"    banner_headers={a['banner_headers']}")

    # JSON output (agent-friendly evidence)
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)
        print(f"\n[+] Wrote JSON evidence to: {args.out_json}")


if __name__ == "__main__":
    main()