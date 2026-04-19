#!/usr/bin/env python3


'''
VPN servers often use specific versions of OpenSSL or other libraries. 
A server can look at the JA3 hash of your SSL handshake.
If that hash matches a known "NordVPN Exit Node" or "OpenVPN Client" signature,
they know you aren't just a regular person on Chrome.


Since JA3 hashes change slightly when libraries (like openssl) update, one way to do this is to keep 
an eye on JA3 Fingerprint Databases. Xheck these resources:
    https://www.google.com/search?q=JA3er.com: A massive community-driven database of hashes.
    Abuse.ch: Often lists JA3 hashes associated with malware or known botnets/VPN nodes.


Many high-end VPNs now use TLS Grease. This adds random data to the handshake so that your JA3 hash 
changes every single time you connect. If you run your script twice and get two different hashes,
 your VPN is using "Grease" to try to defeat fingerprinting.   


 TODO:JA4 fingerprint
 TODO:PeetPrint fingerprint
 TODO:Akamai fingerprint
 TODO:TLS info
TLS version used
Protocols
Supported versions
Curves
Signature algorithms
Extensions
Ciphers


'''

import requests
import re

def detect_grease(ja3_raw):
    """
    Identifies GREASE values (randomized TLS extensions).
    GREASE values in decimal follow a specific pattern (e.g., 2570, 6682).
    """
    grease_decimals = {
        2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354, 
        35466, 39578, 43690, 47802, 51914, 56026, 60138, 64250
    }
    
    found_grease = []
    # Split by common delimiters in raw JA3 strings
    all_values = re.split(r'[;,-]', ja3_raw)
    
    for val in all_values:
        if val.isdigit() and int(val) in grease_decimals:
            found_grease.append(val)
            
    return list(set(found_grease))

def run_deep_analysis():
    # Database of known JA3 hashes
    JA3_DB = {
        "771,4866-4865-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53": 
            "Python (Requests / Urllib3) - Standard Linux/WSL",
        "771,4866-4865-4867-49195-49199-49196-49200-52393-52392-49161-49162-53-47": 
            "Go-lang (Default HTTP Client)",
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53-10": 
            "Chrome 110+ (Windows/Mac)",
        "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49161-49162-49171-49172-156-157-47-53": 
            "Firefox (Modern versions)",
        "771,49195-49199-49196-49200-52393-52392-49161-49162-49171-49172-53-47-10": 
            "OpenVPN / Specialized Tunnel Client",
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157": 
            "Tor Browser (Orbot/Tails)",
        "303,49195-49199-49196-49200-49171-49172-156-157-47-53": 
            "Legacy VPN (SSLv3/TLS 1.0) - HIGHLY DETECTABLE",
    }

    url = "https://tls.peet.ws/api/all"
    
    print("🚀 Starting Deep TLS Fingerprint Analysis...")
    
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        
        ja3_hash = data.get('tls', {}).get('ja3')
        ja3_raw = data.get('tls', {}).get('ja3_raw', '')
        my_ua = data.get('http', {}).get('user-agent', '')
        
        # 1. Signature Matching
        match = JA3_DB.get(ja3_hash, "Unknown / Unique Fingerprint (Possible GREASE Influence)")
        
        # 2. GREASE Detection
        grease_values = detect_grease(ja3_raw)
        
        print(f"\n[+] Detected JA3: {ja3_hash}")
        print(f"[+] Reported UA:  {my_ua}")
        print("-" * 60)
        print(f"DATABASE MATCH: {match}")

        # 3. GREASE Analysis
        if grease_values:
            print(f"GREASE STATUS:  🌈 DETECTED ({len(grease_values)} values)")
            print(f"                Handshake looks like a modern Browser.")
        else:
            print(f"GREASE STATUS:  ❌ NOT DETECTED")
            print(f"                Handshake looks like a static script/library.")

        # 4. Identity Theft / Anomaly Detection
        is_python = "python" in my_ua.lower()
        
        print("\n--- Security Analysis ---")
        if is_python and grease_values:
            print("🚨 ANOMALY: User-Agent claims Python, but GREASE is present. You are likely spoofing.")
        elif not is_python and "Python" in match:
            print("🚨 LEAK: User-Agent claims Browser, but JA3 proves you are a Python script.")
        elif grease_values and "Chrome" not in my_ua and "Firefox" not in my_ua:
            print("⚠️  SUSPICIOUS: Modern TLS features found in a non-standard User-Agent.")
        else:
            print("🟢 VERIFIED: TLS signature appears consistent with the User-Agent.")

    except Exception as e:
        print(f"❌ Error during analysis: {e}")

if __name__ == "__main__":
    run_deep_analysis()