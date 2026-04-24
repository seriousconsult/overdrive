#!/usr/bin/env python3


import requests

def get_geo_data(ip):
    """Helper to fetch location for a specific IP."""
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        return response.json()
    except:
        return None

def run_comprehensive_leak_test():
    print("🚀 Starting Dual-Stack VPN Leak Test...\n")

    # --- 1. CHECK IPv4 ---
    print("[1/2] Checking IPv4 Path...")
    try:
        ipv4 = requests.get("https://4.ident.me", timeout=5).text.strip()
        geo4 = get_geo_data(ipv4)
        if geo4:
            print(f"✅ IPv4: {ipv4}")
            print(f"   Location: {geo4.get('city')}, {geo4.get('country_name')}")
            print(f"   ISP:      {geo4.get('org')}")
    except Exception:
        print("❌ Could not connect via IPv4.")

    print("\n" + "-"*30 + "\n")

    # --- 2. CHECK IPv6 ---
    print("[2/2] Checking IPv6 Path...")
    try:
        # This will ONLY succeed if your system has a working IPv6 route
        ipv6 = requests.get("https://6.ident.me", timeout=5).text.strip()
        geo6 = get_geo_data(ipv6)
        if geo6:
            print(f"⚠️  IPv6: {ipv6}")
            print(f"   Location: {geo6.get('city')}, {geo6.get('country_name')}")
            print(f"   ISP:      {geo6.get('org')}")
            print("\n🚨 ALERT: IPv6 is active. Ensure this matches your VPN, not your home ISP.")
    except Exception:
        # If this fails, it's actually GOOD news for your privacy
        print("No IPv6 detected or connection timed out. (likely not leaking via IPv6.)")

if __name__ == "__main__":
    run_comprehensive_leak_test()