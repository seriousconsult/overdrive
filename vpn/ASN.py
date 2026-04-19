#!/usr/bin/env python3

'''
When you connect to a website, the server looks at your IP address and identifies 
which "neighborhood" (ASN) you are coming from.
Residential ASN: Owned by companies like Comcast, AT&T, or Verizon. 
These are "trusted" because they represent real people in houses.
Data Center/Hosting ASN: Owned by companies like DigitalOcean, Amazon (AWS), or M247.
Most VPN providers host their servers in data centers. If a website performs an ASN lookup and sees that your IP belongs to a Data Center instead of a Residential ISP, it assumes you are using a VPN, Proxy, or Bot.

'''

import requests

def lookup_asn(ip_address=""):
    # If ip_address is empty, it checks your current connection
    url = f"https://ipapi.co/{ip_address}/json/"
    
    try:
        response = requests.get(url)
        data = response.json()
        
        asn = data.get('asn')       # e.g., AS16509
        org = data.get('org')       # e.g., Amazon.com, Inc.
        
        print(f"--- ASN Lookup Results ---")
        print(f"IP Address: {data.get('ip')}")
        print(f"ASN:        {asn}")
        print(f"Provider:   {org}")
        
        # Detection Logic
        if "M247" in org or "Datacamp" in org or "Hosting" in org:
            print("🚩 Status: Likely a VPN/Data Center IP")
        else:
            print("🟢 Status: Likely a Residential/ISP IP")
            
    except Exception as e:
        print(f"Lookup failed: {e}")

lookup_asn() # Check your current connection

