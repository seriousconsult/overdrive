#!/usr/bin/env python3


'''
This is layer 7. Note that TCP fingerprinting may also occur and that is layer 2.

When you connect via HTTP2, your client sends a SETTINGS frame and a WINDOW_UPDATE frame. 
The specific values and the order in which they are sent are unique to different browsers.
These are a fingerprint. So if the site is intended for browsers and your fingerprint is
H2 Fingerprint: 1:4096;2:0;4:65535;5:16384;3:100;6:65536|16777216|0|m,a,s,p that matches 
Python h2 / httpx libraries not chrome (Ex. 1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p). 
So it is obvious you are not an intended user. 

While this doesn't detect the VPN "tunnel," it detects the software being used over the VPN.
Most people using a VPN for privacy use a standard browser. However, people using VPNs for automated
tasks (botting, scraping, account creation) often use Python or headless browsers. 
These tools have very different HTTP2 signatures than a typical human's browser.

1. Settings (The "Signature")
    HEADER_TABLE_SIZE: How much memory the server should use to compress headers.
    ENABLE_PUSH: Whether the client accepts "Server Push."
    INITIAL_WINDOW_SIZE: How much data the client can receive before sending an acknowledgment.
    MAX_FRAME_SIZE: The largest frame the client is willing to receive.
2. Window Update
    The value 12517377 is a massive tell. In HTTP2, the flow control window size is often set to a
       specific number by different network libraries. If your "Browser" sends a window update that
         matches a known Python-httpx or Go-http2 value, you get flagged.
3. Pseudo-Header Order
    Notice the list on the right: method, path, authority, scheme.
    The "Gotcha": Google Chrome always sends these in a specific order (usually :method, :authority, 
    :scheme, :path). If your script sends them in a different order (like putting path before authority),
      the server knows you aren't actually using Chrome, regardless of what your User-Agent says.

'''

import httpx
import time


with httpx.Client(http2=True) as client:
    response = client.get("https://www.google.com")
    print(f"Negotiated Protocol: {response.http_version}") 
    # Should say 'HTTP/2'.


    # Use a timestamp to ensure the URL is "unique" and bypasses some caches
url = f"https://tls.peet.ws/api/all?t={int(time.time())}"

# Explicitly disable connection pooling for a one-off test
with httpx.Client(http2=True, limits=httpx.Limits(max_connections=1)) as client:
    print(f"📡 Testing fresh connection to {url}...")
    response = client.get(url)
    
    print(f"Protocol:    {response.http_version}")
    
    data = response.json()
    h2 = data.get('http2', {})
    
    # Check for the Akamai hash (this is the industry standard H2 fingerprint)
    fingerprint = h2.get('akamai_fingerprint') or h2.get('fingerprint')
    settings = h2.get('settings')

    print(f"H2 Fingerprint: {fingerprint}")
    print(f"Sent Settings:  {settings}")
    
    if fingerprint is None:
        print("\n⚠️  Still None? Your VPN or network is likely acting as a 'Transparent Proxy'.")