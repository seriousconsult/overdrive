#!/usr/bin/env python3
 
'''
For awareness, which DNS are you using?
For example:
The ISP/Internal label means the script performed a reverse lookup.
It asked the IP 10.255.255.254 for its name, and it responded with HW3P674.
This is likely the Device Name of your physical router or the server handling
network traffic in your building.

NOTE: wsl2

In WSL2, Microsoft introduced DNS Tunneling. Instead of WSL trying 
to talk directly to your router or VPN’s DNS over the network (which often broke when the VPN 
changed routing tables), it now sends all DNS queries to a "black box" at 10.255.255.254.  
Windows catches those requests and resolves them using the Windows Host's current DNS settings.  
    VPN Off: Windows uses your ISP/Router DNS; the tunnel passes the result back.
    VPN On: Windows uses the VPN's DNS; the tunnel passes the result back.
Because your script sees the "gateway" IP (10.255.255.254) as the nameserver in both cases, 
it thinks the DNS hasn't changed, even though the upstream resolver on the Windows side likely has.
'''
import socket
import subprocess
import platform
import os


def is_wsl() -> bool:
    if platform.system() != "Linux":
        return False
    try:
        with open("/proc/version", encoding="utf-8", errors="replace") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def wsl_dns() -> str | None:
    """First nameserver in /etc/resolv.conf — on WSL2 this is typically the DNS tunnel host."""
    path = "/etc/resolv.conf"
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
    except OSError:
        return None
    return None


def _resolv_nameservers() -> list[str]:
    path = "/etc/resolv.conf"
    if not os.path.isfile(path):
        return []
    out: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1 and parts[1] not in out:
                        out.append(parts[1])
    except OSError:
        return []
    return out


# Known Public DNS Providers (Commonly blocked by some providers)
DNS_PROVIDER_MAP = {
    # --- Major Global Resolvers ---
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9 (Secondary)",
    "208.67.222.222": "OpenDNS (Cisco)",
    "208.67.220.220": "OpenDNS (Cisco)",

    # --- Privacy & Security Focused ---
    "94.140.14.14": "AdGuard DNS",
    "94.140.15.15": "AdGuard DNS",
    "76.76.2.0": "Control D",
    "76.76.10.0": "Control D",
    "185.228.168.9": "CleanBrowsing",
    "185.228.169.9": "CleanBrowsing",
    "45.33.97.5": "Alternate DNS",
    "37.235.1.174": "FreeDNS",

    # --- Infrastructure / ISP Managed ---
    "64.6.64.6": "Verisign Public DNS",
    "64.6.65.6": "Verisign Public DNS",
    "4.2.2.1": "Level3 (CenturyLink)",
    "4.2.2.2": "Level3 (CenturyLink)",
    "8.26.56.26": "Comodo Secure DNS",
    "8.20.247.20": "Comodo Secure DNS",

    # --- Internal / Virtualization Gateways ---
    "172.18.0.1": "WSL Internal Gateway (NAT)",
    "192.168.1.1": "Common Local ISP's Router",
    "10.0.0.1": "Common Local VPN's Router",
    "10.2.0.1": "Common Local VPN's Router",
    "10.255.255.254": "Corporate/ISP Gateway",
}

def get_dns_info():
    dns_ips = []
    system = platform.system()
    final_score = 1  # Default clean score
    is_public_dns = False

    # --- Step 1: Get the IPs ---
    try:
        if system == "Linux":
            if is_wsl():
                # On WSL2, query Windows DNS settings instead of /etc/resolv.conf
                cmd = ["powershell.exe", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"]
                output = subprocess.check_output(cmd, text=True).strip()
                if output:
                    dns_ips = output.splitlines()
                else:
                    # Fallback to resolv.conf if powershell fails
                    dns_ips = _resolv_nameservers()
            elif os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) > 1:
                                dns_ips.append(parts[1])
        elif system == "Windows":
            cmd = ["powershell.exe", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"]
            output = subprocess.check_output(cmd, text=True).strip()
            if output: dns_ips = output.splitlines()
    except Exception as e:
        print(f"SCORE: 3")
        print(f"STATUS: Error detecting DNS: {e}")
        return

    # --- Step 2: Identify and Format ---
    dns_details_strings = []
    for ip in dns_ips:
        name = DNS_PROVIDER_MAP.get(ip)
        
        if name:
            # If it's a known public provider, mark as potentially problematic for DNSBL
            if "Public" in name or "Cloudflare" in name or "OpenDNS" in name:
                is_public_dns = True
        else:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                name = f"ISP/Internal ({hostname})"
            except (socket.herror, socket.gaierror):
                name = "Private/Unknown Provider"
        
        dns_details_strings.append(f"{ip} ({name})")
    
    # Logic for score based on DNS type
    if is_public_dns:
        final_score = 5
        status_msg = f"Public DNS detected: {', '.join(dns_details_strings)}"
    else:
        final_score = 2
        status_msg = f"System DNS: {', '.join(dns_details_strings)}"

    # --- Final Print Statements ---
    print(f"SCORE: {final_score}")
    print(f"STATUS: {status_msg}")

if __name__ == "__main__":
    print("--- System DNS Identification ---")
    get_dns_info()