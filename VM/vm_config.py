"""
Configuration constants for the VirtualBox lab VMs.
"""

# Mullvad public DNS-over-TLS (DoT). Plain UDP/53 is refused; use stubby on OpenWrt.
# https://mullvad.net/en/help/dns-over-https-and-dns-over-tls
MULLVAD_DOT_RESOLVERS: tuple[tuple[str, str], ...] = (
    ("194.242.2.2", "dns.mullvad.net"),  # unfiltered
    ("193.138.218.74", "adblock.dns.mullvad.net"),  # ads/trackers/malware block
)
MULLVAD_DOT_PORT = 853
OPENWRT_LAN_DNS = "192.168.1.1"
OPENWRT_STUBBY_LISTEN = "127.0.0.1#5453"
