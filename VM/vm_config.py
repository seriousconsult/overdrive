"""
Configuration constants for the VirtualBox lab VMs.
"""

# Mullvad public DNS-over-TLS (DoT). Plain UDP/53 is refused; use stubby on OpenWrt.
# https://mullvad.net/en/help/dns-over-https-and-dns-over-tls
MULLVAD_DOT_RESOLVERS: tuple[tuple[str, str], ...] = (
    ("194.242.2.2", "dns.mullvad.net"),  # unfiltered
    ("194.242.2.3", "adblock.dns.mullvad.net"),  # adblock
)
MULLVAD_DOT_PORT = 853
OPENWRT_LAN_DNS = "192.168.1.1"
OPENWRT_STUBBY_LISTEN = "127.0.0.1#5453"

# Public default password used by the Alpine nocloud image for this disposable lab VM.
# Do not put private/reused passwords in this tracked config file.
ALPINE_CLIENT_ROOT_PASSWORD = "osboxes.org"
