"""Shared constants and probe configuration for Overdrive scripts."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final

__all__ = [
    "ABUSEIPDB_CHECK_URL",
    "BLACKLIST_TIMEOUT",
    "BROWSER_ECHO_TIMEOUT",
    "BROWSERLEAKS_WEBRTC_URL",
    "DNSBL_ZONES",
    "FIREHOL_PROXIES_URL",
    "FIREHOL_TOR_EXITS_1D_URL",
    "FIREHOL_TOR_EXITS_7D_URL",
    "GEOIP_PROVIDERS",
    "HTTP_ECHO_URLS",
    "IP_API_URL",
    "IP_API_URL_WITH_FIELDS",
    "IPAPI_AUTO_URL",
    "IPAPI_IP_URL",
    "LAN_PROBE_URLS",
    "ONIONOO_DETAILS_URL",
    "OVERDRIVE_CACHE_DIR",
    "PROXY_TIMEOUT",
    "TOR_PROXY_TIMEOUT",
    "USER_AGENTS",
    "ZEN_BLOCKED_RESOLVER",
    "ZEN_PBL_OCTET",
    "ZEN_SEVERE_OCTETS",
]


HTTP_ECHO_URLS: Final[tuple[str, ...]] = (
    "https://httpbin.org/get",
    "https://postman-echo.com/get",
)

LAN_PROBE_URLS: Final[tuple[str, ...]] = (
    "https://example.com/",
    "http://example.com/",
    "https://one.one.one.one/",
)

GEOIP_PROVIDERS: Final[tuple[Mapping[str, str], ...]] = (
    MappingProxyType({"name": "ipapi.co", "url": "https://ipapi.co/json/"}),
    MappingProxyType({"name": "ip-api.com", "url": "http://ip-api.com/json/"}),
    MappingProxyType({"name": "ipapi.is", "url": "https://api.ipapi.is/json/"}),
)

BROWSERLEAKS_WEBRTC_URL: Final = "https://browserleaks.com/webrtc"

IP_API_URL: Final = "http://ip-api.com/json/{ip}"
IP_API_URL_WITH_FIELDS: Final = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,query,isp,org,as,hosting,mobile,proxy"
)
IPAPI_AUTO_URL: Final = "https://ipapi.co/json/"
IPAPI_IP_URL: Final = "https://ipapi.co/{ip}/json/"

ONIONOO_DETAILS_URL: Final = "https://onionoo.torproject.org/details"
FIREHOL_PROXIES_URL: Final = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_proxies.netset"
)
FIREHOL_TOR_EXITS_1D_URL: Final = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits_1d.ipset"
)
FIREHOL_TOR_EXITS_7D_URL: Final = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits_7d.ipset"
)
ABUSEIPDB_CHECK_URL: Final = "https://api.abuseipdb.com/api/v2/check"

DNSBL_ZONES: Final[tuple[tuple[str, str], ...]] = (
    ("zen.spamhaus.org", "spamhaus-zen"),
    ("bl.spamcop.net", "spamcop"),
    ("b.barracudacentral.org", "barracuda"),
)
ZEN_SEVERE_OCTETS: Final[frozenset[int]] = frozenset({2, 3, 4, 9, 11})
ZEN_PBL_OCTET: Final = 10
ZEN_BLOCKED_RESOLVER: Final = "127.255.255.254"

BLACKLIST_TIMEOUT: Final = 8
PROXY_TIMEOUT: Final = 12
BROWSER_ECHO_TIMEOUT: Final = 25
TOR_PROXY_TIMEOUT: Final = 15

USER_AGENTS: Final[Mapping[str, str]] = MappingProxyType({
    "asn": "overdrive-asn-lookup/1.0",
    "blacklist": "overdrive-blacklist-check/1.0",
    "clock_time_mismatch": "overdrive-clock-time-mismatch/1.0",
    "egress_ptr": "overdrive-egress-ptr/1.0",
    "ipv6_leak": "overdrive-ipv6-leak/1.0",
    "proxy": "overdrive-proxy-detect/1.0",
    "tor_proxy": "overdrive-tor-proxy-reputation/1.0",
})

OVERDRIVE_CACHE_DIR: Final = Path.home() / ".cache" / "overdrive"
