"""Generated OpenWrt helper scripts and config assets."""

from VM.vm_config import (
    MULLVAD_DOT_PORT,
    MULLVAD_DOT_RESOLVERS,
    OPENWRT_LAN_DNS,
    OPENWRT_STUBBY_LISTEN,
)


__all__ = [
    "APPLY_MULLVAD_DOT_SH",
    "OVERDRIVE_MULLVAD_INIT_D",
    "UCI_DEFAULTS_ENABLE_MULLVAD",
]


_MULLVAD_STUBBY_YAML_UPSTREAMS = "\n".join(
    f"  - address_data: {ip}\n"
    f"    tls_auth_name: \"{name}\"\n"
    f"    tls_port: {MULLVAD_DOT_PORT}"
    for ip, name in MULLVAD_DOT_RESOLVERS
)

_MULLVAD_RESOLVER_UCI = "\n".join(
    f"uci add stubby resolver\n"
    f"uci set stubby.@resolver[-1].address='{ip}'\n"
    f"uci set stubby.@resolver[-1].tls_auth_name='{name}'\n"
    f"uci set stubby.@resolver[-1].tls_port='{MULLVAD_DOT_PORT}'"
    for ip, name in MULLVAD_DOT_RESOLVERS
)

APPLY_MULLVAD_DOT_SH = f"""#!/bin/sh
# Overdrive lab: Mullvad DNS-over-TLS via stubby; LAN clients use OpenWrt as DNS.
# Idempotent: safe to re-run. Force with: FORCE=1 /root/apply_mullvad_dot.sh
# Use DEBUG=1 for shell tracing (default set -x flooded serial logs).
[ "${{DEBUG:-0}}" = "1" ] && set -x

DONE=/etc/overdrive-mullvad-dot.done

# whoami.akamai.net returns the recursive resolver's source IP as seen by Akamai.
# Mullvad publishes anycast 194.242.2.x; whoami often returns the PoP unicast behind
# that anycast (e.g. 193.148.18.30 = us-nyc-dns-601.mullvad.net), NOT 194.242.2.x.
# ISP/VBox NAT (e.g. Verizon 71.x) means dnsmasq is NOT going through stubby→Mullvad.
parse_whoami_ip() {{
  # Last public IPv4 in nslookup/dig output (skip 127.x / 10.x / 192.168.x answers).
  echo "$1" | grep -Eo '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' | awk '
    $0 !~ /^127\\./ && $0 !~ /^10\\./ && $0 !~ /^192\\.168\\./ && $0 !~ /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./ {{ ip=$0 }}
    END {{ print ip }}
  '
}}

verify_mullvad_upstream() {{
  local out ip
  if command -v dig >/dev/null 2>&1; then
    out="$(dig +time=3 +tries=2 +short @127.0.0.1 whoami.akamai.net A 2>/dev/null || true)"
  else
    out="$(nslookup whoami.akamai.net 127.0.0.1 2>/dev/null || true)"
  fi
  echo "$out"
  ip="$(parse_whoami_ip "$out")"
  case "$ip" in
    194.242.2.*)
      echo "[overdrive] Upstream whoami=$ip (Mullvad anycast) — OK"
      return 0
      ;;
    "")
      echo "[!!] Could not parse whoami.akamai.net via 127.0.0.1"
      return 1
      ;;
    71.*|96.*)
      echo "[!!] Upstream whoami=$ip — ISP/VBox DNS, not Mullvad."
      return 1
      ;;
  esac
  # PoP unicast behind Mullvad anycast (e.g. 193.148.18.30). Require Mullvad stubby config.
  if grep -q 'dns.mullvad.net' /etc/stubby/stubby.yml 2>/dev/null; then
    echo "[overdrive] Upstream whoami=$ip (Mullvad DoT PoP via stubby.yml) — OK"
    return 0
  fi
  echo "[!!] Upstream whoami=$ip but stubby.yml missing dns.mullvad.net."
  return 1
}}

if [ -f "$DONE" ] && [ "${{FORCE:-0}}" != "1" ]; then
  if grep -q 'dns.mullvad.net' /etc/stubby/stubby.yml 2>/dev/null \\
    && grep -q '127.0.0.1#5453\\|127.0.0.1@5453' /etc/config/dhcp 2>/dev/null \\
    && verify_mullvad_upstream; then
    echo "[overdrive] Mullvad DoT already configured (use FORCE=1 to re-apply)."
    exit 0
  fi
  echo "[overdrive] DONE marker present but Mullvad upstream not verified; re-applying..."
  rm -f "$DONE"
fi

echo "--- [debug] Initial DNS (/etc/resolv.conf) ---"
cat /etc/resolv.conf 2>/dev/null || true
ls -la /tmp/resolv.conf.d 2>/dev/null || true

echo "[overdrive] Syncing time (TLS needs correct clock)..."
/etc/init.d/sysntpd stop 2>/dev/null || true
# BusyBox ntpd can hang; bound it so serial apply cannot stall forever.
if command -v timeout >/dev/null 2>&1; then
  timeout 20 ntpd -n -q -p 1.1.1.1 || timeout 20 ntpd -n -q -p 9.9.9.9 || true
else
  ntpd -n -q -p 1.1.1.1 || ntpd -n -q -p 9.9.9.9 || true
fi
/etc/init.d/sysntpd start 2>/dev/null || true

install_stubby() {{
  if command -v stubby >/dev/null 2>&1; then
    echo "[overdrive] stubby already installed: $(command -v stubby)"
    return 0
  fi
  # Prefer offline APKs injected into the image (no apk update / mirror fetch).
  if [ -d /root/overdrive-apks ] && ls /root/overdrive-apks/*.apk >/dev/null 2>&1; then
    echo "[overdrive] Installing stubby from offline APKs in /root/overdrive-apks..."
    # OpenWrt 25.12+: apk replaces opkg. Local files need --allow-untrusted.
    apk add --allow-untrusted /root/overdrive-apks/*.apk || return 1
    command -v stubby >/dev/null 2>&1 || return 1
    return 0
  fi
  if command -v apk >/dev/null 2>&1; then
    echo "[overdrive] No offline APKs; apk update + add stubby (needs WAN DNS)..."
    if command -v timeout >/dev/null 2>&1; then
      timeout 120 apk update || return 1
      timeout 180 apk add stubby ca-bundle ca-certificates || return 1
    else
      apk update || return 1
      apk add stubby ca-bundle ca-certificates || return 1
    fi
  elif command -v opkg >/dev/null 2>&1; then
    echo "[overdrive] opkg update (legacy OpenWrt < 25.12)..."
    if command -v timeout >/dev/null 2>&1; then
      timeout 180 opkg update || return 1
      timeout 180 opkg install stubby ca-bundle ca-certificates || return 1
    else
      opkg update || return 1
      opkg install stubby ca-bundle ca-certificates || return 1
    fi
  else
    echo "[!!] FATAL: neither apk nor opkg found"
    return 1
  fi
}}

install_stubby || {{
  echo "[!!] FATAL: could not install stubby"
  exit 1
}}

echo "[overdrive] Writing /etc/stubby/stubby.yml for Mullvad DoT..."
mkdir -p /etc/stubby
cat > /etc/stubby/stubby.yml << 'STUBBY_EOF'
# Generated by overdrive apply_mullvad_dot.sh — Mullvad DNS-over-TLS only.
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1
round_robin_upstreams: 1
idle_timeout: 10000
listen_addresses:
  - 127.0.0.1@5453
upstream_recursive_servers:
{_MULLVAD_STUBBY_YAML_UPSTREAMS}
STUBBY_EOF

# Prefer the packaged CA bundle if present.
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
  printf '\\ntls_ca_file: "/etc/ssl/certs/ca-certificates.crt"\\n' >> /etc/stubby/stubby.yml
elif [ -f /etc/ssl/cert.pem ]; then
  printf '\\ntls_ca_file: "/etc/ssl/cert.pem"\\n' >> /etc/stubby/stubby.yml
fi

echo "--- [debug] stubby.yml ---"
cat /etc/stubby/stubby.yml

# manual=1 → use stubby.yml (NOT UCI). Earlier bug: manual=1 + UCI Mullvad = Cloudflare defaults.
echo "[overdrive] Pointing OpenWrt stubby init at stubby.yml (manual=1)..."
while uci -q delete stubby.@resolver[0]; do :; done
{_MULLVAD_RESOLVER_UCI}
uci set stubby.global.manual='1'
uci set stubby.global.trigger='wan'
uci set stubby.global.tls_authentication='1'
uci set stubby.global.round_robin_upstreams='1'
uci -q delete stubby.global.listen_address
uci add_list stubby.global.listen_address='127.0.0.1@5453'
uci commit stubby

echo "[overdrive] dnsmasq → stubby ONLY; ignore WAN/VBox resolv (noresolv)..."
uci -q delete dhcp.@dnsmasq[0].server
uci add_list dhcp.@dnsmasq[0].server='{OPENWRT_STUBBY_LISTEN}'
uci set dhcp.@dnsmasq[0].noresolv='1'
# Keep a resolvfile path that cannot reintroduce ISP DNS if noresolv is ignored.
uci set dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.overdrive-empty'
: > /tmp/resolv.conf.overdrive-empty
uci set dhcp.@dnsmasq[0].localuse='1'
uci -q delete dhcp.lan.dhcp_option
uci add_list dhcp.lan.dhcp_option='6,{OPENWRT_LAN_DNS}'
uci commit dhcp

echo "[overdrive] Disable WAN plaintext DNS (peerdns) and reload network..."
uci -q delete network.wan.dns
uci set network.wan.peerdns='0'
uci commit network
# Critical: peerdns=0 does nothing until network reloads; otherwise VBox NAT DNS
# (host→ISP) stays in /tmp/resolv.conf.d/resolv.conf.auto and dnsmasq may use it.
/etc/init.d/network reload 2>/dev/null || ubus call network reload 2>/dev/null || true
sleep 2

# Router itself must query local dnsmasq (which forwards to stubby → Mullvad DoT).
mkdir -p /tmp/resolv.conf.d
: > /tmp/resolv.conf.overdrive-empty
# Neutralize auto resolv from WAN DHCP / natdnshostresolver.
rm -f /tmp/resolv.conf.d/resolv.conf.auto
echo "# overdrive: ISP resolv disabled; use dnsmasq→stubby" > /tmp/resolv.conf.d/resolv.conf.auto
rm -f /tmp/resolv.conf
echo "nameserver 127.0.0.1" > /tmp/resolv.conf
if [ -L /etc/resolv.conf ]; then
  :
else
  echo "nameserver 127.0.0.1" > /etc/resolv.conf
fi

/etc/init.d/stubby enable
/etc/init.d/stubby restart
/etc/init.d/dnsmasq restart
sleep 4

echo "--- [debug] listeners / processes ---"
netstat -lnu 2>/dev/null | grep -E '5453|:53' || ss -uln 2>/dev/null | grep -E '5453|:53' || true
ps w | grep -E 'stubby|dnsmasq' | grep -v grep || true
echo "--- [debug] dnsmasq UCI ---"
uci get dhcp.@dnsmasq[0].noresolv; uci get dhcp.@dnsmasq[0].server
uci get network.wan.peerdns

echo "--- [debug] DNS via dnsmasq ---"
if ! nslookup google.com 127.0.0.1; then
  echo "[!!] DNS via dnsmasq FAILED — check /tmp/overdrive-mullvad-dot.log and stubby"
  exit 1
fi

# Prove stubby is answering on 5453 (DoT path), not just VBox/WAN DNS.
echo "--- [debug] stubby :5453 ---"
if command -v dig >/dev/null 2>&1; then
  dig +time=3 +tries=1 @127.0.0.1 -p 5453 google.com +short || {{
    echo "[!!] stubby on 5453 did not answer — DoT path broken"
    exit 1
  }}
elif command -v nslookup >/dev/null 2>&1; then
  nslookup -port=5453 google.com 127.0.0.1 || {{
    echo "[!!] stubby on 5453 did not answer — DoT path broken"
    exit 1
  }}
else
  echo "[!!] neither dig nor nslookup available to probe stubby"
  exit 1
fi

grep -q 'dns.mullvad.net' /etc/stubby/stubby.yml || {{
  echo "[!!] stubby.yml missing Mullvad — abort"
  exit 1
}}

echo "--- [debug] whoami (Mullvad anycast 194.242.2.x or PoP *.mullvad.net) ---"
verify_mullvad_upstream || {{
  echo "[!!] Resolving works but upstream is not Mullvad — refusing to mark DONE"
  echo "     Check: uci get dhcp.@dnsmasq[0].noresolv; uci get dhcp.@dnsmasq[0].server"
  echo "     Check: ps | grep stubby; cat /etc/stubby/stubby.yml"
  exit 1
}}

touch "$DONE"
echo "[overdrive] Mullvad DoT active: client → {OPENWRT_LAN_DNS} → stubby → Mullvad :{MULLVAD_DOT_PORT}"
rm -f /root/apply_mullvad_dot.sh
"""

OVERDRIVE_MULLVAD_INIT_D = """#!/bin/sh /etc/rc.common
# After WAN is up, install stubby and switch DNS to Mullvad DoT.
# Retries until whoami proves Mullvad (or attempts exhausted).
START=99
STOP=10

boot() {
	start
}

start() {
	[ -f /etc/overdrive-mullvad-dot.done ] && [ ! -x /root/apply_mullvad_dot.sh ] && return 0
	[ -x /root/apply_mullvad_dot.sh ] || return 1
	(
		i=0
		while [ "$i" -lt 90 ]; do
			if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 \\
				|| ping -c1 -W2 9.9.9.9 >/dev/null 2>&1; then
				break
			fi
			i=$((i + 1))
			sleep 2
		done
		attempt=1
		while [ "$attempt" -le 3 ]; do
			echo "[overdrive] Mullvad DoT apply attempt $attempt" >>/tmp/overdrive-mullvad-dot.log
			if FORCE=1 /root/apply_mullvad_dot.sh >>/tmp/overdrive-mullvad-dot.log 2>&1; then
				exit 0
			fi
			attempt=$((attempt + 1))
			sleep 10
		done
		echo "[overdrive] Mullvad DoT setup FAILED after retries; see /tmp/overdrive-mullvad-dot.log" >&2
	) &
}

stop() {
	return 0
}
"""

UCI_DEFAULTS_ENABLE_MULLVAD = """#!/bin/sh
# Enable one-shot Mullvad DoT setup on first boot.
[ -x /etc/init.d/overdrive-mullvad-dot ] && /etc/init.d/overdrive-mullvad-dot enable
exit 0
"""
