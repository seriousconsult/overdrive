#!/bin/sh
# Overdrive lab: Mullvad DNS-over-TLS via stubby; LAN clients use OpenWrt as DNS.
# Safe to re-run. Requires WAN (NAT/bridged) so apk/opkg can fetch stubby.
set -e
DONE=/etc/overdrive-mullvad-dot.done

echo "[overdrive] Installing stubby for Mullvad DoT..."
if command -v apk >/dev/null 2>&1; then
  apk update
  apk add stubby ca-bundle
elif command -v opkg >/dev/null 2>&1; then
  opkg update
  opkg install stubby ca-bundle
else
  echo "[overdrive] ERROR: neither apk nor opkg found" >&2
  exit 1
fi

echo "[overdrive] Configuring stubby → Mullvad DoT..."
while uci -q delete stubby.@resolver[0]; do :; done
uci add stubby resolver
uci set stubby.@resolver[-1].address='194.242.2.2'
uci set stubby.@resolver[-1].tls_auth_name='dns.mullvad.net'
uci set stubby.@resolver[-1].tls_port='853'
uci add stubby resolver
uci set stubby.@resolver[-1].address='194.242.2.4'
uci set stubby.@resolver[-1].tls_auth_name='base.dns.mullvad.net'
uci set stubby.@resolver[-1].tls_port='853'
uci set stubby.global.manual='0'
uci set stubby.global.trigger='wan'
uci set stubby.global.tls_authentication='1'
uci set stubby.global.round_robin_upstreams='1'
uci -q delete stubby.global.listen_address
uci add_list stubby.global.listen_address='127.0.0.1@5453'
uci add_list stubby.global.listen_address='0::1@5453'
uci commit stubby

echo "[overdrive] Pointing dnsmasq at stubby; advertising LAN DNS 192.168.1.1..."
uci -q delete dhcp.@dnsmasq[0].server
uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5453'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci set dhcp.@dnsmasq[0].localuse='1'
# DHCP option 6: clients must use OpenWrt, not upstream Mullvad IPs directly
uci -q delete dhcp.lan.dhcp_option
uci add_list dhcp.lan.dhcp_option='6,192.168.1.1'
uci commit dhcp

# Stop relying on VBox/WAN plaintext DNS once DoT is in place
uci -q delete network.wan.dns
uci set network.wan.peerdns='0'
uci commit network

/etc/init.d/stubby enable
/etc/init.d/stubby restart
/etc/init.d/dnsmasq restart

touch "$DONE"
echo "[overdrive] Done. Verify: nslookup google.com 192.168.1.1"
nslookup google.com 192.168.1.1 || true
