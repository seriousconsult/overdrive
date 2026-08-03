"""Alpine client hardening scripts and OpenRC assets."""

__all__ = [
    "CLIENT_FIREWALL_INIT_ALPINE",
    "CLIENT_FIREWALL_SCRIPT",
    "CLIENT_HARDENING_SCRIPT",
]


CLIENT_FIREWALL_INIT_ALPINE = """#!/sbin/openrc-run
description="OpenWrt lab client firewall"

depend() {
    need localmount
    after bootmisc
    before net
}

start() {
    ebegin "Starting client firewall"
    /usr/local/sbin/client-firewall start
    eend $?
}

stop() {
    ebegin "Stopping client firewall"
    /usr/local/sbin/client-firewall stop
    eend $?
}
"""

CLIENT_FIREWALL_SCRIPT = r"""#!/bin/sh
# Restrictive client policy:
# - default deny inbound and forwarding
# - outbound only DHCP, DNS to OpenWrt, TCP to OpenWrt, HTTP/HTTPS, and ICMP troubleshooting
# - IPv6 blocked to avoid unmanaged network paths
set -eu

OPENWRT_DNS="192.168.1.1"

require_tools() {
  command -v iptables >/dev/null 2>&1
  command -v ip6tables >/dev/null 2>&1
}

flush_ipv4() {
  iptables -F
  iptables -X || true
}

flush_ipv6() {
  ip6tables -F
  ip6tables -X || true
}

start_firewall() {
  require_tools
  flush_ipv4
  flush_ipv6

  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT DROP

  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  iptables -A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT
  iptables -A INPUT -p udp --sport 67 --dport 68 -j ACCEPT

  iptables -A OUTPUT -d "$OPENWRT_DNS" -p udp --dport 53 -j ACCEPT
  iptables -A OUTPUT -d "$OPENWRT_DNS" -p tcp --dport 53 -j ACCEPT
  iptables -A OUTPUT -d "$OPENWRT_DNS" -p tcp -j ACCEPT

  iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
  iptables -A OUTPUT -p icmp -j ACCEPT
  iptables -A INPUT -p icmp -j ACCEPT

  ip6tables -P INPUT DROP
  ip6tables -P FORWARD DROP
  ip6tables -P OUTPUT DROP
  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A OUTPUT -o lo -j ACCEPT
  ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

stop_firewall() {
  require_tools
  flush_ipv4
  flush_ipv6
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT
  ip6tables -P INPUT DROP
  ip6tables -P FORWARD DROP
  ip6tables -P OUTPUT DROP
}

case "${1:-start}" in
  start) start_firewall ;;
  stop) stop_firewall ;;
  restart) stop_firewall; start_firewall ;;
  *) echo "usage: $0 {start|stop|restart}" >&2; exit 2 ;;
esac
"""

CLIENT_HARDENING_SCRIPT = r"""#!/bin/sh
# Security hardening for the disposable Alpine client VM.
set -eu

disable_service() {
  svc="$1"
  rc-service "$svc" stop >/dev/null 2>&1 || true
  for level in default boot sysinit shutdown nonetwork; do
    rc-update del "$svc" "$level" >/dev/null 2>&1 || true
  done
}

remove_if_installed() {
  pkg="$1"
  if apk info -e "$pkg" >/dev/null 2>&1; then
    apk del "$pkg"
  fi
}

for svc in sshd ssh dropbear telnetd vsftpd lighttpd nginx apache2 crond chronyd ntpd; do
  disable_service "$svc"
done

for pkg in openssh openssh-server openssh-client openssh-keygen dropbear dropbear-scp dropbear-ssh telnet-bsd busybox-extras; do
  remove_if_installed "$pkg"
done

for bin in ssh sshd scp sftp dropbear dbclient dropbearkey; do
  if command -v "$bin" >/dev/null 2>&1; then
    echo "[overdrive] ERROR: SSH-related binary still present after hardening: $bin" >&2
    exit 1
  fi
done

rc-update add client-firewall boot
rc-update add client-firewall default
"""
