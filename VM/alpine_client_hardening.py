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

matching_remote_service_pids() {
  for proc in /proc/[0-9]*; do
    [ -r "$proc/comm" ] || continue
    comm="$(cat "$proc/comm" 2>/dev/null || true)"
    case "$comm" in
      sshd|dropbear) echo "${proc##*/}" ;;
    esac
  done
}

remove_matching_packages() {
  prefix="$1"
  apk info 2>/dev/null | while IFS= read -r pkg; do
    case "$pkg" in
      "$prefix"|"$prefix"-*) apk del "$pkg" ;;
    esac
  done
}

kill_matching_processes() {
  pids="$(matching_remote_service_pids)"
  [ -n "$pids" ] || return 0
  kill $pids 2>/dev/null || true
  sleep 1
  pids="$(matching_remote_service_pids)"
  [ -n "$pids" ] || return 0
  kill -9 $pids 2>/dev/null || true
}

install_remote_service_guard() {
  cat > /usr/local/sbin/overdrive-no-remote-services <<'GUARD'
#!/bin/sh
set -u

disable_service() {
  svc="$1"
  rc-service "$svc" stop >/dev/null 2>&1 || true
  for level in default boot sysinit shutdown nonetwork; do
    rc-update del "$svc" "$level" >/dev/null 2>&1 || true
    rm -f "/etc/runlevels/$level/$svc" 2>/dev/null || true
  done
}

matching_remote_service_pids() {
  for proc in /proc/[0-9]*; do
    [ -r "$proc/comm" ] || continue
    comm="$(cat "$proc/comm" 2>/dev/null || true)"
    case "$comm" in
      sshd|dropbear) echo "${proc##*/}" ;;
    esac
  done
}

remove_matching_packages() {
  prefix="$1"
  apk info 2>/dev/null | while IFS= read -r pkg; do
    case "$pkg" in
      "$prefix"|"$prefix"-*) apk del "$pkg" >/dev/null 2>&1 || true ;;
    esac
  done
}

for svc in sshd ssh dropbear; do
  disable_service "$svc"
done

remove_matching_packages openssh
remove_matching_packages dropbear

pids="$(matching_remote_service_pids)"
if [ -n "$pids" ]; then
  kill $pids 2>/dev/null || true
  sleep 1
  pids="$(matching_remote_service_pids)"
  [ -z "$pids" ] || kill -9 $pids 2>/dev/null || true
fi
GUARD

  cat > /etc/init.d/overdrive-no-remote-services <<'INIT'
#!/sbin/openrc-run
description="Disable remote login daemons on the disposable lab client"

depend() {
    need localmount
    after bootmisc net ssh sshd dropbear cloud-init cloud-final
}

start() {
    ebegin "Removing remote login daemons"
    /usr/local/sbin/overdrive-no-remote-services
    eend $?
}
INIT

  chmod 0755 /usr/local/sbin/overdrive-no-remote-services
  chmod 0755 /etc/init.d/overdrive-no-remote-services
  rc-update add overdrive-no-remote-services default
}

for svc in sshd ssh dropbear telnetd vsftpd lighttpd nginx apache2 crond chronyd ntpd; do
  disable_service "$svc"
done

remove_matching_packages openssh
remove_matching_packages dropbear

for pkg in openssh openssh-client openssh-client-common openssh-client-default openssh-keygen openssh-server openssh-server-common openssh-server-pam openssh-sftp-server dropbear dropbear-scp dropbear-ssh telnet-bsd busybox-extras; do
  remove_if_installed "$pkg"
done

for svc in sshd ssh dropbear; do
  disable_service "$svc"
done

install_remote_service_guard
/usr/local/sbin/overdrive-no-remote-services

kill_matching_processes

for bin in ssh sshd scp sftp dropbear dbclient dropbearkey; do
  if command -v "$bin" >/dev/null 2>&1; then
    echo "[overdrive] ERROR: SSH-related binary still present after hardening: $bin" >&2
    exit 1
  fi
done

if ss -tuln 2>/dev/null | awk '{print $5}' | grep -Eq '(^|[\]:])22$|:22$'; then
  echo "[overdrive] ERROR: port 22 is still listening after hardening" >&2
  exit 1
fi

rc-update add client-firewall boot
rc-update add client-firewall default
"""
