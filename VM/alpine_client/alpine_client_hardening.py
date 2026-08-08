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
# - outbound only DHCP, DNS to OpenWrt, targeted router discovery, TCP to
#   OpenWrt, HTTP/HTTPS, and ICMP troubleshooting
# - IPv6 blocked to avoid unmanaged network paths
set -eu

OPENWRT_DNS="192.168.1.1"
SSDP_MCAST="239.255.255.250"
MDNS_MCAST="224.0.0.251"

require_tools() {
  command -v iptables >/dev/null 2>&1
  command -v ip6tables >/dev/null 2>&1
}

flush_ipv4() {
  iptables -F
  iptables -X || true
  iptables -t nat -F 2>/dev/null || true
  iptables -t nat -X 2>/dev/null || true
  iptables -t mangle -F 2>/dev/null || true
  iptables -t mangle -X 2>/dev/null || true
}

flush_ipv6() {
  ip6tables -F
  ip6tables -X || true
  ip6tables -t nat -F 2>/dev/null || true
  ip6tables -t nat -X 2>/dev/null || true
  ip6tables -t mangle -F 2>/dev/null || true
  ip6tables -t mangle -X 2>/dev/null || true
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

  # Keep resolver traffic pinned to the OpenWrt router. Targeted UDP discovery
  # and TCP to the router stay open so router probes/admin checks still work.
  iptables -A OUTPUT -d "$OPENWRT_DNS" -p udp --dport 53 -j ACCEPT
  iptables -A OUTPUT -d "$OPENWRT_DNS" -p tcp --dport 53 -j ACCEPT
  iptables -A OUTPUT -d "$OPENWRT_DNS" -p udp -m multiport --dports 1900,5353 -j ACCEPT
  iptables -A OUTPUT -d "$OPENWRT_DNS" -p tcp -j ACCEPT

  # Preserve local router/discovery detections without opening general LAN egress.
  iptables -A OUTPUT -p igmp -j ACCEPT
  iptables -A INPUT -p igmp -j ACCEPT
  iptables -A OUTPUT -d "$SSDP_MCAST" -p udp --dport 1900 -j ACCEPT
  iptables -A OUTPUT -d "$MDNS_MCAST" -p udp --dport 5353 -j ACCEPT
  iptables -A INPUT -p udp --sport 1900 -j ACCEPT
  iptables -A INPUT -d "$MDNS_MCAST" -p udp --sport 5353 --dport 5353 -j ACCEPT

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

SYSCTL_FILE="/etc/sysctl.d/99-overdrive-client-hardening.conf"

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
    apk del --purge "$pkg" || apk del "$pkg" || true
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
      "$prefix"|"$prefix"-*) apk del --purge "$pkg" >/dev/null 2>&1 || apk del "$pkg" >/dev/null 2>&1 || true ;;
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

install_privacy_profile() {
  mkdir -p /etc/profile.d
  cat > /etc/profile.d/99-overdrive-privacy.sh <<'PROFILE'
# Overdrive disposable client privacy defaults.
umask 077
export HISTFILE=/dev/null
export HISTSIZE=0
export SAVEHIST=0
export LESSHISTFILE=/dev/null
export PYTHONHISTFILE=/dev/null
export WGETRC=/etc/wgetrc
ulimit -c 0 2>/dev/null || true
PROFILE
  chmod 0644 /etc/profile.d/99-overdrive-privacy.sh

  cat > /etc/wgetrc <<'WGETRC'
hsts_file = /dev/null
WGETRC
  chmod 0644 /etc/wgetrc
}

install_sysctl_hardening() {
  mkdir -p /etc/sysctl.d
  cat > "$SYSCTL_FILE" <<'SYSCTL'
# Overdrive disposable client network/kernel hardening.
kernel.core_pattern = /dev/null
kernel.core_uses_pid = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
SYSCTL
  chmod 0644 "$SYSCTL_FILE"
  if command -v sysctl >/dev/null 2>&1; then
    while IFS= read -r line; do
      case "$line" in
        ""|\#*) continue ;;
      esac
      setting="$(printf '%s' "$line" | sed 's/[[:space:]]*=[[:space:]]*/=/')"
      sysctl -w "$setting" >/dev/null 2>&1 || true
    done < "$SYSCTL_FILE"
  fi

  cat > /etc/init.d/overdrive-sysctl-hardening <<'INIT'
#!/sbin/openrc-run
description="Apply Overdrive Alpine client sysctl hardening"

depend() {
    need localmount
    before net
}

start() {
    ebegin "Applying Overdrive sysctl hardening"
    if command -v sysctl >/dev/null 2>&1 && [ -f /etc/sysctl.d/99-overdrive-client-hardening.conf ]; then
        while IFS= read -r line; do
            case "$line" in
                ""|\#*) continue ;;
            esac
            setting="$(printf '%s' "$line" | sed 's/[[:space:]]*=[[:space:]]*/=/')"
            sysctl -w "$setting" >/dev/null 2>&1 || true
        done < /etc/sysctl.d/99-overdrive-client-hardening.conf
    fi
    eend 0
}
INIT
  chmod 0755 /etc/init.d/overdrive-sysctl-hardening
  rc-update add overdrive-sysctl-hardening boot >/dev/null 2>&1 || true
}

install_filesystem_hardening() {
  chmod 0700 /root 2>/dev/null || true
  chmod 0644 /etc/passwd /etc/group 2>/dev/null || true
  chmod 0600 /etc/shadow /etc/gshadow 2>/dev/null || true
  chmod 1777 /tmp /var/tmp 2>/dev/null || true
  mkdir -p /root/.cache
  chmod 0700 /root/.cache
  touch /root/.ash_history
  chmod 0600 /root/.ash_history
  rm -f /root/.wget-hsts /root/.python_history /root/.lesshst /root/.bash_history 2>/dev/null || true
}

scrub_tracking_identifiers() {
  # Remove stable host/instance IDs that can correlate DHCP or local state.
  rm -f /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true
  : > /etc/machine-id 2>/dev/null || true
  chmod 0444 /etc/machine-id 2>/dev/null || true
  rm -rf /var/lib/cloud 2>/dev/null || true
  rm -f /etc/cloud/cloud.cfg.d/* 2>/dev/null || true
}

clean_private_artifacts() {
  rm -f /etc/ssh/ssh_host_* /etc/dropbear/dropbear_* 2>/dev/null || true
  rm -f /root/.ash_history /root/.wget-hsts /root/.python_history /root/.lesshst /root/.bash_history 2>/dev/null || true
  find /tmp /var/tmp -mindepth 1 -maxdepth 1 -name 'overdrive-*' -exec rm -rf {} + 2>/dev/null || true
  find /var/cache/apk -type f -name '*.apk' -delete 2>/dev/null || true
  find /var/log -type f -exec sh -c ': > "$1"' sh {} \; 2>/dev/null || true
  scrub_tracking_identifiers
}

remove_remote_login_artifacts() {
  rm -f \
    /usr/sbin/sshd \
    /usr/bin/ssh /usr/bin/scp /usr/bin/sftp \
    /usr/bin/ssh-add /usr/bin/ssh-agent /usr/bin/ssh-keygen /usr/bin/ssh-keyscan \
    /usr/sbin/dropbear /usr/bin/dropbear /usr/bin/dbclient \
    /usr/bin/dropbearkey /usr/bin/dropbearconvert /usr/bin/dropbearmulti \
    /usr/bin/telnet /usr/bin/telnetd /usr/sbin/telnetd \
    2>/dev/null || true
  rm -rf /etc/ssh /etc/dropbear /root/.ssh 2>/dev/null || true
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

install_privacy_profile
install_sysctl_hardening
install_filesystem_hardening

remove_matching_packages openssh
remove_matching_packages dropbear

for pkg in openssh openssh-client openssh-client-common openssh-client-default openssh-keygen openssh-server openssh-server-common openssh-server-pam openssh-sftp-server dropbear dropbear-scp dropbear-ssh telnet-bsd busybox-extras; do
  remove_if_installed "$pkg"
done
remove_remote_login_artifacts

for svc in sshd ssh dropbear; do
  disable_service "$svc"
done

install_remote_service_guard
/usr/local/sbin/overdrive-no-remote-services

kill_matching_processes
remove_remote_login_artifacts

for bin in sshd dropbear telnetd; do
  if command -v "$bin" >/dev/null 2>&1; then
    echo "[overdrive] ERROR: remote-login daemon binary still present after hardening: $bin" >&2
    exit 1
  fi
done

if ss -tuln 2>/dev/null | awk '{print $5}' | grep -Eq '(^|[\]:])22$|:22$'; then
  echo "[overdrive] ERROR: port 22 is still listening after hardening" >&2
  exit 1
fi

clean_private_artifacts

rc-update add client-firewall boot
rc-update add client-firewall default
"""
