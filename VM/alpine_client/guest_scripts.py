"""Guest shell/OpenRC assets and virt-customize command strings."""

from __future__ import annotations

from VM.alpine_client.client_config import CLIENT_GUEST_HOSTNAME
from VM.vm_config import OPENWRT_LAN_DNS

__all__ = [
    "ASSERT_NO_REMOTE_BOOT_HOOKS_COMMAND",
    "CLEAN_CLIENT_PRIME_HELPERS_COMMAND",
    "CLIENT_IDENTITY_COMMAND",
    "CLIENT_IP_TIMEZONE_INIT_ALPINE",
    "CLIENT_IP_TIMEZONE_SCRIPT",
    "CONFIGURE_CLIENT_SERVICES_AND_BOOT_COMMAND",
    "INSTALL_DETECTION_LIBRARIES_COMMAND",
    "REMOVE_CLIENT_INSTALL_PY_COMMAND",
    "LAB_INTERFACES_ALPINE",
    "LAB_NET_TROUBLESHOOT_SCRIPT",
    "LAB_NET_UP_INIT_ALPINE",
    "LAB_NET_UP_SCRIPT",
    "REMOTE_BOOT_SERVICE_CLEANUP_COMMAND",
]

LAB_INTERFACES_ALPINE = """auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
"""

LAB_NET_UP_INIT_ALPINE = """#!/sbin/openrc-run
description="Lab LAN: link up + DHCP"

depend() {
    need localmount client-firewall
    after bootmisc
}

start() {
    ebegin "Starting lab-net-up"
    /usr/local/sbin/lab-net-up
    eend $?
}
"""

LAB_NET_UP_SCRIPT = f"""#!/bin/sh
# Bring up Ethernet NICs and request DHCP from OpenWrt when still unaddressed.
set -u
ok=0
for path in /sys/class/net/*; do
  IFACE=$(basename "$path")
  [ "$IFACE" = lo ] && continue
  [ ! -e "$path/device" ] && continue
  ip link set "$IFACE" up || true
  if ip -4 -o addr show dev "$IFACE" 2>/dev/null | grep -q ' inet '; then
    ok=1
    continue
  fi
  # Neutral DHCP identity: send generic hostname, empty vendor class (no alpine/overdrive).
  if udhcpc -i "$IFACE" -n -q -x hostname:{CLIENT_GUEST_HOSTNAME} -V ""; then
    ok=1
  fi
done
ip -4 route show default 2>/dev/null | grep -q . && exit 0
[ "$ok" -eq 1 ]
"""

LAB_NET_TROUBLESHOOT_SCRIPT = f"""#!/bin/sh
# Installed by create_VM_client_browser_pipe_alpine.py
set -u
echo "================================================================"
echo " Lab network troubleshoot (test client on test-lan)"
echo "================================================================"
echo ""
echo "=== IPv4 addresses ==="
ip -br -4 addr 2>/dev/null || true
echo ""
echo "=== Link state ==="
ip -br link 2>/dev/null || true
echo ""
echo "=== Routes ==="
ip route 2>/dev/null || true
echo ""
echo "=== Default IPv4 route ==="
if ip -4 route show default 2>/dev/null | grep -q .; then
  ip -4 route show default
else
  echo "(none) - no DHCP lease or no gateway from OpenWrt."
fi
echo ""
echo "=== Resolver (/etc/resolv.conf) ==="
if [ -r /etc/resolv.conf ]; then
  cat /etc/resolv.conf
else
  echo "(missing) - no DNS nameserver configured."
fi
echo ""
echo "=== DHCP on each Ethernet-like interface ==="
for IFACE in /sys/class/net/*; do
  IFACE=$(basename "$IFACE")
  [ "$IFACE" = lo ] && continue
  [ ! -e "/sys/class/net/$IFACE/device" ] && continue
  echo "--- link up + udhcpc $IFACE ---"
  if [ "$(id -u)" -eq 0 ]; then
    ip link set "$IFACE" up 2>&1 || true
    udhcpc -i "$IFACE" -n -q -x hostname:{CLIENT_GUEST_HOSTNAME} -V "" 2>&1 || true
  else
    sudo ip link set "$IFACE" up 2>&1 || true
    sudo udhcpc -i "$IFACE" -n -q -x hostname:{CLIENT_GUEST_HOSTNAME} -V "" 2>&1 || true
  fi
done
echo ""
echo "=== After DHCP ==="
ip -br -4 addr 2>/dev/null || true
ip -4 route show default 2>/dev/null || true
echo ""
echo "=== L3 vs DNS ==="
echo "--- ping gateway ---"
ping -c2 -W2 {OPENWRT_LAN_DNS} 2>&1 || true
echo "--- ping 8.8.8.8 ---"
ping -c2 -W3 8.8.8.8 2>&1 || true
echo "--- ping google.com ---"
ping -c2 -W3 google.com 2>&1 || true
echo ""
if command -v dig >/dev/null 2>&1; then
  echo "=== dig via OpenWrt ({OPENWRT_LAN_DNS}) ==="
  dig +time=2 +tries=1 +short @{OPENWRT_LAN_DNS} google.com 2>&1 || true
  echo ""
fi
"""

CLIENT_IP_TIMEZONE_SCRIPT = r"""#!/bin/sh
# Set the test client's timezone to the timezone reported for its current egress IP.
#
# This intentionally changes only the local timezone presentation
# (/etc/localtime + /etc/timezone). The system clock remains UTC internally.
set -u

LOG=/var/log/overdrive-ip-timezone.log
TZDIR=/usr/share/zoneinfo

log() {
  echo "[overdrive-tz] $*"
  echo "[overdrive-tz] $*" >> "$LOG"
}

valid_tz() {
  tz="$1"
  [ -n "$tz" ] || return 1
  case "$tz" in
    /*|*..*|*//*|*\\*|UTC|Etc/UTC|Etc/GMT*) return 1 ;;
  esac
  [ -f "$TZDIR/$tz" ]
}

fetch_timezone() {
  python3 <<'PY'
import json
import urllib.error
import urllib.request

URLS = (
    "http://ip-api.com/json/?fields=status,message,timezone,query",
    "https://ipapi.co/json/",
)

for url in URLS:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "curl/8.5.0", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            data = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError):
        continue
    if not isinstance(data, dict):
        continue
    if data.get("status") == "fail":
        continue
    tz = str(data.get("timezone") or "").strip()
    if "/" in tz:
        print(tz)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

sync_timezone() {
  : > "$LOG"
  if [ ! -d "$TZDIR" ]; then
    log "tzdata zoneinfo directory missing: $TZDIR"
    return 1
  fi

  attempts="${1:-18}"
  i=1
  while [ "$i" -le "$attempts" ]; do
    tz="$(fetch_timezone 2>>"$LOG" || true)"
    if valid_tz "$tz"; then
      cp "$TZDIR/$tz" /etc/localtime
      echo "$tz" > /etc/timezone
      log "timezone set to $tz from current egress IP"
      date >> "$LOG" 2>&1 || true
      return 0
    fi
    [ -n "$tz" ] && log "rejected timezone value: $tz"
    sleep 5
    i=$((i + 1))
  done

  log "could not determine a valid IP timezone after $attempts attempts"
  return 1
}

case "${1:-sync}" in
  sync) sync_timezone "${2:-18}" ;;
  once) sync_timezone 1 ;;
  *) echo "usage: $0 {sync|once} [attempts]" >&2; exit 2 ;;
esac
"""

CLIENT_IP_TIMEZONE_INIT_ALPINE = """#!/sbin/openrc-run
description="Set client timezone from current egress IP"

depend() {
    need net
    after lab-net-up networking
}

start() {
    ebegin "Syncing timezone to egress IP"
    /usr/local/sbin/overdrive-ip-timezone sync 18
    eend $?
}
"""

CLIENT_IDENTITY_COMMAND = (
    "mkdir -p /usr/local/sbin /root && "
    f"echo '{CLIENT_GUEST_HOSTNAME}' > /etc/hostname"
)

INSTALL_DETECTION_LIBRARIES_COMMAND = "cd /root && python3 /root/install.py --non-interactive"

REMOVE_CLIENT_INSTALL_PY_COMMAND = (
    "find /root /tmp /var/tmp -maxdepth 4 -name 'install.py' -type f -delete"
)

CLEAN_CLIENT_PRIME_HELPERS_COMMAND = (
    "rm -f "
    "/root/install.py /root/install-client-packages.sh /root/harden-client.sh "
    "/tmp/install.py /tmp/install-client-packages.sh /tmp/harden-client.sh "
    "/var/tmp/install.py /var/tmp/install-client-packages.sh /var/tmp/harden-client.sh; "
    f"{REMOVE_CLIENT_INSTALL_PY_COMMAND}"
)

REMOTE_BOOT_SERVICE_CLEANUP_COMMAND = (
    "for svc in sshd ssh dropbear tiny-cloud-boot tiny-cloud-early tiny-cloud-main "
    "tiny-cloud-final cloud-init cloud-final; do "
    "rm -f \"/etc/init.d/$svc\" \"/etc/conf.d/$svc\" 2>/dev/null || true; "
    "for level in default boot sysinit shutdown nonetwork; do "
    "rc-update del \"$svc\" \"$level\" >/dev/null 2>&1 || true; "
    "rm -f \"/etc/runlevels/$level/$svc\" 2>/dev/null || true; "
    "done; "
    "done && "
    "rm -f /etc/tiny-cloud.conf 2>/dev/null || true"
)

CONFIGURE_CLIENT_SERVICES_AND_BOOT_COMMAND = (
    "mv /usr/local/sbin/lab_net_troubleshoot.sh /usr/local/sbin/lab-net-troubleshoot && "
    "mv /etc/init.d/lab-net-up.init /etc/init.d/lab-net-up && "
    "mv /etc/init.d/client-firewall.init /etc/init.d/client-firewall && "
    "mv /etc/init.d/overdrive-ip-timezone.init /etc/init.d/overdrive-ip-timezone && "
    "chmod 0755 /usr/local/sbin/lab-net-troubleshoot && "
    "chmod 0755 /usr/local/sbin/lab-net-up && "
    "chmod 0755 /usr/local/sbin/client-firewall && "
    "chmod 0755 /usr/local/sbin/overdrive-ip-timezone && "
    "chmod 0755 /etc/init.d/lab-net-up && "
    "chmod 0755 /etc/init.d/client-firewall && "
    "chmod 0755 /etc/init.d/overdrive-ip-timezone && "
    "find /root/local_host -type f -name '*.py' -exec chmod 0755 {} \\; && "
    f"{REMOTE_BOOT_SERVICE_CLEANUP_COMMAND} && "
    "rc-update add lab-net-up default && "
    "rc-update add overdrive-ip-timezone default && "
    "grep -q '^ttyS0' /etc/inittab || echo 'ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100' >> /etc/inittab && "
    "grep -qx 'ttyS0' /etc/securetty 2>/dev/null || echo ttyS0 >> /etc/securetty || true && "
    # Unattended boot: stock nocloud uses DEFAULT menu.c32 + TIMEOUT, but VBox
    # serial noise cancels TIMEOUT so the menu waits forever for Enter.
    # Boot the MENU DEFAULT / first LABEL directly + TOTALTIMEOUT.
    "for f in /boot/extlinux.conf /boot/syslinux/syslinux.cfg /boot/syslinux.cfg "
    "/media/*/boot/syslinux/syslinux.cfg; do "
    "[ -f \"$f\" ] || continue; "
    "DEF=$(awk 'BEGIN{l=\"\"} "
    "tolower($1)==\"label\"{l=$2; next} "
    "tolower($1)==\"menu\" && tolower($2)==\"default\"{print l; exit}' \"$f\"); "
    "[ -n \"$DEF\" ] || DEF=$(awk 'tolower($1)==\"label\"{print $2; exit}' \"$f\"); "
    "tmp=$(mktemp); "
    "awk 'BEGIN{ignore=0} "
    "tolower($1)==\"serial\"{next} "
    "tolower($1)==\"timeout\"{next} "
    "tolower($1)==\"totaltimeout\"{next} "
    "tolower($1)==\"prompt\"{next} "
    "tolower($1)==\"default\"{next} "
    "tolower($1)==\"noescape\"{next} "
    "tolower($1)==\"ui\"{next} "
    "tolower($1)==\"menu\" && (tolower($2)==\"title\"||tolower($2)==\"hidden\"||tolower($2)==\"autoboot\"||tolower($2)==\"separator\"){next} "
    "{print}' \"$f\" > \"$tmp\"; "
    "{ "
    "echo 'SERIAL 0 115200'; "
    "echo 'PROMPT 0'; "
    "echo 'NOESCAPE 1'; "
    "echo 'TIMEOUT 5'; "
    "echo 'TOTALTIMEOUT 20'; "
    "[ -n \"$DEF\" ] && echo \"DEFAULT $DEF\"; "
    "echo; "
    "cat \"$tmp\"; "
    "} > \"$f.new\"; "
    "mv \"$f.new\" \"$f\"; rm -f \"$tmp\"; "
    "grep -q 'console=ttyS0' \"$f\" || "
    "sed -i -E 's/^([[:space:]]*(APPEND|append)[[:space:]].*)$/\\1 console=ttyS0,115200/' \"$f\"; "
    "echo \"[overdrive] unattended bootloader: $f default=${DEF:-none}\"; "
    "done"
)

ASSERT_NO_REMOTE_BOOT_HOOKS_COMMAND = (
    "! find /etc/init.d /etc/runlevels /etc/conf.d "
    "\\( -name 'sshd' -o -name 'ssh' -o -name 'dropbear' "
    "-o -name 'tiny-cloud-*' -o -name 'cloud-init' -o -name 'cloud-final' \\) "
    "-print -quit | grep -q . && "
    "[ ! -e /etc/ssh ] && "
    "[ ! -e /etc/tiny-cloud.conf ]"
)
