"""Guest shell/systemd assets and virt-customize command strings."""

from __future__ import annotations

from VM.kali_client.client_config import CLIENT_GUEST_HOSTNAME
from VM.guest_launch_identity import LAUNCH_IDENTITY_SCRIPT, LAUNCH_IDENTITY_SERVICE_SYSTEMD
from VM.vm_config import OPENWRT_LAN_DNS

__all__ = [
    "ASSERT_NO_REMOTE_BOOT_HOOKS_COMMAND",
    "CLEAN_CLIENT_PRIME_HELPERS_COMMAND",
    "CLIENT_IDENTITY_COMMAND",
    "CLIENT_IP_TIMEZONE_SCRIPT",
    "CLIENT_IP_TIMEZONE_SERVICE",
    "CONFIGURE_CLIENT_SERVICES_AND_BOOT_COMMAND",
    "INSTALL_DETECTION_LIBRARIES_COMMAND",
    "LAUNCH_IDENTITY_SCRIPT",
    "LAUNCH_IDENTITY_SERVICE",
    "LAB_NET_TROUBLESHOOT_SCRIPT",
    "LAB_NET_UP_SCRIPT",
    "LAB_NET_UP_SERVICE",
    "REMOTE_BOOT_SERVICE_CLEANUP_COMMAND",
    "REMOVE_CLIENT_INSTALL_PY_COMMAND",
]

LAB_NET_UP_SCRIPT = f"""#!/bin/bash
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
  # Neutral DHCP identity: generic hostname, no vendor class (no kali/overdrive).
  if dhclient -1 -v -pf "/run/dhclient-$IFACE.pid" -lf "/var/lib/dhcp/dhclient-$IFACE.leases" \\
      -H {CLIENT_GUEST_HOSTNAME} "$IFACE"; then
    ok=1
  fi
done
ip -4 route show default 2>/dev/null | grep -q . && exit 0
[ "$ok" -eq 1 ]
"""

LAB_NET_UP_SERVICE = """[Unit]
Description=Lab LAN: link up + DHCP
After=local-fs.target client-firewall.service
Before=network-online.target overdrive-ip-timezone.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/lab-net-up

[Install]
WantedBy=multi-user.target
"""

LAB_NET_TROUBLESHOOT_SCRIPT = f"""#!/bin/bash
# Installed by create_VM_client_kali.py
set -u
echo "================================================================"
echo " Lab network troubleshoot (test clientk on test-lan)"
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
  echo "--- link up + dhclient $IFACE ---"
  if [ "$(id -u)" -eq 0 ]; then
    ip link set "$IFACE" up 2>&1 || true
    dhclient -1 -v -pf "/run/dhclient-$IFACE.pid" -lf "/var/lib/dhcp/dhclient-$IFACE.leases" \\
      -H {CLIENT_GUEST_HOSTNAME} "$IFACE" 2>&1 || true
  else
    sudo ip link set "$IFACE" up 2>&1 || true
    sudo dhclient -1 -v -pf "/run/dhclient-$IFACE.pid" -lf "/var/lib/dhcp/dhclient-$IFACE.leases" \\
      -H {CLIENT_GUEST_HOSTNAME} "$IFACE" 2>&1 || true
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

CLIENT_IP_TIMEZONE_SCRIPT = r"""#!/bin/bash
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
      ln -sf "$TZDIR/$tz" /etc/localtime
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

CLIENT_IP_TIMEZONE_SERVICE = """[Unit]
Description=Set client timezone from current egress IP
After=lab-net-up.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/overdrive-ip-timezone sync 18

[Install]
WantedBy=multi-user.target
"""

LAUNCH_IDENTITY_SERVICE = LAUNCH_IDENTITY_SERVICE_SYSTEMD

CLIENT_IDENTITY_COMMAND = (
    "mkdir -p /usr/local/sbin /root && "
    f"echo '{CLIENT_GUEST_HOSTNAME}' > /etc/hostname && "
    f"hostnamectl set-hostname {CLIENT_GUEST_HOSTNAME} 2>/dev/null || true"
)

INSTALL_DETECTION_LIBRARIES_COMMAND = (
    "timeout 900 bash -lc "
    "'cd /root && env PYTHONUNBUFFERED=1 PIP_DEFAULT_TIMEOUT=20 PIP_RETRIES=2 "
    "python3 /root/install.py --non-interactive'"
)

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
    "for svc in ssh sshd ssh.service sshd.service dropbear "
    "cloud-init cloud-init-local cloud-config cloud-final "
    "NetworkManager NetworkManager-wait-online; do "
    "systemctl stop \"$svc\" >/dev/null 2>&1 || true; "
    "systemctl disable \"$svc\" >/dev/null 2>&1 || true; "
    "systemctl mask \"$svc\" >/dev/null 2>&1 || true; "
    "done; "
    "touch /etc/cloud/cloud-init.disabled 2>/dev/null || true; "
    "rm -rf /etc/systemd/system/multi-user.target.wants/ssh.service "
    "/etc/systemd/system/multi-user.target.wants/sshd.service "
    "/etc/systemd/system/multi-user.target.wants/NetworkManager.service "
    "/etc/systemd/system/multi-user.target.wants/cloud-init*.service 2>/dev/null || true"
)

CONFIGURE_CLIENT_SERVICES_AND_BOOT_COMMAND = (
    "mv /usr/local/sbin/lab_net_troubleshoot.sh /usr/local/sbin/lab-net-troubleshoot && "
    "mv /etc/systemd/system/lab-net-up.service.tmp /etc/systemd/system/lab-net-up.service && "
    "mv /etc/systemd/system/client-firewall.service.tmp /etc/systemd/system/client-firewall.service && "
    "mv /etc/systemd/system/overdrive-ip-timezone.service.tmp /etc/systemd/system/overdrive-ip-timezone.service && "
    "mv /etc/systemd/system/overdrive-launch-identity.service.tmp /etc/systemd/system/overdrive-launch-identity.service && "
    "chmod 0755 /usr/local/sbin/lab-net-troubleshoot && "
    "chmod 0755 /usr/local/sbin/lab-net-up && "
    "chmod 0755 /usr/local/sbin/client-firewall && "
    "chmod 0755 /usr/local/sbin/overdrive-ip-timezone && "
    "chmod 0755 /usr/local/sbin/overdrive-launch-identity && "
    "find /root/local_host -type f -name '*.py' -exec chmod 0755 {} \\; && "
    f"{REMOTE_BOOT_SERVICE_CLEANUP_COMMAND} && "
    "systemctl daemon-reload && "
    "systemctl enable overdrive-launch-identity.service client-firewall.service lab-net-up.service overdrive-ip-timezone.service && "
    "systemctl enable serial-getty@ttyS0.service 2>/dev/null || "
    "ln -sf /lib/systemd/system/serial-getty@.service /etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service 2>/dev/null || true && "
    "if [ -f /etc/default/grub ]; then "
    "grep -q 'console=ttyS0' /etc/default/grub || "
    "sed -i -E 's/^(GRUB_CMDLINE_LINUX=\"[^\"]*)(\".*)$/\\1 console=ttyS0,115200n8\\2/' /etc/default/grub || "
    "sed -i -E 's/^(GRUB_CMDLINE_LINUX=)(\"[^\"]*\")$/\\1\"console=ttyS0,115200n8 \\2\"/' /etc/default/grub || true; "
    "grep -q '^GRUB_TERMINAL=' /etc/default/grub || echo 'GRUB_TERMINAL=\"serial console\"' >> /etc/default/grub; "
    "grep -q '^GRUB_SERIAL_COMMAND=' /etc/default/grub || "
    "echo 'GRUB_SERIAL_COMMAND=\"serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1\"' >> /etc/default/grub; "
    "update-grub 2>/dev/null || true; "
    "fi"
)

ASSERT_NO_REMOTE_BOOT_HOOKS_COMMAND = (
    "! systemctl list-unit-files 'ssh*.service' 'dropbear*.service' 'cloud-init*.service' "
    "2>/dev/null | awk '{print $1, $2}' "
    "| grep -E '^(ssh|sshd|dropbear|cloud-init|cloud-config|cloud-final)\\.service' "
    "| awk '$2==\"enabled\"' | grep -q . && "
    "[ ! -x /usr/sbin/sshd ] && "
    "[ ! -x /usr/sbin/dropbear ] && "
    "[ ! -e /etc/ssh ] && "
    "[ -f /etc/cloud/cloud-init.disabled ]"
)
