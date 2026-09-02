"""Guest scripts that regenerate pseudo-random host identity on every boot."""

from __future__ import annotations

__all__ = [
    "LAUNCH_IDENTITY_INIT_ALPINE",
    "LAUNCH_IDENTITY_SCRIPT",
    "LAUNCH_IDENTITY_SERVICE_SYSTEMD",
]

# Runs before DHCP/network so each boot gets a fresh machine-id / hostid.
LAUNCH_IDENTITY_SCRIPT = r"""#!/bin/sh
# Regenerate pseudo-random host identifiers before lab networking starts.
set -eu

LOG=/var/log/overdrive-launch-identity.log

log() {
  echo "[overdrive-launch-id] $*"
  echo "[overdrive-launch-id] $*" >> "$LOG"
}

write_machine_id() {
  mid=""
  if [ -r /proc/sys/kernel/random/uuid ]; then
    mid=$(tr -d '-' < /proc/sys/kernel/random/uuid | cut -c1-32)
  fi
  if [ -z "$mid" ] && command -v openssl >/dev/null 2>&1; then
    mid=$(openssl rand -hex 16)
  fi
  if [ -z "$mid" ]; then
    mid=$(date +%s%N 2>/dev/null | sha256sum 2>/dev/null | cut -c1-32)
  fi
  [ -n "$mid" ] || return 1
  printf '%s\n' "$mid" > /etc/machine-id
  chmod 0444 /etc/machine-id 2>/dev/null || true
  mkdir -p /var/lib/dbus
  rm -f /var/lib/dbus/machine-id 2>/dev/null || true
  if ln -sf /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null; then
    :
  else
    cp /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true
  fi
  if command -v hostid >/dev/null 2>&1; then
    hostid >/dev/null 2>&1 || true
  fi
  log "machine-id refreshed (${#mid} hex chars)"
}

clear_dhcp_client_state() {
  rm -f /var/lib/dhcp/dhclient*.leases /var/lib/dhcp/dhclient*.lease 2>/dev/null || true
  rm -f /var/lib/udhcpc/*.lease /var/lib/udhcpc/*.leases 2>/dev/null || true
  rm -f /var/lib/NetworkManager/dhclient*.lease 2>/dev/null || true
  log "cleared stale DHCP client lease files"
}

: > "$LOG"
write_machine_id
clear_dhcp_client_state
exit 0
"""

LAUNCH_IDENTITY_INIT_ALPINE = """#!/sbin/openrc-run
description="Regenerate pseudo-random host identity before lab networking"

depend() {
    need localmount
    before client-firewall lab-net-up net
}

start() {
    ebegin "Refreshing launch host identity"
    /usr/local/sbin/overdrive-launch-identity
    eend $?
}
"""

LAUNCH_IDENTITY_SERVICE_SYSTEMD = """[Unit]
Description=Regenerate pseudo-random host identity before lab networking
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target client-firewall.service lab-net-up.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/overdrive-launch-identity
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
