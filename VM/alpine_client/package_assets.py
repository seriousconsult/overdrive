"""Bootstrap-only OS packages for the test client builder.

``iptables`` is installed here so ``client-firewall`` can harden the network
without ``install.py``. Other network tools (curl, iproute2, iputils,
wireguard-tools), diagnostics (nmap, dig), Chromium/Xvfb, and Python checker
libs are installed by ``install.py`` — not here. This script also ensures
``python3`` (to run that bootstrap) plus a tiny shell/tz base.
"""

from __future__ import annotations

__all__ = ["client_package_install_script"]


BASE_CLIENT_PACKAGE_INSTALL_SCRIPT = r"""#!/bin/sh
# Bootstrap packages — shell/tz, python3 for /root/install.py, and iptables
# so client-firewall hardening works without install.py.
# curl / iproute2 / iputils / wireguard-tools / nmap / dig / Chromium / Xvfb /
# venv libs are installed by install.py, not here.
#
# Package mirror/DNS failures should stop VM creation. Details are left in
# the guest image for inspection if virt-customize fails:
#   cat /root/overdrive-package-install.log
set -u

LOG=/root/overdrive-package-install.log
: > "$LOG"

say() {
  echo "[overdrive] $*"
  echo "[overdrive] $*" >> "$LOG"
}

run_logged() {
  echo "+ $*" >> "$LOG"
  "$@" >> "$LOG" 2>&1
}

install_pkg() {
  pkg="$1"
  if apk info -e "$pkg" >/dev/null 2>&1; then
    say "package already installed: $pkg"
    return 0
  fi
  if run_logged apk add --no-cache "$pkg"; then
    say "installed package: $pkg"
    return 0
  fi
  say "WARNING: failed to install package: $pkg"
  return 1
}

say "updating Alpine package indexes (bootstrap packages only)"
run_logged apk update || say "WARNING: apk update failed; continuing with any cached indexes"

FAILED=""
for pkg in bash python3 tzdata iptables; do
  install_pkg "$pkg" || FAILED="$FAILED $pkg"
done

if ! command -v python3 >/dev/null 2>&1; then
  say "ERROR: python3 missing after base package install"
  FAILED="$FAILED python3"
fi

if ! command -v iptables >/dev/null 2>&1 || ! command -v ip6tables >/dev/null 2>&1; then
  say "ERROR: iptables/ip6tables missing after base package install"
  FAILED="$FAILED iptables"
fi

if [ -n "$FAILED" ]; then
  say "ERROR: required base package install failed:$FAILED"
  exit 1
fi
say "base package install phase complete"
exit 0
"""


def client_package_install_script() -> str:
    return BASE_CLIENT_PACKAGE_INSTALL_SCRIPT
