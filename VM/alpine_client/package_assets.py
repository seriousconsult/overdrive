"""Package installation script assets for the Alpine client builder."""

from __future__ import annotations

__all__ = ["client_package_install_script"]


BASE_CLIENT_PACKAGE_INSTALL_SCRIPT = r"""#!/bin/sh
# Required package install for the Alpine lab client.
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

say "updating Alpine package indexes"
run_logged apk update || say "WARNING: apk update failed; continuing with any cached indexes"

FAILED=""
for pkg in bash bind-tools curl iproute2 iptables iputils net-tools nmap python3 py3-pip py3-requests py3-httpx py3-h2 socat tcpdump tzdata; do
  install_pkg "$pkg" || FAILED="$FAILED $pkg"
done

if command -v python3 >/dev/null 2>&1; then
  if ! python3 -c 'import requests' >/dev/null 2>&1; then
    install_pkg py3-requests || FAILED="$FAILED py3-requests"
  fi

  if ! python3 -c 'import scapy.all' >/dev/null 2>&1; then
    if install_pkg py3-scapy; then
      :
    elif command -v pip3 >/dev/null 2>&1; then
      run_logged pip3 install --break-system-packages scapy \
        || run_logged pip3 install scapy \
        || FAILED="$FAILED scapy"
    else
      say "WARNING: pip3 missing; Scapy install skipped"
      FAILED="$FAILED scapy"
    fi
  fi

  if ! python3 -c 'import httpx, h2' >/dev/null 2>&1; then
    if install_pkg py3-httpx && install_pkg py3-h2; then
      :
    elif command -v pip3 >/dev/null 2>&1; then
      run_logged pip3 install --break-system-packages 'httpx[http2]' \
        || run_logged pip3 install 'httpx[http2]' \
        || FAILED="$FAILED httpx"
    else
      say "WARNING: pip3 missing; httpx install skipped"
      FAILED="$FAILED httpx"
    fi
  fi

  if ! python3 -c 'import zeroconf' >/dev/null 2>&1; then
    if install_pkg py3-zeroconf; then
      :
    elif command -v pip3 >/dev/null 2>&1; then
      run_logged pip3 install --break-system-packages zeroconf \
        || run_logged pip3 install zeroconf \
        || FAILED="$FAILED zeroconf"
    else
      say "WARNING: pip3 missing; zeroconf install skipped"
      FAILED="$FAILED zeroconf"
    fi
  fi

  if ! python3 -c 'import requests' >/dev/null 2>&1; then
    say "ERROR: Python requests is not importable after package install"
    FAILED="$FAILED requests-import"
  fi
  if ! python3 -c 'import scapy.all' >/dev/null 2>&1; then
    say "ERROR: Scapy is not importable after package install"
    FAILED="$FAILED scapy-import"
  fi
  if ! python3 -c 'import zeroconf' >/dev/null 2>&1; then
    say "ERROR: zeroconf is not importable after package install"
    FAILED="$FAILED zeroconf-import"
  fi
  if ! python3 -c 'import httpx, h2' >/dev/null 2>&1; then
    say "ERROR: httpx with HTTP/2 support is not importable after package install"
    FAILED="$FAILED httpx-import"
  fi
else
  say "ERROR: python3 missing; Python local_host tools will not run"
  FAILED="$FAILED python3"
fi

if [ -n "$FAILED" ]; then
  say "ERROR: required package install failed:$FAILED"
  exit 1
fi
say "package install phase complete"
exit 0
"""


def client_package_install_script() -> str:
    return BASE_CLIENT_PACKAGE_INSTALL_SCRIPT
