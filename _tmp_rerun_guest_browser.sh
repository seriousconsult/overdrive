#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/code/overdrive
# Free/rebind UART from Windows side first if available.
if command -v VBoxManage.exe >/dev/null 2>&1; then
  VBoxManage.exe controlvm Test_Client changeuartmode1 disconnected || true
  sleep 1
  VBoxManage.exe controlvm Test_Client changeuartmode1 tcpserver 2325 || true
  sleep 1
fi
exec virtual_env/bin/python run/run_VMs_then_client_browser.py \
  --skip-vms \
  --deny-external \
  --browser-timeout 500 \
  --client-ready-timeout 90
