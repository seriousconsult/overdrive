#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/code/overdrive
exec virtual_env/bin/python _tmp_guest_browser_status.py
