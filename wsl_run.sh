#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/mnt/c/code/overdrive"
cd "$REPO_DIR"

# Activate the virtualenv
# (adjust if your venv layout differs)
source "$REPO_DIR/virtual_env/bin/activate"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <script.py> [args...]"
  exit 2
fi

SCRIPT="$1"
shift

# Prevent path traversal / only allow basenames
BASENAME="$(basename "$SCRIPT")"

# Whitelist allowed scripts (edit this list if needed)
case "$BASENAME" in
  container_VM_detect.py|virtual_env_setup.py)
    ;;
  *)
    echo "Refusing to run unapproved script: $BASENAME"
    echo "Allowed: container_VM_detect.py, virtual_env_setup.py"
    exit 3
    ;;
esac

# Run
python "$BASENAME" "$@"
