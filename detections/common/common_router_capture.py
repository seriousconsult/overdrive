"""Helpers shared by router packet-capture probes."""

from __future__ import annotations

import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

from detections.common.common_local import get_repo_root
from detections.common.common_utils import reexec_with_repo_venv, repo_venv_python


def print_sniff_permission_help() -> None:
    """Print help for packet capture permissions."""
    script = Path(sys.argv[0]).resolve()
    repo = Path(get_repo_root())
    vpy = repo_venv_python(repo) or (repo / "virtual_env" / "bin" / "python")
    print("[!] Packet capture needs raw sockets (Linux: root or cap_net_raw+cap_net_admin on the venv Python).")
    print("    From repo root, for example:")
    print(f"        sudo -n {vpy} {script}")
    print("    Or grant capabilities once (then you can run without sudo):")
    print(f"        sudo setcap cap_net_raw,cap_net_admin+eip {vpy}")
    print("    See README: Passwordless sudo / capture scripts.")


def background_probe_loop(stop: threading.Event, urls: tuple[str, ...], pause_s: float) -> None:
    """Background HTTP probe loop for packet capture."""
    n = 0
    while not stop.is_set():
        url = urls[n % len(urls)]
        n += 1
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "overdrive-router-probe/1.0", "Connection": "close"},
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                resp.read(8192)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            pass
        if stop.wait(pause_s):
            break
