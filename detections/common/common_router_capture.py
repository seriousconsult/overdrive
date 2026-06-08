"""Helpers shared by router packet-capture probes."""

from __future__ import annotations

import os
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path


def _repo_root_for_script(script: Path) -> Path:
    """Return the repository root for a script under ``detections/<category>/``."""
    for parent in script.parents:
        if (parent / "detections").is_dir() and (parent / "run").is_dir():
            return parent
    return script.parents[2]


def reexec_to_repo_venv_python() -> None:
    """Re-execute the active script with repo virtualenv Python if available."""
    script = Path(sys.argv[0]).resolve()
    repo = _repo_root_for_script(script)
    candidates = (
        repo / "virtual_env" / "bin" / "python",
        repo / "virtual_env" / "Scripts" / "python.exe",
    )
    vpy = next((candidate for candidate in candidates if candidate.is_file()), None)
    if vpy is None:
        return
    try:
        if Path(sys.executable).resolve() == vpy.resolve():
            return
    except OSError:
        return
    try:
        os.execv(str(vpy), [str(vpy), str(script), *sys.argv[1:]])
    except OSError:
        pass


def print_sniff_permission_help() -> None:
    """Print help for packet capture permissions."""
    script = Path(sys.argv[0]).resolve()
    repo = _repo_root_for_script(script)
    vpy = repo / "virtual_env" / "bin" / "python"
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
