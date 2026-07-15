#!/usr/bin/env python3
"""Open a separate serial console window for each lab VM; leave this shell free.

Expected layout after this succeeds (3 terminals):
  1. This host terminal (returns immediately)
  2. OpenWrt router serial (COM1 / TCP 2324) — new window
  3. LAN client serial (COM1 / TCP 2323) — new window
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from detections.common.common_vm import (
    OPENWRT_CLIENT_VM_NAME,
    OPENWRT_ROUTER_VM_NAME,
    find_vboxmanage,
    get_system_paths,
    get_vm_state,
    spawn_serial_console_window,
)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Open router + client serial consoles in separate windows.",
    )
    ap.add_argument(
        "--router-only",
        action="store_true",
        help="Only open the OpenWrt router serial window (TCP 2324).",
    )
    ap.add_argument(
        "--client-only",
        action="store_true",
        help="Only open the LAN client serial window (TCP 2323).",
    )
    ns = ap.parse_args()

    if ns.router_only and not ns.client_only:
        open_router, open_client = True, False
    elif ns.client_only and not ns.router_only:
        open_router, open_client = False, True
    else:
        open_router = open_client = True

    paths = get_system_paths(OPENWRT_ROUTER_VM_NAME)
    vbox = find_vboxmanage(paths)
    if not vbox:
        print("[!] VBoxManage not found.", file=sys.stderr)
        return 2

    opened: list[str] = []
    ok = True

    if open_router:
        st = get_vm_state(vbox, OPENWRT_ROUTER_VM_NAME)
        if st != "running":
            print(
                f"[!] {OPENWRT_ROUTER_VM_NAME} is not running (state={st!r}). "
                "Start it before opening serial."
            )
            ok = False
        else:
            spawned = spawn_serial_console_window(
                SCRIPT_DIR / "create_VM_OpenWrt_router.py",
                title="OpenWrt Router serial 2324",
                extra_args=["--force-interactive-serial"],
                cwd=SCRIPT_DIR,
            )
            if spawned:
                opened.append("router :2324")
            else:
                ok = False
            time.sleep(1.0)

    if open_client:
        st = get_vm_state(vbox, OPENWRT_CLIENT_VM_NAME)
        if st != "running":
            print(
                f"[!] {OPENWRT_CLIENT_VM_NAME} is not running (state={st!r}). "
                "Start it before opening serial."
            )
            ok = False
        else:
            spawned = spawn_serial_console_window(
                SCRIPT_DIR / "create_VM_client_browser_pipe.py",
                title="LAN Client serial 2323",
                extra_args=["--force-interactive-serial"],
                cwd=SCRIPT_DIR,
            )
            if spawned:
                opened.append("client :2323")
            else:
                ok = False

    print(f"[serial] Spawned: {', '.join(opened) if opened else '(none)'}")
    if ok and len(opened) == (1 if (ns.router_only ^ ns.client_only) else 2):
        print(
            "You should now have 3 windows total:\n"
            "  1) this host shell\n"
            "  2) OpenWrt Router serial (2324)\n"
            "  3) LAN Client serial (2323)\n"
            "Press Enter in each serial window if blank. Detach with Ctrl+]."
        )
        return 0
    if opened:
        print(
            "[!] Only some serial windows opened. "
            "Retry the missing one with --router-only or --client-only."
        )
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
