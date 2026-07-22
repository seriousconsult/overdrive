#!/usr/bin/env python3

"""Create an OpenWrt router VM in VirtualBox (WSL or Linux).

**NIC order vs stock OpenWrt:** The x86 image defaults to **LAN** on ``eth0`` (``br-lan``) and **WAN**
on ``eth1``. VirtualBox presents adapters in order as ``eth0``, ``eth1``. So **NIC1** is the **LAN**
leg (internal network ``openwrt-lan``) and **NIC2** is **WAN** (bridged or NAT). Client VMs use
``--nic1 intnet`` on the same intnet name.

**DNS:** After first boot (once WAN is up), the router installs **stubby**, forwards LAN DNS
through **dnsmasq → stubby → Mullvad DoT** (``dns.mullvad.net`` / ``base.dns.mullvad.net``), and
DHCP advertises OpenWrt ``192.168.1.1`` to clients.

**Serial console:** COM1 / ``ttyS0`` at 115200 baud (stock OpenWrt already uses
``console=ttyS0``). On Windows VirtualBox this is exposed as TCP port **2324** (client uses
**2323**). Attach with ``./create_VM_OpenWrt_router.py --serial-only``.

At startup, any **existing VirtualBox VM with the same name** and the matching folder under
``~/VirtualBox VMs/<VM_NAME>/`` are **removed** (power off, ``unregistervm --delete``, then delete
leftover directory) so the script always builds the same thing from a clean slate.
"""

import argparse
import gzip
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


# Ensure the repo package path is importable when running this script from VM/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from detections.common.common_vm import (
    ROUTER_SERIAL_PTY_LINK_PATH,
    ROUTER_SERIAL_TCP_PORT,
    ROUTER_SERIAL_UNIX_SOCKET_PATH,
    SERIAL_BAUD,
    SERIAL_TCP_HOST,
    find_vboxmanage,
    get_active_bridged_interface,
    get_linux_distro_id,
    get_system_paths,
    get_vboxmanage_install_hint,
    get_vm_state,
    OPENWRT_IMAGE_NAME,
    OPENWRT_LAN_INTNET_NAME,
    OPENWRT_ROUTER_VM_NAME,
    OPENWRT_URL,
    OPENWRT_VDI_NAME,
    remove_existing_vm,
    resolve_vbox_settings_path,
    run_vboxmanage,
    serial_endpoint_for_vbox,
    serial_tcp_host_candidates,
    spawn_serial_console_window,
    vboxmanage_targets_windows,
    vm_is_registered,
    wsl_to_windows_path,
)
from VM.vm_config import (
    MULLVAD_DOT_PORT,
    MULLVAD_DOT_RESOLVERS,
    OPENWRT_LAN_DNS,
    OPENWRT_STUBBY_LISTEN,
)

VM_NAME = OPENWRT_ROUTER_VM_NAME
# Downstream VMs: ``VBoxManage modifyvm <name> --nic1 intnet --intnet1 openwrt-lan``
LAN_INTNET_NAME = OPENWRT_LAN_INTNET_NAME
IMAGE_NAME = OPENWRT_IMAGE_NAME
VDI_NAME = OPENWRT_VDI_NAME

# Written into the OpenWrt image (uci-defaults + init.d) and also printed for manual apply.
_MULLVAD_RESOLVER_UCI = "\n".join(
    f"uci add stubby resolver\n"
    f"uci set stubby.@resolver[-1].address='{ip}'\n"
    f"uci set stubby.@resolver[-1].tls_auth_name='{name}'\n"
    f"uci set stubby.@resolver[-1].tls_port='{MULLVAD_DOT_PORT}'"
    for ip, name in MULLVAD_DOT_RESOLVERS
)

APPLY_MULLVAD_DOT_SH = f"""#!/bin/sh
# Overdrive lab: Mullvad DNS-over-TLS via stubby; LAN clients use OpenWrt as DNS.
# Safe to re-run. Requires WAN (NAT/bridged) so apk/opkg can fetch stubby.
set -e
DONE=/etc/overdrive-mullvad-dot.done

echo "[overdrive] Installing stubby for Mullvad DoT..."
if command -v apk >/dev/null 2>&1; then
  apk update
  apk add stubby ca-bundle
elif command -v opkg >/dev/null 2>&1; then
  opkg update
  opkg install stubby ca-bundle
else
  echo "[overdrive] ERROR: neither apk nor opkg found" >&2
  exit 1
fi

echo "[overdrive] Configuring stubby → Mullvad DoT..."
while uci -q delete stubby.@resolver[0]; do :; done
{_MULLVAD_RESOLVER_UCI}
uci set stubby.global.manual='0'
uci set stubby.global.trigger='wan'
uci set stubby.global.tls_authentication='1'
uci set stubby.global.round_robin_upstreams='1'
uci -q delete stubby.global.listen_address
uci add_list stubby.global.listen_address='127.0.0.1@5453'
uci add_list stubby.global.listen_address='0::1@5453'
uci commit stubby

echo "[overdrive] Pointing dnsmasq at stubby; advertising LAN DNS {OPENWRT_LAN_DNS}..."
uci -q delete dhcp.@dnsmasq[0].server
uci add_list dhcp.@dnsmasq[0].server='{OPENWRT_STUBBY_LISTEN}'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci set dhcp.@dnsmasq[0].localuse='1'
# DHCP option 6: clients must use OpenWrt, not upstream Mullvad IPs directly
uci -q delete dhcp.lan.dhcp_option
uci add_list dhcp.lan.dhcp_option='6,{OPENWRT_LAN_DNS}'
uci commit dhcp

# Stop relying on VBox/WAN plaintext DNS once DoT is in place
uci -q delete network.wan.dns
uci set network.wan.peerdns='0'
uci commit network

/etc/init.d/stubby enable
/etc/init.d/stubby restart
/etc/init.d/dnsmasq restart

touch "$DONE"
echo "[overdrive] Done. Verify: nslookup google.com {OPENWRT_LAN_DNS}"
nslookup google.com {OPENWRT_LAN_DNS} || true
"""

OVERDRIVE_MULLVAD_INIT_D = """#!/bin/sh /etc/rc.common
# One-shot: after WAN is up, install stubby and switch DNS to Mullvad DoT.
START=99
STOP=10

boot() {
	start
}

start() {
	[ -f /etc/overdrive-mullvad-dot.done ] && return 0
	[ -x /root/apply_mullvad_dot.sh ] || return 1
	(
		# Wait for WAN connectivity (VBox NAT DNS / peerdns bootstrap).
		i=0
		while [ "$i" -lt 90 ]; do
			if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1 \\
				|| ping -c1 -W2 9.9.9.9 >/dev/null 2>&1; then
				break
			fi
			i=$((i + 1))
			sleep 2
		done
		/root/apply_mullvad_dot.sh >>/tmp/overdrive-mullvad-dot.log 2>&1 \\
			|| echo "[overdrive] Mullvad DoT setup failed; see /tmp/overdrive-mullvad-dot.log" >&2
	) &
}

stop() {
	return 0
}
"""

UCI_DEFAULTS_ENABLE_MULLVAD = """#!/bin/sh
# Enable one-shot Mullvad DoT setup on first boot.
[ -x /etc/init.d/overdrive-mullvad-dot ] && /etc/init.d/overdrive-mullvad-dot enable
exit 0
"""


def download_openwrt_image(url: str, dest_path: str) -> None:
    dest = Path(dest_path)
    if dest.exists():
        print(f"OpenWrt raw image already exists at {dest}")
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading OpenWrt image to {dest}...")
    with urllib.request.urlopen(url) as response:
        if response.status != 200:
            raise RuntimeError(f"Download failed with HTTP {response.status}")
        with gzip.GzipFile(fileobj=response) as gz:
            with open(dest, "wb") as out_file:
                shutil.copyfileobj(gz, out_file)
    print("Download complete.")


def write_mullvad_dot_helpers(dest_dir: Path) -> Path:
    """Write the apply script next to the raw image / VM folder for manual use."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    apply_path = dest_dir / "apply_mullvad_dot.sh"
    apply_path.write_text(APPLY_MULLVAD_DOT_SH, encoding="utf-8", newline="\n")
    try:
        apply_path.chmod(0o755)
    except OSError:
        pass
    return apply_path


def inject_mullvad_dot_into_openwrt_image(img_path: str) -> bool:
    """
    Best-effort: place apply script + init.d + uci-defaults into the OpenWrt rootfs.
    Uses guestfish when available. Returns True on success.
    """
    guestfish = shutil.which("guestfish")
    if not guestfish:
        print("[!] guestfish not found; skipping image inject of Mullvad DoT scripts.")
        return False

    with tempfile.TemporaryDirectory(prefix="overdrive_owrt_dns_") as tmp:
        tmp_path = Path(tmp)
        apply = tmp_path / "apply_mullvad_dot.sh"
        initd = tmp_path / "overdrive-mullvad-dot"
        uci_def = tmp_path / "99-overdrive-mullvad-dot"
        apply.write_text(APPLY_MULLVAD_DOT_SH, encoding="utf-8", newline="\n")
        initd.write_text(OVERDRIVE_MULLVAD_INIT_D, encoding="utf-8", newline="\n")
        uci_def.write_text(UCI_DEFAULTS_ENABLE_MULLVAD, encoding="utf-8", newline="\n")

        gf_script = f"""\
run
list-filesystems
# Prefer second ext partition (rootfs on combined images); fall back to first.
mount /dev/sda2 /
mkdir-p /root
mkdir-p /etc/init.d
mkdir-p /etc/uci-defaults
mkdir-p /etc/rc.d
upload {apply.as_posix()} /root/apply_mullvad_dot.sh
upload {initd.as_posix()} /etc/init.d/overdrive-mullvad-dot
upload {uci_def.as_posix()} /etc/uci-defaults/99-overdrive-mullvad-dot
chmod 0755 /root/apply_mullvad_dot.sh
chmod 0755 /etc/init.d/overdrive-mullvad-dot
chmod 0755 /etc/uci-defaults/99-overdrive-mullvad-dot
ln-sf ../init.d/overdrive-mullvad-dot /etc/rc.d/S99overdrive-mullvad-dot
sync
umount /
"""
        print(f"Injecting Mullvad DoT first-boot scripts into {img_path}...")
        result = subprocess.run(
            [guestfish, "--rw", "-a", img_path],
            input=gf_script,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            # Retry with sda1 in case partition layout differs
            gf_script_sda1 = gf_script.replace("mount /dev/sda2 /", "mount /dev/sda1 /")
            result = subprocess.run(
                [guestfish, "--rw", "-a", img_path],
                input=gf_script_sda1,
                capture_output=True,
                text=True,
            )
        if result.returncode != 0:
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            print(f"[!] guestfish inject failed:\n{detail}")
            return False
    print("[+] Mullvad DoT scripts injected into OpenWrt image.")
    return True


def mullvad_dot_console_instructions(apply_path: Path | None = None) -> str:
    resolvers = ", ".join(f"{ip} ({name})" for ip, name in MULLVAD_DOT_RESOLVERS)
    extra = ""
    if apply_path is not None:
        extra = (
            f"Host copy of the apply script: {apply_path}\n"
            "Paste or scp onto OpenWrt if first-boot auto-setup did not run:\n"
            "  python3 /root/apply_mullvad_dot.py\n"
            "Or paste the same script from the host file above.\n"
        )
    return (
        "\n--- DNS (Mullvad DoT) ---\n"
        f"Upstream: Mullvad DNS-over-TLS on port {MULLVAD_DOT_PORT}: {resolvers}\n"
        f"LAN clients: DHCP option 6 → {OPENWRT_LAN_DNS} (dnsmasq → stubby → Mullvad).\n"
        "On first boot after WAN is up, OpenWrt runs apply_mullvad_dot.py automatically\n"
        "if the image was injected; log: /tmp/overdrive-mullvad-dot.log\n"
        f"{extra}"
        "Manual apply on OpenWrt console (after WAN works):\n"
        "  python3 /root/apply_mullvad_dot.py\n"
        f"Verify on OpenWrt:  nslookup google.com {OPENWRT_LAN_DNS}\n"
        f"Verify on client:   dig @{OPENWRT_LAN_DNS} google.com +short\n"
        "  cat /etc/resolv.conf   # expect nameserver 192.168.1.1\n"
    )


def router_serial_endpoint(vboxmanage: str) -> str:
    """Host endpoint for OpenWrt COM1 (distinct from the LAN client port)."""
    return serial_endpoint_for_vbox(
        vboxmanage,
        tcp_port=ROUTER_SERIAL_TCP_PORT,
        unix_path=ROUTER_SERIAL_UNIX_SOCKET_PATH,
    )


def configure_router_serial(vboxmanage: str, endpoint: str) -> None:
    """Expose OpenWrt COM1 as TCP (Windows VBox) or Unix socket (native Linux VBox)."""
    if vboxmanage_targets_windows(vboxmanage):
        uart_mode = "tcpserver"
        print(
            f"Serial console: COM1 -> TCP {SERIAL_TCP_HOST}:{endpoint} "
            f"({SERIAL_BAUD} baud; OpenWrt ttyS0)."
        )
    else:
        uart_mode = "server"
        print(f"Serial console: COM1 -> host socket {endpoint} ({SERIAL_BAUD} baud).")

    run_vboxmanage(
        vboxmanage,
        [
            "modifyvm",
            VM_NAME,
            "--uart1",
            "0x3F8",
            "4",
            "--uartmode1",
            uart_mode,
            endpoint,
        ],
    )


def refresh_live_router_serial(vboxmanage: str, endpoint: str) -> None:
    """Refresh COM1 backend on an already-running router VM."""
    if vboxmanage_targets_windows(vboxmanage):
        uart_mode = "tcpserver"
        print(f"Refreshing live serial TCP backend for {VM_NAME}: {SERIAL_TCP_HOST}:{endpoint}")
    else:
        uart_mode = "server"
        print(f"Refreshing live serial socket backend for {VM_NAME}: {endpoint}")
    run_vboxmanage(vboxmanage, ["controlvm", VM_NAME, "changeuartmode1", "disconnected"])
    run_vboxmanage(vboxmanage, ["controlvm", VM_NAME, "changeuartmode1", uart_mode, endpoint])


def router_serial_instructions(vboxmanage: str, endpoint: str) -> str:
    """Host-specific attach instructions for the OpenWrt serial console."""
    if vboxmanage_targets_windows(vboxmanage):
        hosts = ", ".join(serial_tcp_host_candidates(SERIAL_TCP_HOST))
        return (
            "\n--- Serial console (OpenWrt ttyS0) ---\n"
            f"VirtualBox exposes COM1 as TCP port {endpoint} on the Windows host.\n"
            f"From WSL, connect to one of: {hosts}\n"
            f"  ./{Path(__file__).name} --serial-only\n"
            "Stock OpenWrt already uses console=ttyS0; press Enter for the ash login.\n"
            "Client serial stays on TCP 2323; router uses 2324 so both can run together.\n"
        )
    return (
        "\n--- Serial console (OpenWrt ttyS0) ---\n"
        f"VirtualBox exposes COM1 as: {endpoint}\n"
        f"  rm -f {ROUTER_SERIAL_PTY_LINK_PATH}\n"
        f"  socat -d -d UNIX-CONNECT:{endpoint} "
        f"PTY,link={ROUTER_SERIAL_PTY_LINK_PATH},raw,echo=0\n"
        f"  screen {ROUTER_SERIAL_PTY_LINK_PATH} {SERIAL_BAUD}\n"
        "Press Enter once if the console is blank (OpenWrt ash askfirst).\n"
    )


def connect_router_serial_console(
    vboxmanage: str,
    endpoint: str,
    *,
    force_interactive: bool = True,
) -> bool:
    """Attach this terminal to the OpenWrt serial console (reuse client TCP bridge)."""
    # Import lazily so --help / create paths stay light if client module is heavy.
    if SCRIPT_DIR not in sys.path:
        sys.path.insert(0, SCRIPT_DIR)
    import create_VM_client_browser_pipe as client_serial  # noqa: PLC0415

    if vboxmanage_targets_windows(vboxmanage):
        return client_serial.connect_tcp_serial_console(
            SERIAL_TCP_HOST,
            int(endpoint),
            force_interactive=force_interactive,
        )

    socat = shutil.which("socat")
    screen = shutil.which("screen")
    if not socat or not screen:
        raise RuntimeError(
            "Native Linux serial attach requires socat and screen:\n"
            "  sudo apt install -y socat screen"
        )
    print(router_serial_instructions(vboxmanage, endpoint))
    return True


def serial_only_attach(*, here: bool = False, force_interactive: bool = True) -> None:
    """Attach to an already-configured OpenWrt serial endpoint.

    By default opens a **new window** so the caller shell stays free.
    Pass ``here=True`` (``--serial-here``) to attach in this terminal.
    """
    if not here:
        spawned = spawn_serial_console_window(
            Path(__file__).resolve(),
            title="OpenWrt Router serial (2324)",
            extra_args=["--force-interactive-serial"] if force_interactive else [],
            cwd=Path(SCRIPT_DIR),
        )
        if spawned:
            return
        print("[!] Falling back to in-terminal serial attach.")

    paths = get_system_paths(VM_NAME)
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError(get_vboxmanage_install_hint())
    endpoint = router_serial_endpoint(vboxmanage)
    state = get_vm_state(vboxmanage, VM_NAME)
    if state != "running":
        raise RuntimeError(
            f"{VM_NAME} is not running (state={state!r}). Start it first, then --serial-only."
        )
    try:
        refresh_live_router_serial(vboxmanage, endpoint)
    except RuntimeError as exc:
        print(f"[!] Could not refresh live UART mode ({exc}); trying connect anyway.")
    print(router_serial_instructions(vboxmanage, endpoint))
    connect_router_serial_console(
        vboxmanage, endpoint, force_interactive=force_interactive
    )


def try_remove_vbox_storage_controller(vboxmanage: str, vm_name: str, ctl_name: str) -> None:
    """Remove a storage controller if it exists (fresh VMs may not have IDE — avoid noisy errors)."""
    r = subprocess.run(
        [vboxmanage, "storagectl", vm_name, "--name", ctl_name, "--remove"],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        return
    combined = ((r.stderr or "") + (r.stdout or "")).lower()
    if "could not find" in combined and "controller" in combined:
        return
    if "vbox_e_object_not_found" in combined:
        return
    msg = (r.stderr or r.stdout or "").strip() or f"exit {r.returncode}"
    raise RuntimeError(
        f"VBoxManage storagectl --remove {ctl_name!r} failed unexpectedly: {msg}"
    )


def try_remove_vbox_storage_controller_with_retry(
    vboxmanage: str,
    vm_name: str,
    ctl_name: str,
    *,
    retries: int = 12,
    delay_s: float = 1.0,
) -> None:
    """Remove a storage controller, retrying transient VirtualBox machine locks."""
    for attempt in range(retries + 1):
        try:
            try_remove_vbox_storage_controller(vboxmanage, vm_name, ctl_name)
            return
        except RuntimeError as exc:
            msg = str(exc).lower()
            locked = (
                "already locked for a session" in msg
                or "being unlocked" in msg
                or "vbox_e_invalid_object_state" in msg
                or "0x80bb0007" in msg
            )
            if not locked or attempt >= retries:
                raise
            if attempt == 0:
                print("VirtualBox still has a machine lock; waiting before storage cleanup...")
            time.sleep(delay_s)


def remove_existing_router_vm(
    vboxmanage: str,
    vm_base: str,
    *,
    medium_path_for_vbox: str,
) -> None:
    """Compatibility wrapper; use ``common_vm.remove_existing_vm`` for new code."""
    remove_existing_vm(
        vboxmanage,
        VM_NAME,
        vm_base,
        medium_path_for_vbox=medium_path_for_vbox,
    )
    return
    if vm_is_registered(vboxmanage, VM_NAME):
        state = get_vm_state(vboxmanage, VM_NAME)
        if state == "saved":
            print(f"Discarding saved state for {VM_NAME!r}…")
            subprocess.run(
                [vboxmanage, "discardstate", VM_NAME], capture_output=True, text=True
            )
            state = get_vm_state(vboxmanage, VM_NAME)
        if state in ("running", "paused", "stopping", "starting"):
            print(f"Powering off existing VM {VM_NAME!r} ({state})…")
            subprocess.run([vboxmanage, "controlvm", VM_NAME, "poweroff"], check=False)
            for _ in range(45):
                time.sleep(1)
                st = get_vm_state(vboxmanage, VM_NAME)
                if st in (None, "poweroff", "aborted"):
                    break
            else:
                print(
                    f"[!] VM {VM_NAME!r} did not reach poweroff in time; "
                    "unregister may fail — close the VM window or run ``VBoxManage controlvm … poweroff``."
                )
        # Extra beat so Manager / GUI releases the machine session after poweroff.
        time.sleep(3)

        print(f"Unregistering and deleting VirtualBox VM {VM_NAME!r} (all media)…")
        if not try_unregistervm_delete(vboxmanage, VM_NAME):
            raise RuntimeError(
                f"Could not unregister {VM_NAME!r} (VirtualBox still has it locked). "
                "Close any window showing that VM, exit stray VBoxManage sessions, then re-run."
            )

    # Stale registry entry (e.g. old run deleted files without unregister): clear before new VDI.
    vbox_closemedium_disk_delete_best_effort(vboxmanage, medium_path_for_vbox)

    if os.path.isdir(vm_base):
        print(f"Removing leftover VM directory {vm_base!r}…")
        shutil.rmtree(vm_base, ignore_errors=True)


def setup_openwrt_vm(
    start_type: str = "gui",
    *,
    wan_mode: str = "nat",
    connect_serial: bool = True,
) -> None:
    paths = get_system_paths(VM_NAME, IMAGE_NAME)
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError(get_vboxmanage_install_hint())

    distro_id = get_linux_distro_id()
    if distro_id == "fedora":
        print(
            "Detected Fedora host. Using native Linux VirtualBox paths; if startvm fails, "
            "check that the VirtualBox kernel modules are built for the running kernel."
        )

    img_path = paths["img_path"]  # raw OpenWrt image (tar/gzip handled by downloader elsewhere)
    vm_base = paths["vm_base"]
    vms_root = paths["vms_root"]
    vdi_path = os.path.join(vm_base, VDI_NAME)
    dst_path = wsl_to_windows_path(vdi_path) if paths["is_wsl"] else vdi_path

    print(f"Fresh rebuild: removing existing {VM_NAME!r} registration and disk first.")
    remove_existing_vm(
        vboxmanage,
        VM_NAME,
        vm_base,
        medium_path_for_vbox=dst_path,
    )

    os.makedirs(vms_root, exist_ok=True)
    os.makedirs(vm_base, exist_ok=True)

    # This script expects the raw OpenWrt image already being downloadable/available via OPENWRT_URL logic.
    # Keep your existing downloader/converter flow:
    download_openwrt_image(OPENWRT_URL, img_path)
    apply_helper = write_mullvad_dot_helpers(Path(vm_base))
    # Also keep a copy beside the script for easy access from the repo.
    write_mullvad_dot_helpers(Path(SCRIPT_DIR))
    old_sh_in_script_dir = Path(SCRIPT_DIR) / "apply_mullvad_dot.sh"
    if old_sh_in_script_dir.exists():
        try:
            old_sh_in_script_dir.unlink()
        except OSError:
            pass
    if not inject_mullvad_dot_into_openwrt_image(img_path):
        print(
            "[!] Image inject skipped/failed — after OpenWrt WAN is up, run on the router console:\n"
            "      python3 /root/apply_mullvad_dot.py\n"
            f"    (host copy: {apply_helper})"
        )

    src_path = wsl_to_windows_path(img_path) if paths["is_wsl"] else img_path
    vms_root_for_vbox = wsl_to_windows_path(vms_root) if paths["is_wsl"] else vms_root

    if not os.path.exists(vdi_path):
        print("Converting raw image to VDI...")
        run_vboxmanage(vboxmanage, ["convertfromraw", src_path, dst_path, "--format", "VDI"])
    else:
        print("VDI already exists; skipping conversion.")
        print(
            "[!] Existing VDI may predate Mullvad DoT inject. "
            "Delete the VDI (or re-run after removing it) so convertfromraw picks up the patched image, "
            "or run apply_mullvad_dot.py on the OpenWrt console."
        )

    # ``createvm --basefolder`` must be the *parent* ``VirtualBox VMs`` dir (Windows path for VBoxManage.exe).
    if not vm_is_registered(vboxmanage, VM_NAME):
        existing_vbox = resolve_vbox_settings_path(vm_base, VM_NAME)
        if existing_vbox:
            reg_path = (
                wsl_to_windows_path(existing_vbox)
                if paths["is_wsl"]
                else existing_vbox
            )
            print(f"Registering existing settings file: {existing_vbox}")
            run_vboxmanage(vboxmanage, ["registervm", reg_path])
        else:
            run_vboxmanage(
                vboxmanage,
                [
                    "createvm",
                    "--name",
                    VM_NAME,
                    "--ostype",
                    "Linux_64",
                    "--basefolder",
                    vms_root_for_vbox,
                    "--register",
                ],
            )

    # Force BIOS firmware (command line uses modifyvm, not createvm).
    run_vboxmanage(vboxmanage, ["modifyvm", VM_NAME, "--firmware", "bios"])

    # NIC1 = LAN: matches OpenWrt default br-lan on eth0. NIC2 = WAN: matches wan on eth1.
    lan_nic_args = [
        "--nic1",
        "intnet",
        "--intnet1",
        LAN_INTNET_NAME,
        "--nicpromisc1",
        "allow-vms",
    ]

    bridge_interface = get_active_bridged_interface(vboxmanage) if wan_mode == "bridged" else None
    if wan_mode == "bridged" and bridge_interface:
        wan_nic_args = ["--nic2", "bridged", "--bridgeadapter2", bridge_interface]
        wan_note = f"bridged → {bridge_interface!r} (WAN / uplink)"
    else:
        # Host resolver is bootstrap only: so apk/opkg can resolve package mirrors
        # before stubby + Mullvad DoT is installed on first boot.
        wan_nic_args = [
            "--nic2",
            "nat",
            "--natdnshostresolver2",
            "on",
        ]
        if wan_mode == "bridged":
            wan_note = "NAT (WAN fallback — no bridged adapter; DNS host-resolver for stubby bootstrap)"
        else:
            wan_note = "NAT (WAN; DNS host-resolver for stubby/Mullvad DoT bootstrap)"

    # Ensure VirtualBox can create VM log files.
    logs_dir = Path(vm_base) / "Logs"
    os.makedirs(logs_dir, exist_ok=True)

    print(f"Configuring VM {VM_NAME}…")
    print(f"  LAN (NIC1): internal network {LAN_INTNET_NAME!r} — stock OpenWrt ``br-lan`` on ``eth0``.")
    print(f"  WAN (NIC2): {wan_note} — stock OpenWrt ``wan`` on ``eth1``.")
    print("  Client VMs: ``--nic1 intnet`` on the same intnet name (see create_VM_client_browser.py).")

    run_vboxmanage(
        vboxmanage,
        [
            "modifyvm",
            VM_NAME,
            "--memory",
            "512",
            "--cpus",
            "1",
            "--graphicscontroller",
            "vmsvga",
            *lan_nic_args,
            *wan_nic_args,
        ],
    )

    serial_endpoint = router_serial_endpoint(vboxmanage)
    configure_router_serial(vboxmanage, serial_endpoint)

    try_remove_vbox_storage_controller_with_retry(vboxmanage, VM_NAME, "IDE")

    run_vboxmanage(vboxmanage, ["storagectl", VM_NAME, "--name", "IDE", "--add", "ide", "--controller", "PIIX4"])
    run_vboxmanage(
        vboxmanage,
        [
            "storageattach",
            VM_NAME,
            "--storagectl",
            "IDE",
            "--port",
            "0",
            "--device",
            "0",
            "--type",
            "hdd",
            "--medium",
            dst_path,
        ],
    )

    if start_type == "none":
        print("VM configured. Skipping start because --start-type none was selected.")
        print(mullvad_dot_console_instructions(apply_helper))
        print(router_serial_instructions(vboxmanage, serial_endpoint))
        return

    print(f"Starting VM ({start_type})...")
    run_vboxmanage(vboxmanage, ["startvm", VM_NAME, "--type", start_type])

    # IMPORTANT: Do not call get_vm_state() here; it is not imported and the VM may
    # already be running by the time this function executes.
    print(f"[+] VM start command issued for {VM_NAME!r} with --type {start_type!r}.")
    print(mullvad_dot_console_instructions(apply_helper))
    print(router_serial_instructions(vboxmanage, serial_endpoint))

    if connect_serial:
        time.sleep(3)
        # New window by default — keep the create/start shell free.
        spawned = spawn_serial_console_window(
            Path(__file__).resolve(),
            title="OpenWrt Router serial (2324)",
            extra_args=["--force-interactive-serial"],
            cwd=Path(SCRIPT_DIR),
        )
        if not spawned:
            try:
                connect_router_serial_console(
                    vboxmanage,
                    serial_endpoint,
                    force_interactive=True,
                )
            except RuntimeError as exc:
                print(f"[!] Serial attach failed: {exc}")
                print(f"    Retry with: ./{Path(__file__).name} --serial-only")


def enable_serial_on_existing_router() -> None:
    """Enable COM1 serial on an already-registered router VM (no full recreate)."""
    paths = get_system_paths(VM_NAME)
    vboxmanage = find_vboxmanage(paths)
    if not vboxmanage:
        raise RuntimeError(get_vboxmanage_install_hint())
    if not vm_is_registered(vboxmanage, VM_NAME):
        raise RuntimeError(f"{VM_NAME} is not registered. Create it first.")

    endpoint = router_serial_endpoint(vboxmanage)
    state = get_vm_state(vboxmanage, VM_NAME)
    if state == "running":
        print(f"{VM_NAME} is running — enabling UART requires power off for --uart1 IRQ setup.")
        print("Powering off…")
        subprocess.run([vboxmanage, "controlvm", VM_NAME, "poweroff"], check=False)
        for _ in range(45):
            time.sleep(1)
            st = get_vm_state(vboxmanage, VM_NAME)
            if st in (None, "poweroff", "aborted"):
                break
        else:
            raise RuntimeError(f"{VM_NAME} did not power off in time.")

    configure_router_serial(vboxmanage, endpoint)
    print(router_serial_instructions(vboxmanage, endpoint))
    print(f"Start the VM (GUI), then: ./{Path(__file__).name} --serial-only")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create / refresh an OpenWrt router VM in VirtualBox.",
    )
    parser.add_argument(
        "--start-type",
        choices=("gui", "separate", "none"),
        default="gui",
        help=(
            "How to start the VM after creation.\n"
            "Headless removed because it crashes on this host.\n"
            "Default: gui."
        ),
    )
    parser.add_argument(
        "--wan-mode",
        choices=("nat", "bridged"),
        default="nat",
        help="Router WAN VirtualBox mode. Default: nat.",
    )
    parser.add_argument(
        "--serial-only",
        action="store_true",
        help="Open OpenWrt serial in a new window (TCP 2324); do not recreate. Host shell stays free.",
    )
    parser.add_argument(
        "--serial-here",
        action="store_true",
        help="Attach OpenWrt serial in THIS terminal (used by new-window spawners).",
    )
    parser.add_argument(
        "--force-interactive-serial",
        action="store_true",
        help="Open the serial bridge even if guest output was not detected yet.",
    )
    parser.add_argument(
        "--enable-serial",
        action="store_true",
        help="Enable COM1 serial on the existing router VM (power off if needed); do not recreate.",
    )
    parser.add_argument(
        "--no-connect-serial",
        action="store_true",
        help="After create/start, do not open a serial console window.",
    )
    args = parser.parse_args()
    if args.serial_here:
        serial_only_attach(here=True, force_interactive=True)
        return
    if args.serial_only:
        serial_only_attach(
            here=False,
            force_interactive=args.force_interactive_serial or True,
        )
        return
    if args.enable_serial:
        enable_serial_on_existing_router()
        return
    setup_openwrt_vm(
        start_type=args.start_type,
        wan_mode=args.wan_mode,
        connect_serial=not args.no_connect_serial,
    )


if __name__ == "__main__":
    main()
