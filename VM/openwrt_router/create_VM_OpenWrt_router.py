#!/usr/bin/env python3

"""Create an OpenWrt router VM in VirtualBox (WSL or Linux).

**NIC order vs stock OpenWrt:** The x86 image defaults to **LAN** on ``eth0`` (``br-lan``) and **WAN**
on ``eth1``. VirtualBox presents adapters in order as ``eth0``, ``eth1``. So **NIC1** is the **LAN**
leg (internal network ``openwrt-lan``) and **NIC2** is **WAN** (bridged). Client VMs use
``--nic1 intnet`` on the same intnet name.

**DNS:** Before convert, the script downloads stubby ``.apk`` deps (OpenWrt 25.12 uses
**apk**, not opkg) and injects them with ``apply_mullvad_dot.sh`` into the image. After
start, serial runs that script once (no upload/retry loop) and **requires**
``whoami.akamai.net`` proves Mullvad (anycast ``194.242.2.x`` or PoP ``*.mullvad.net``).

**Serial console:** COM1 / ``ttyS0`` at 115200 baud (stock OpenWrt already uses
``console=ttyS0``). On Windows VirtualBox this is exposed as TCP port **2324** (client uses
**2325**). Attach with ``./create_VM_OpenWrt_router.py --serial-only``.

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


# Ensure the repo package path is importable when running this script directly.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = str(Path(SCRIPT_DIR).resolve().parents[1])
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from detections.common.common_vm import (
    ROUTER_SERIAL_PTY_LINK_PATH,
    ROUTER_SERIAL_TCP_PORT,
    ROUTER_SERIAL_UNIX_SOCKET_PATH,
    SERIAL_BAUD,
    SERIAL_TCP_HOST,
    ensure_kvm_accessible,
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
from VM.openwrt_router.openwrt_assets import (
    APPLY_MULLVAD_DOT_SH,
    OVERDRIVE_MULLVAD_INIT_D,
    UCI_DEFAULTS_ENABLE_MULLVAD,
)
from VM.openwrt_router.pipeline import (
    BuildStep,
    OpenWrtRouterBuildOptions,
    run_openwrt_router_pipeline,
)
from VM.vm_config import (
    G3100_MAC_OUI,
    MULLVAD_DOT_PORT,
    MULLVAD_DOT_RESOLVERS,
    OPENWRT_LAN_DNS,
    format_mac_colon,
    openwrt_root_password,
    random_g3100_mac_vbox,
)

try:
    from VM.alpine_client.create_VM_client_browser_pipe_alpine import setup_client_vm as setup_alpine_client_vm
except ImportError:
    setup_alpine_client_vm = None

VM_NAME = OPENWRT_ROUTER_VM_NAME
# Downstream VMs: ``VBoxManage modifyvm <name> --nic1 intnet --intnet1 openwrt-lan``
LAN_INTNET_NAME = OPENWRT_LAN_INTNET_NAME
IMAGE_NAME = OPENWRT_IMAGE_NAME
VDI_NAME = OPENWRT_VDI_NAME

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


# OpenWrt 25.12+ ships apk packages (.apk), not .ipk. Versions come from index.json.
_OPENWRT_APK_FEEDS = {
    "packages": "https://downloads.openwrt.org/releases/{release}/packages/x86_64/packages",
    "base": "https://downloads.openwrt.org/releases/{release}/packages/x86_64/base",
    "targets": "https://downloads.openwrt.org/releases/{release}/targets/x86/64/packages",
}

# Curated closure for stubby (DEPENDS: libyaml + getdns + ca-certs) and getdns/libunbound.
_STUBBY_APK_PACKAGES: tuple[tuple[str, str], ...] = (
    ("packages", "stubby"),
    ("packages", "getdns"),
    ("packages", "libyaml"),
    ("packages", "libunbound"),
    ("base", "ca-bundle"),
    ("base", "ca-certificates"),
    ("base", "libopenssl"),
    ("base", "libevent2"),
    ("base", "libmnl"),
)


def _openwrt_release_from_url(url: str = OPENWRT_URL) -> str:
    import re

    m = re.search(r"/releases/([^/]+)/", url)
    if not m:
        raise RuntimeError(f"Cannot parse OpenWrt release from URL: {url}")
    return m.group(1)


def fetch_openwrt_stubby_apks(*, cache_dir: Path | None = None) -> Path:
    """
    Download stubby + dependency .apk files for the OpenWrt release in OPENWRT_URL.
    Returns the directory containing the .apk files (cached on disk).

    OpenWrt 25.12 apk filenames are often ABI-suffixed (e.g. libopenssl → libopenssl3-….apk),
    so we resolve the real filename from each feed's directory listing.
    """
    import json
    import re

    release = _openwrt_release_from_url()
    dest = cache_dir or (Path(SCRIPT_DIR) / ".cache" / f"openwrt-{release}-stubby-apks")
    dest.mkdir(parents=True, exist_ok=True)

    def _list_apk_hrefs(feed_url: str) -> set[str]:
        html = urllib.request.urlopen(feed_url + "/", timeout=60).read().decode(
            "utf-8", "replace"
        )
        return set(re.findall(r'href="([^"]+\.apk)"', html))

    def _resolve_apk_filename(hrefs: set[str], name: str, version: str) -> str:
        exact = f"{name}-{version}.apk"
        if exact in hrefs:
            return exact
        # ABI forms: libopenssl3-VER.apk  /  libevent2-7-VER.apk
        abi1 = re.compile(rf"^{re.escape(name)}\d+-{re.escape(version)}\.apk$")
        abi2 = re.compile(rf"^{re.escape(name)}-\d+-{re.escape(version)}\.apk$")
        for h in sorted(hrefs):
            if abi1.match(h) or abi2.match(h):
                return h
        raise RuntimeError(
            f"No .apk file for {name}-{version} in feed listing "
            f"(tried exact and ABI-suffixed names)"
        )

    indexes: dict[str, dict[str, str]] = {}
    hrefs_by_feed: dict[str, set[str]] = {}
    for feed, tmpl in _OPENWRT_APK_FEEDS.items():
        feed_url = tmpl.format(release=release)
        idx_url = feed_url + "/index.json"
        print(f"[overdrive] Fetching package index {feed}...")
        with urllib.request.urlopen(idx_url, timeout=60) as resp:
            data = json.load(resp)
        indexes[feed] = {k: str(v) for k, v in data["packages"].items()}
        print(f"[overdrive] Listing {feed} package files...")
        hrefs_by_feed[feed] = _list_apk_hrefs(feed_url)

    # libevent2 often pulls core; include both so offline apk add is self-contained.
    packages = list(_STUBBY_APK_PACKAGES)
    if ("base", "libevent2-core") not in packages:
        packages.append(("base", "libevent2-core"))

    paths: list[Path] = []
    for feed, name in packages:
        ver = indexes.get(feed, {}).get(name)
        if not ver:
            raise RuntimeError(
                f"Package {name!r} not found in OpenWrt {release} feed {feed!r}"
            )
        filename = _resolve_apk_filename(hrefs_by_feed[feed], name, ver)
        local = dest / filename
        url = f"{_OPENWRT_APK_FEEDS[feed].format(release=release)}/{filename}"
        if local.is_file() and local.stat().st_size > 0:
            print(f"[overdrive]   cached {filename}")
        else:
            print(f"[overdrive]   downloading {filename}...")
            urllib.request.urlretrieve(url, local)
        paths.append(local)

    print(f"[+] Offline stubby APKs ready ({len(paths)} packages) in {dest}")
    return dest


def _libguestfs_env() -> dict[str, str]:
    """Environment for guestfish/virt-customize (WSL-friendly, same as Alpine priming)."""
    ensure_kvm_accessible()
    import glob
    import re
    import tarfile
    import urllib.request

    env = os.environ.copy()
    env.setdefault("LIBGUESTFS_BACKEND", "direct")

    # Prefer a fixed appliance — WSL supermin often exits 1 without this.
    def _find_appliance() -> str | None:
        candidates = [
            "/usr/lib64/guestfs/appliance",
            "/usr/lib/guestfs/appliance",
            "/usr/local/lib/guestfs/appliance",
        ]
        for c in candidates:
            d = Path(c)
            if (d / "README.fixed").is_file() and all(
                (d / x).is_file() for x in ("kernel", "initrd", "root")
            ):
                return str(d)
        for cr in (
            Path.home() / ".cache" / "libguestfs" / "appliance",
            Path.home() / ".cache" / "guestfs" / "appliance",
        ):
            if not cr.exists():
                continue
            for d in cr.glob("**/"):
                if not d.is_dir():
                    continue
                if (d / "README.fixed").is_file() and all(
                    (d / x).is_file() for x in ("kernel", "initrd", "root")
                ):
                    return str(d)
        return None

    appliance = _find_appliance()
    if appliance is None:
        try:
            cache_dir = Path.home() / ".cache" / "libguestfs" / "appliance"
            cache_dir.mkdir(parents=True, exist_ok=True)
            index_url = "https://download.libguestfs.org/binaries/appliance/"
            index_html = urllib.request.urlopen(index_url, timeout=60).read().decode(
                "utf-8", errors="replace"
            )
            versions = re.findall(r"(appliance-\d+(?:\.\d+)+)\.tar\.xz", index_html)
            if versions:

                def verkey(s: str) -> tuple[int, ...]:
                    return tuple(int(x) for x in s.replace("appliance-", "").split("."))

                latest = max(versions, key=verkey)
                tar_name = f"{latest}.tar.xz"
                tar_path = cache_dir / tar_name
                extract_root = cache_dir / latest
                if not any(
                    (p / "README.fixed").is_file() for p in [extract_root, *extract_root.glob("**/")]
                    if p.is_dir()
                ):
                    if not tar_path.exists():
                        print(f"[libguestfs] Downloading fixed appliance: {tar_name} ...")
                        urllib.request.urlretrieve(f"{index_url}{tar_name}", tar_path)
                    print(f"[libguestfs] Extracting fixed appliance into {extract_root} ...")
                    if extract_root.exists():
                        shutil.rmtree(extract_root)
                    extract_root.mkdir(parents=True, exist_ok=True)
                    with tarfile.open(tar_path, mode="r:xz") as tf:
                        tf.extractall(path=extract_root)
                for d in [extract_root, *extract_root.glob("**/")]:
                    if (
                        d.is_dir()
                        and (d / "README.fixed").is_file()
                        and all((d / x).is_file() for x in ("kernel", "initrd", "root"))
                    ):
                        appliance = str(d)
                        break
        except Exception as exc:
            print(f"[!] Could not download libguestfs fixed appliance: {exc}")

    if appliance:
        env["LIBGUESTFS_PATH"] = appliance
        print(f"[libguestfs] Using fixed appliance: LIBGUESTFS_PATH={appliance}")
    else:
        # Last resort: point supermin at a real host kernel (WSL).
        boot_kernels = sorted(glob.glob("/boot/vmlinuz*"))
        if boot_kernels:
            kernel = max(boot_kernels, key=lambda p: os.path.getmtime(p))
            m = re.sub(r"^/boot/vmlinuz-?", "", os.path.basename(kernel))
            env["SUPERMIN_KERNEL"] = kernel
            mod_dir = f"/lib/modules/{m}"
            if Path(mod_dir).is_dir():
                env["SUPERMIN_MODULES"] = mod_dir
            print(f"[libguestfs] Using SUPERMIN_KERNEL={kernel}")

    return env


def inject_mullvad_dot_into_openwrt_image(
    img_path: str,
    *,
    apk_dir: Path | None = None,
) -> bool:
    """
    Place apply script + init.d + uci-defaults (+ optional offline stubby APKs)
    into the OpenWrt rootfs. Tries guestfish, then virt-customize.
    """
    guestfish = shutil.which("guestfish")
    virt_customize = shutil.which("virt-customize")
    if not guestfish and not virt_customize:
        print("[!] guestfish/virt-customize not found; cannot inject Mullvad DoT scripts.")
        return False

    apk_files: list[Path] = []
    if apk_dir is not None:
        apk_files = sorted(Path(apk_dir).glob("*.apk"))
        if not apk_files:
            print(f"[!] No .apk files in {apk_dir}")
            return False

    with tempfile.TemporaryDirectory(prefix="overdrive_owrt_dns_") as tmp:
        tmp_path = Path(tmp)
        apply = tmp_path / "apply_mullvad_dot.sh"
        initd = tmp_path / "overdrive-mullvad-dot"
        uci_def = tmp_path / "99-overdrive-mullvad-dot"
        apply.write_text(APPLY_MULLVAD_DOT_SH, encoding="utf-8", newline="\n")
        initd.write_text(OVERDRIVE_MULLVAD_INIT_D, encoding="utf-8", newline="\n")
        uci_def.write_text(UCI_DEFAULTS_ENABLE_MULLVAD, encoding="utf-8", newline="\n")
        env = _libguestfs_env()

        apk_upload_lines = ""
        if apk_files:
            apk_upload_lines = "mkdir-p /root/overdrive-apks\n"
            for apk in apk_files:
                apk_upload_lines += (
                    f"upload {apk.as_posix()} /root/overdrive-apks/{apk.name}\n"
                )

        if guestfish:
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
{apk_upload_lines}chmod 0755 /root/apply_mullvad_dot.sh
chmod 0755 /etc/init.d/overdrive-mullvad-dot
chmod 0755 /etc/uci-defaults/99-overdrive-mullvad-dot
ln-sf ../init.d/overdrive-mullvad-dot /etc/rc.d/S99overdrive-mullvad-dot
# Prove files landed (guestfish download fails the run if missing).
download /root/apply_mullvad_dot.sh {tmp_path.as_posix()}/_verify_apply.sh
sync
umount /
"""
            print(
                f"Injecting Mullvad DoT scripts"
                f"{f' + {len(apk_files)} APKs' if apk_files else ''} "
                f"into {img_path} (guestfish)..."
            )
            result = subprocess.run(
                [guestfish, "--rw", "-a", img_path],
                input=gf_script,
                capture_output=True,
                text=True,
                env=env,
            )
            if result.returncode != 0:
                gf_script_sda1 = gf_script.replace("mount /dev/sda2 /", "mount /dev/sda1 /")
                result = subprocess.run(
                    [guestfish, "--rw", "-a", img_path],
                    input=gf_script_sda1,
                    capture_output=True,
                    text=True,
                    env=env,
                )
            if result.returncode == 0 and (tmp_path / "_verify_apply.sh").is_file():
                print("[+] Mullvad DoT scripts injected into OpenWrt image (guestfish).")
                return True
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            print(f"[!] guestfish inject failed:\n{detail}")

        if virt_customize:
            print(
                f"Injecting Mullvad DoT scripts"
                f"{f' + {len(apk_files)} APKs' if apk_files else ''} "
                f"into {img_path} (virt-customize)..."
            )
            cmd = [
                virt_customize,
                "-a",
                img_path,
                "--mkdir",
                "/root",
                "--mkdir",
                "/root/overdrive-apks",
                "--mkdir",
                "/etc/init.d",
                "--mkdir",
                "/etc/uci-defaults",
                "--mkdir",
                "/etc/rc.d",
                "--upload",
                f"{apply.as_posix()}:/root/apply_mullvad_dot.sh",
                "--upload",
                f"{initd.as_posix()}:/etc/init.d/overdrive-mullvad-dot",
                "--upload",
                f"{uci_def.as_posix()}:/etc/uci-defaults/99-overdrive-mullvad-dot",
            ]
            for apk in apk_files:
                cmd.extend(
                    ["--upload", f"{apk.as_posix()}:/root/overdrive-apks/{apk.name}"]
                )
            cmd.extend(
                [
                    "--chmod",
                    "0755:/root/apply_mullvad_dot.sh",
                    "--chmod",
                    "0755:/etc/init.d/overdrive-mullvad-dot",
                    "--chmod",
                    "0755:/etc/uci-defaults/99-overdrive-mullvad-dot",
                    "--link",
                    "/etc/init.d/overdrive-mullvad-dot:/etc/rc.d/S99overdrive-mullvad-dot",
                ]
            )
            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            if result.returncode == 0:
                print("[+] Mullvad DoT scripts injected into OpenWrt image (virt-customize).")
                return True
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            print(f"[!] virt-customize inject failed:\n{detail}")

    return False


def _router_serial_hosts() -> list[str]:
    """Prefer localhost first; WSL Windows-host IPs can hang before refusing."""
    from detections.common.common_vm import serial_tcp_host_candidates

    hosts = serial_tcp_host_candidates(SERIAL_TCP_HOST)
    if "127.0.0.1" in hosts:
        hosts = ["127.0.0.1", *[host for host in hosts if host != "127.0.0.1"]]
    return hosts


def _open_router_serial_socket(
    *,
    timeout_s: float = 60.0,
) -> "socket.socket":
    """Connect to the OpenWrt COM1 TCP serial endpoint."""
    import socket

    errors: dict[str, str] = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for host in _router_serial_hosts():
            try:
                sock = socket.create_connection((host, ROUTER_SERIAL_TCP_PORT), timeout=1.0)
                sock.settimeout(0.5)
                return sock
            except OSError as exc:
                errors[host] = str(exc)
        time.sleep(0.5)

    detail = "; ".join(f"{host}: {err}" for host, err in errors.items()) or "no attempts"
    raise RuntimeError(f"Could not open router serial TCP :{ROUTER_SERIAL_TCP_PORT}: {detail}")


def _serial_drain(sock, *, wait_s: float = 0.3) -> str:
    """Read whatever is already pending on the serial socket."""
    buf = bytearray()
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(8192)
            if chunk:
                buf.extend(chunk)
                deadline = time.monotonic() + wait_s
            else:
                break
        except OSError:
            time.sleep(0.05)
    return buf.decode("utf-8", errors="replace")


def _serial_exchange(sock, payload: str, *, wait_s: float = 2.0) -> str:
    """Send CRLF-terminated text and read available reply."""
    sock.sendall(payload.encode("utf-8", errors="replace"))
    return _serial_drain(sock, wait_s=wait_s)


def _close_serial_socket(sock) -> None:
    """Best-effort close for a VirtualBox TCP serial socket."""
    import socket

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


# OpenWrt ash + VBox serial wraps ~80 cols and corrupts long typed lines.
_SERIAL_MAX_CMD = 76


def _serial_line_has_marker(buf: str, marker: str) -> bool:
    """True if marker appears as its own output line (not inside local-echoed ``echo MARKER``)."""
    for line in buf.replace("\r", "\n").splitlines():
        if line.strip() == marker:
            return True
    return False


def _serial_run_marked(sock, command: str, *, marker: str, wait_s: float = 15.0) -> str:
    """Run a short command; wait until marker appears as its own line.

    Must not match the local echo of ``echo <marker>`` (substring match is wrong).
    """
    if len(command) > _SERIAL_MAX_CMD:
        raise ValueError(
            f"serial command too long ({len(command)}>{_SERIAL_MAX_CMD}): {command!r}"
        )
    if len(marker) > 12:
        raise ValueError(f"serial marker too long: {marker!r}")
    _serial_drain(sock, wait_s=0.2)
    # Send command and marker on SEPARATE lines so wrap cannot glue/corrupt them.
    sock.sendall(f"{command}\r".encode("utf-8", errors="replace"))
    time.sleep(0.15)
    sock.sendall(f"echo {marker}\r".encode("utf-8", errors="replace"))
    buf = ""
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        buf += _serial_drain(sock, wait_s=0.4)
        if _serial_line_has_marker(buf, marker):
            break
    return buf


def _serial_status_digit(sock, *, check_cmd: str, marker: str) -> str:
    """Run check_cmd that writes a single digit to /tmp/st, then cat it.

    Never trust echoed ``echo HAVE`` / ``echo OK`` on serial — local echo always
    contains those strings even when the guest command failed.
    """
    _serial_run_marked(sock, "rm -f /tmp/st", marker=f"{marker}0", wait_s=3.0)
    _serial_run_marked(sock, check_cmd, marker=f"{marker}1", wait_s=5.0)
    out = _serial_run_marked(sock, "cat /tmp/st", marker=f"{marker}2", wait_s=3.0)
    digit = "?"
    for line in out.replace("\r", "\n").splitlines():
        s = line.strip()
        if s.isdigit() and len(s) <= 3:
            digit = s
    return digit


def _guest_has_apply_script(sock) -> bool:
    """True if /root/apply_mullvad_dot.sh exists and contains Mullvad apply markers."""
    # grep exit code 0 => found. Write $? so we don't rely on echoed OK/HAVE.
    digit = _serial_status_digit(
        sock,
        check_cmd="grep -q verify_mullvad /root/apply_mullvad_dot.sh; echo $? >/tmp/st",
        marker="HV",
    )
    return digit == "0"


def _remove_guest_apply_script(sock, marker: str) -> None:
    _serial_run_marked(sock, "rm -f /root/apply_mullvad_dot.sh", marker=marker, wait_s=3.0)


def _serial_output_is_mullvad_whoami(sock, who_out: str, *, status_digit_func=None) -> bool:
    """True if whoami shows Mullvad anycast or a public IP via Mullvad-configured stubby."""
    import re

    if re.search(r"\b194\.242\.2\.\d+\b", who_out):
        m = re.search(r"\b194\.242\.2\.\d+\b", who_out)
        print(f"[overdrive] whoami anycast {m.group(0)} — Mullvad OK")
        return True

    candidates: list[str] = []
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", who_out):
        if ip.startswith(("127.", "10.", "192.168.", "0.")):
            continue
        if re.match(r"172\.(1[6-9]|2\d|3[0-1])\.", ip):
            continue
        # Common ISP / VBox host-resolver leftovers (not Mullvad).
        if ip.startswith(("71.", "96.")):
            print(f"[overdrive] whoami {ip} looks like ISP/VBox DNS — not Mullvad")
            return False
        if ip not in candidates:
            candidates.append(ip)

    if not candidates:
        return False

    # Confirm stubby is aimed at Mullvad; whoami then returns PoP unicast (e.g. 193.148.18.30),
    # not necessarily 194.242.2.x. PTR via stubby is often NXDOMAIN, so do not require it.
    if status_digit_func is None:
        digit = _serial_status_digit(
            sock,
            check_cmd="grep -q dns.mullvad.net /etc/stubby/stubby.yml; echo $? >/tmp/st",
            marker="CF",
        )
    else:
        digit = status_digit_func(
            check_cmd="grep -q dns.mullvad.net /etc/stubby/stubby.yml; echo $? >/tmp/st",
            marker="CF",
        )
    if digit != "0":
        print("[overdrive] stubby.yml missing dns.mullvad.net — not Mullvad")
        return False

    print(f"[overdrive] whoami {candidates[0]} via Mullvad stubby config — OK")
    return True


def _wait_for_openwrt_shell(sock, *, timeout_s: float = 180.0) -> None:
    """Nudge the serial console until an ash/root prompt appears."""
    deadline = time.monotonic() + timeout_s
    collected = ""
    sent_login = False
    sent_password = False
    while time.monotonic() < deadline:
        collected += _serial_exchange(sock, "\r", wait_s=1.0)
        lower = collected[-800:].lower()
        if "please press enter" in lower or "press enter to activate" in lower:
            collected += _serial_exchange(sock, "\r", wait_s=1.0)
            lower = collected[-800:].lower()
        if "login:" in lower and not sent_login:
            collected += _serial_exchange(sock, "root\r", wait_s=1.0)
            sent_login = True
            sent_password = False
            continue
        if "password:" in lower and not sent_password:
            collected += _serial_exchange(sock, openwrt_root_password() + "\r", wait_s=1.0)
            sent_password = True
            continue
        if any(p in collected for p in ("root@OpenWrt", "root@openwrt", "# ")):
            # Clear any partial line.
            _serial_exchange(sock, "\r", wait_s=0.5)
            return
        time.sleep(1.0)
    raise RuntimeError(
        "OpenWrt serial shell did not appear in time. "
        f"Last output:\n{collected[-1500:]}"
    )


def _serial_wait_for_text(sock, needles: tuple[str, ...], *, timeout_s: float) -> str:
    """Read serial output until any lowercase needle appears."""
    buf = ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        buf += _serial_drain(sock, wait_s=0.4)
        lower = buf.lower()
        if any(needle in lower for needle in needles):
            return buf
    raise RuntimeError(
        f"Timed out waiting for serial text {needles!r}. Last output:\n{buf[-1200:]}"
    )


def _serial_wait_for_shell_prompt(sock, *, timeout_s: float) -> str:
    """Read serial output until the OpenWrt shell prompt returns."""
    buf = ""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        buf += _serial_drain(sock, wait_s=0.4)
        if any(p in buf for p in ("root@OpenWrt", "root@openwrt", "# ")):
            return buf
    raise RuntimeError(f"Timed out waiting for OpenWrt shell prompt. Last output:\n{buf[-1200:]}")


def _serial_read_status_digit(sock, *, marker: str) -> str:
    out = _serial_run_marked(sock, "cat /tmp/st", marker=marker, wait_s=3.0)
    digit = "?"
    for line in out.replace("\r", "\n").splitlines():
        s = line.strip()
        if s.isdigit() and len(s) <= 3:
            digit = s
    return digit


def _set_openwrt_root_password(sock) -> None:
    """Set OpenWrt root password from VM/.env over the existing serial shell."""
    password = openwrt_root_password()
    if any(ch in password for ch in "\r\n\0"):
        raise RuntimeError("OPENWRT_ROOT_PASSWORD must not contain newlines or NUL bytes.")
    if len(password) > _SERIAL_MAX_CMD:
        raise RuntimeError(
            "OPENWRT_ROOT_PASSWORD is too long for the OpenWrt serial console; "
            f"use {_SERIAL_MAX_CMD} characters or fewer."
        )

    _serial_run_marked(sock, "rm -f /tmp/st", marker="PW0", wait_s=3.0)
    _serial_drain(sock, wait_s=0.2)
    sock.sendall(b"passwd root; echo $? >/tmp/st\r")
    _serial_wait_for_text(
        sock,
        ("new password", "password:"),
        timeout_s=8.0,
    )
    sock.sendall(f"{password}\r".encode("utf-8", errors="replace"))
    _serial_wait_for_text(
        sock,
        ("retype", "again", "confirm", "repeat"),
        timeout_s=8.0,
    )
    sock.sendall(f"{password}\r".encode("utf-8", errors="replace"))
    out = _serial_wait_for_shell_prompt(sock, timeout_s=12.0)
    digit = _serial_read_status_digit(sock, marker="PW2")
    if digit != "0":
        raise RuntimeError(f"Failed to set OpenWrt root password (exit={digit}).\n{out[-1000:]}")
    _serial_run_marked(sock, "rm -f /tmp/st", marker="PWC", wait_s=3.0)
    print("[overdrive] OpenWrt root password set from VM/.env.")


def _serial_upload_b64_file(
    sock,
    *,
    remote_path: str,
    data: bytes,
    verify_grep: str | None = "verify_mullvad",
    chmod_mode: str = "0755",
) -> None:
    """Upload bytes to remote_path via short base64 printf chunks (no long lines).

    Never deletes ``remote_path`` until a verified decode succeeds (writes via temp).
    """
    import base64
    import re

    expected = len(data)
    b64 = base64.b64encode(data).decode("ascii")
    tmp_b64 = "/tmp/od.b64"
    tmp_out = "/tmp/od.new"
    _serial_run_marked(sock, f"rm -f {tmp_b64} {tmp_out}", marker="UP0", wait_s=3.0)
    # printf '%s' '<chunk>' >> /tmp/od.b64  must stay <= _SERIAL_MAX_CMD.
    chunk_size = 40
    chunks = [b64[i : i + chunk_size] for i in range(0, len(b64), chunk_size)]
    for i, piece in enumerate(chunks, start=1):
        cmd = f"printf '%s' '{piece}' >> {tmp_b64}"
        if len(cmd) > _SERIAL_MAX_CMD:
            raise ValueError(f"upload chunk cmd too long: {len(cmd)}")
        # Unique markers so a stale "U" line cannot satisfy the next chunk.
        marker = f"U{i % 1000}"
        _serial_run_marked(sock, cmd, marker=marker, wait_s=5.0)
        if i == 1 or i % 50 == 0 or i == len(chunks):
            print(f"[overdrive]   upload chunk {i}/{len(chunks)}")

    def _remote_size(path: str) -> int:
        out = _serial_run_marked(sock, f"wc -c {path}", marker="SZ", wait_s=5.0)
        m = re.search(rf"(\d+)\s+{re.escape(path)}", out)
        if m:
            return int(m.group(1))
        for line in out.replace("\r", "\n").splitlines():
            m2 = re.match(r"^\s*(\d+)\s", line)
            if m2:
                return int(m2.group(1))
        return -1

    b64_size = _remote_size(tmp_b64)
    if b64_size != len(b64):
        raise RuntimeError(
            f"Serial upload incomplete: b64 size={b64_size} expected={len(b64)}"
        )

    # BusyBox base64 decodes stdin — do NOT pass the filename as an arg.
    _serial_run_marked(
        sock,
        f"base64 -d < {tmp_b64} > {tmp_out}",
        marker="D1",
        wait_s=15.0,
    )
    size = _remote_size(tmp_out)
    if size != expected:
        _serial_run_marked(
            sock,
            f"base64 -D < {tmp_b64} > {tmp_out}",
            marker="D4",
            wait_s=15.0,
        )
        size = _remote_size(tmp_out)

    if size != expected:
        raise RuntimeError(
            f"Serial upload decode failed: size={size} expected={expected}. "
            "Rely on image inject instead."
        )

    if verify_grep:
        digit = _serial_status_digit(
            sock,
            check_cmd=f"grep -q {verify_grep} {tmp_out}; echo $? >/tmp/st",
            marker="D3",
        )
        if digit != "0":
            raise RuntimeError(
                f"Serial upload content check failed (grep_exit={digit})"
            )

    # Atomic replace — existing remote_path kept until this succeeds.
    _serial_run_marked(sock, f"mv -f {tmp_out} {remote_path}", marker="MV", wait_s=3.0)
    _serial_run_marked(sock, f"chmod {chmod_mode} {remote_path}", marker="D2", wait_s=3.0)
    print(f"[overdrive]   upload OK ({size} bytes)")


def ensure_mullvad_dot_over_serial(
    *,
    timeout_s: float = 240.0,
    vboxmanage: str | None = None,
    allow_serial_upload: bool = False,
) -> None:
    """
    After VM start: run image-injected apply_mullvad_dot.sh once, require Mullvad whoami.

    Offline stubby APKs must already be in the image (/root/overdrive-apks). Serial upload
    of the script is optional last-resort only — never used for multi-MB package installs.
    """
    import re
    import socket

    print(
        f"[overdrive] Waiting for OpenWrt serial and applying Mullvad DoT "
        f"(timeout {int(timeout_s)}s)..."
    )

    overall_deadline = time.monotonic() + timeout_s

    def remaining(label: str, *, cap: float | None = None) -> float:
        rem = overall_deadline - time.monotonic()
        if rem <= 0:
            raise RuntimeError(f"OpenWrt serial bootstrap timed out during {label}.")
        if cap is not None:
            rem = min(rem, cap)
        return max(0.2, rem)

    def open_sock(*, timeout: float = 30.0):
        return _open_router_serial_socket(
            timeout_s=remaining("serial connect", cap=timeout),
        )

    sock = open_sock(timeout=min(60.0, timeout_s))
    try:
        last_transport_error: OSError | None = None
        while True:
            try:
                _wait_for_openwrt_shell(
                    sock,
                    timeout_s=remaining("shell prompt", cap=60.0),
                )
                break
            except OSError as exc:
                last_transport_error = exc
                if time.monotonic() >= overall_deadline:
                    raise RuntimeError(
                        "OpenWrt serial dropped before a shell prompt appeared."
                    ) from last_transport_error
                print(f"[overdrive] Router serial dropped while waiting for shell ({exc}); reconnecting...")
                _close_serial_socket(sock)
                sock = open_sock(timeout=10.0)

        try:
            _set_openwrt_root_password(sock)
        except (OSError, RuntimeError) as exc:
            print(f"[overdrive] Could not set OpenWrt root password over serial ({exc}); reconnecting...")
            _close_serial_socket(sock)
            sock = open_sock(timeout=10.0)
            _wait_for_openwrt_shell(sock, timeout_s=remaining("shell prompt after reconnect", cap=30.0))

        def reconnect_serial(exc: OSError) -> None:
            nonlocal sock
            print(f"[overdrive] Router serial dropped during bootstrap ({exc}); reconnecting...")
            _close_serial_socket(sock)
            sock = open_sock(timeout=10.0)
            _wait_for_openwrt_shell(sock, timeout_s=remaining("shell prompt after reconnect", cap=30.0))

        def run_marked(command: str, *, marker: str, wait_s: float = 15.0) -> str:
            attempts = 3
            for attempt in range(1, attempts + 1):
                try:
                    return _serial_run_marked(
                        sock,
                        command,
                        marker=marker,
                        wait_s=remaining(f"serial marker {marker}", cap=wait_s),
                    )
                except OSError as exc:
                    if attempt >= attempts:
                        raise
                    reconnect_serial(exc)
            raise RuntimeError(f"unreachable serial retry state for marker {marker!r}")

        def status_digit(*, check_cmd: str, marker: str) -> str:
            run_marked("rm -f /tmp/st", marker=f"{marker}0", wait_s=3.0)
            run_marked(check_cmd, marker=f"{marker}1", wait_s=5.0)
            out = run_marked("cat /tmp/st", marker=f"{marker}2", wait_s=3.0)
            digit = "?"
            for line in out.replace("\r", "\n").splitlines():
                s = line.strip()
                if s.isdigit() and len(s) <= 3:
                    digit = s
            return digit

        def guest_has_apply_script() -> bool:
            digit = status_digit(
                check_cmd="grep -q verify_mullvad /root/apply_mullvad_dot.sh; echo $? >/tmp/st",
                marker="HV",
            )
            return digit == "0"

        def output_is_mullvad_whoami(who_out: str) -> bool:
            return _serial_output_is_mullvad_whoami(
                sock,
                who_out,
                status_digit_func=status_digit,
            )

        # Stop any first-boot background apply so we own a single run.
        run_marked("killall apply_mullvad_dot.sh", marker="K1", wait_s=3.0)

        wan_deadline = min(time.monotonic() + 120.0, overall_deadline)
        while time.monotonic() < wan_deadline:
            out = run_marked(
                "ping -c1 -W2 1.1.1.1 >/dev/null && echo WAN_OK",
                marker="WAN",
                wait_s=6.0,
            )
            if _serial_line_has_marker(out, "WAN_OK"):
                print("[overdrive] WAN reachable from OpenWrt.")
                break
            print("[overdrive]   waiting for WAN...")
            time.sleep(2.0)
        else:
            print("[!] WAN not confirmed; continuing apply anyway...")

        # Fast path first — does not need apply script (survives a bad serial upload).
        who0 = run_marked(
            "nslookup whoami.akamai.net 127.0.0.1",
            marker="WHO0",
            wait_s=20.0,
        )
        if output_is_mullvad_whoami(who0):
            run_marked(
                "touch /etc/overdrive-mullvad-dot.done",
                marker="DONE0",
                wait_s=3.0,
            )
            run_marked("rm -f /root/apply_mullvad_dot.sh", marker="RMAPP0", wait_s=3.0)
            print("[+] Mullvad DoT already active on OpenWrt.")
            return

        if not guest_has_apply_script():
            if not allow_serial_upload:
                raise RuntimeError(
                    "/root/apply_mullvad_dot.sh missing on guest and DNS is not Mullvad yet. "
                    "Recreate the router (guestfish injects the script + offline APKs)."
                )
            print("[overdrive] Guest missing apply script; uploading once over serial...")
            try:
                _serial_upload_b64_file(
                    sock,
                    remote_path="/root/apply_mullvad_dot.sh",
                    data=APPLY_MULLVAD_DOT_SH.encode("utf-8"),
                )
            except Exception as exc:
                raise RuntimeError(
                    "Serial upload of apply script failed. "
                    "Recreate the router so guestfish injects the script + APKs."
                ) from exc
        else:
            print("[overdrive] Using /root/apply_mullvad_dot.sh from image.")

        apk_digit = status_digit(
            check_cmd="ls /root/overdrive-apks/*.apk >/dev/null 2>&1; echo $? >/tmp/st",
            marker="AK",
        )
        if apk_digit != "0":
            print(
                "[!] No offline APKs in /root/overdrive-apks — "
                "apply will try apk update (slow, often fails)."
            )
        else:
            print("[overdrive] Offline stubby APKs present on guest.")

        # Capture exit code in the same line so $? is from apply, not from echo MARKER.
        apply_cmd = "FORCE=1 /root/apply_mullvad_dot.sh >/tmp/a.log 2>&1; echo $? >/tmp/a.ex"
        print("[overdrive] Running FORCE=1 /root/apply_mullvad_dot.sh ...")
        apply_out = run_marked(
            apply_cmd,
            marker="APDONE",
            wait_s=min(150.0, timeout_s),
        )
        if not _serial_line_has_marker(apply_out, "APDONE"):
            print(f"[!] Apply did not finish cleanly:\n{apply_out[-2000:]}")

        exit_digit = status_digit(
            check_cmd="cp /tmp/a.ex /tmp/st 2>/dev/null || echo 9 >/tmp/st",
            marker="EX",
        )
        log_tail = run_marked("tail -30 /tmp/a.log", marker="LG", wait_s=10.0)
        print(f"[overdrive] Apply exit={exit_digit}")
        print(log_tail[-1500:])

        who = run_marked(
            "nslookup whoami.akamai.net 127.0.0.1",
            marker="WHO",
            wait_s=25.0,
        )
        if output_is_mullvad_whoami(who):
            # Guest apply may still exit non-zero if its verify only accepted 194.242.2.x;
            # host accepts Mullvad anycast PoP unicast (*.mullvad.net PTR) too.
            run_marked(
                "touch /etc/overdrive-mullvad-dot.done",
                marker="DONE1",
                wait_s=3.0,
            )
            run_marked("rm -f /root/apply_mullvad_dot.sh", marker="RMAPP1", wait_s=3.0)
            print("[+] Mullvad DoT verified on OpenWrt.")
            return

        # One cold-start retry (clock/WAN), still no upload loop.
        print("[!] whoami not Mullvad yet; one retry after short delay...")
        print(who[-1500:])
        time.sleep(min(8.0, max(0.0, overall_deadline - time.monotonic())))
        apply_out = run_marked(
            apply_cmd,
            marker="AP2",
            wait_s=min(120.0, timeout_s),
        )
        exit_digit = status_digit(
            check_cmd="cp /tmp/a.ex /tmp/st 2>/dev/null || echo 9 >/tmp/st",
            marker="EX2",
        )
        log_tail = run_marked("tail -40 /tmp/a.log", marker="LG2", wait_s=10.0)
        print(f"[overdrive] Retry apply exit={exit_digit}")
        print(log_tail[-2000:])
        who = run_marked(
            "nslookup whoami.akamai.net 127.0.0.1",
            marker="WHO2",
            wait_s=25.0,
        )
        if output_is_mullvad_whoami(who):
            run_marked(
                "touch /etc/overdrive-mullvad-dot.done",
                marker="DONE2",
                wait_s=3.0,
            )
            run_marked("rm -f /root/apply_mullvad_dot.sh", marker="RMAPP2", wait_s=3.0)
            print("[+] Mullvad DoT verified on OpenWrt.")
            return

        raise RuntimeError(
            "OpenWrt Mullvad DoT was not verified after create.\n"
            "Expected Mullvad DNS (anycast 194.242.2.x or PoP *.mullvad.net) "
            "via dnsmasq→stubby.\n"
            f"apply exit={exit_digit}\n{log_tail[-2500:]}\n{who[-1500:]}"
        )
    finally:
        _close_serial_socket(sock)


def mullvad_dot_console_instructions(apply_path: Path | None = None) -> str:
    resolvers = ", ".join(f"{ip} ({name})" for ip, name in MULLVAD_DOT_RESOLVERS)
    extra = ""
    if apply_path is not None:
        extra = (
            f"Host copy of the apply script: {apply_path}\n"
            "Paste or scp onto OpenWrt if first-boot auto-setup did not run:\n"
            "  /root/apply_mullvad_dot.sh\n"
            "Or paste the same script from the host file above.\n"
        )
    return (
        "\n--- DNS (Mullvad DoT) ---\n"
        f"Upstream: Mullvad DNS-over-TLS on port {MULLVAD_DOT_PORT}: {resolvers}\n"
        f"LAN clients: DHCP option 6 → {OPENWRT_LAN_DNS} (dnsmasq → stubby → Mullvad).\n"
        "create_VM_OpenWrt_router.py downloads stubby .apk deps, injects them + apply script\n"
        "into the image, then after start runs apply once over serial and requires\n"
        "Mullvad DNS (whoami anycast 194.242.2.x or PoP *.mullvad.net).\n"
        "After successful verification, /root/apply_mullvad_dot.sh is removed from OpenWrt.\n"
        "Log on router: /tmp/overdrive-mullvad-dot.log\n"
        f"{extra}"
        "Recreate the router if Mullvad DoT needs to be applied from scratch again.\n"
        "Verify on OpenWrt:  nslookup whoami.akamai.net 127.0.0.1\n"
        "  # expect 194.242.2.x OR PTR of that IP is *.mullvad.net\n"
        "  grep dns.mullvad.net /etc/stubby/stubby.yml\n"
        f"Verify on client:   dig +short whoami.akamai.net\n"
        f"  cat /etc/resolv.conf   # expect nameserver {OPENWRT_LAN_DNS}\n"
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


def assign_g3100_macs(vboxmanage: str) -> tuple[str, str]:
    """
    Assign fresh Verizon FiOS G3100-style MACs to LAN (NIC1) and WAN (NIC2).

    Must be called while the VM is powered off. A new pair is generated on every
    create so the lab router does not keep a sticky VirtualBox OUI.
    """
    lan = random_g3100_mac_vbox()
    wan = random_g3100_mac_vbox()
    while wan == lan:
        wan = random_g3100_mac_vbox()
    run_vboxmanage(
        vboxmanage,
        [
            "modifyvm",
            VM_NAME,
            "--macaddress1",
            lan,
            "--macaddress2",
            wan,
        ],
    )
    oui = G3100_MAC_OUI.lower().replace(":", "")
    oui_colon = ":".join(oui[i : i + 2] for i in range(0, 6, 2))
    print(
        f"[overdrive] G3100 MACs (OUI {oui_colon}): "
        f"LAN={format_mac_colon(lan)}  WAN={format_mac_colon(wan)}"
    )
    return lan, wan


def wait_for_router_running(vboxmanage: str, *, timeout_s: float = 60.0) -> None:
    """Wait until VBoxManage reports the router VM as running."""
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            last_state = get_vm_state(vboxmanage, VM_NAME)
        except Exception as exc:
            last_state = f"error: {exc}"
        if last_state == "running":
            return
        time.sleep(1.0)
    raise RuntimeError(f"{VM_NAME} did not reach running state; last state={last_state!r}")


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
            "Alpine client serial uses TCP 2325; router uses 2324 so both can run together.\n"
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
    from VM.alpine_client import create_VM_client_browser_pipe_alpine as client_serial

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
    connect_serial: bool = True,
) -> None:
    options = OpenWrtRouterBuildOptions(
        start_type=start_type,
        connect_serial=connect_serial,
    )
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
    src_path = wsl_to_windows_path(img_path) if paths["is_wsl"] else img_path
    vms_root_for_vbox = wsl_to_windows_path(vms_root) if paths["is_wsl"] else vms_root
    serial_endpoint = router_serial_endpoint(vboxmanage)
    apply_helper: Path | None = None
    apk_dir: Path | None = None
    router_started = False
    dot_verified = False

    def require_apply_helper() -> Path:
        if apply_helper is None:
            raise RuntimeError("Mullvad DoT helper was not prepared before router start.")
        return apply_helper

    def require_apk_dir() -> Path:
        if apk_dir is None:
            raise RuntimeError("OpenWrt Stubby APK cache was not prepared before image injection.")
        return apk_dir

    def remove_previous_vm() -> None:
        print(f"Fresh rebuild: removing existing {VM_NAME!r} registration and disk first.")
        remove_existing_vm(
            vboxmanage,
            VM_NAME,
            vm_base,
            medium_path_for_vbox=dst_path,
        )

    def ensure_workspace() -> None:
        os.makedirs(vms_root, exist_ok=True)
        os.makedirs(vm_base, exist_ok=True)

    def download_base_image() -> None:
        download_openwrt_image(OPENWRT_URL, img_path)

    def prepare_mullvad_dot_helpers() -> None:
        nonlocal apply_helper
        apply_helper = write_mullvad_dot_helpers(Path(vm_base))
        # Keep a copy beside the script for manual use.
        write_mullvad_dot_helpers(Path(SCRIPT_DIR))

    def fetch_mullvad_dot_packages() -> None:
        nonlocal apk_dir
        apk_dir = fetch_openwrt_stubby_apks()

    def inject_mullvad_dot_assets() -> None:
        injected = inject_mullvad_dot_into_openwrt_image(
            img_path,
            apk_dir=require_apk_dir(),
        )
        if not injected:
            raise RuntimeError(
                "Image inject failed (need guestfish/virt-customize + libguestfs). "
                "Offline stubby APKs + apply script must be baked into the disk - "
                "serial upload is too slow/fragile for OpenWrt 25.12 apk packages.\n"
                f"Host apply script: {require_apply_helper()}\n"
                f"APK cache: {require_apk_dir()}"
            )

    def convert_image_to_vdi() -> None:
        # Always rebuild VDI from the (possibly just-injected) raw image.
        if os.path.exists(vdi_path):
            print(f"Removing stale VDI so convertfromraw uses the current image: {vdi_path}")
            try:
                os.remove(vdi_path)
            except OSError as exc:
                print(f"[!] Could not remove VDI ({exc}); attempting VBox closemedium...")
                subprocess.run(
                    [vboxmanage, "closemedium", "disk", dst_path, "--delete"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
        print("Converting raw image to VDI...")
        run_vboxmanage(vboxmanage, ["convertfromraw", src_path, dst_path, "--format", "VDI"])

    def create_vm_registration() -> None:
        # ``createvm --basefolder`` must be the parent ``VirtualBox VMs`` dir.
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

    def configure_vm_firmware() -> None:
        # Force BIOS firmware (command line uses modifyvm, not createvm).
        run_vboxmanage(vboxmanage, ["modifyvm", VM_NAME, "--firmware", "bios"])

    def configure_vm_network_and_hardware() -> None:
        # NIC1 = LAN: matches OpenWrt default br-lan on eth0. NIC2 = WAN on eth1.
        lan_nic_args = [
            "--nic1",
            "intnet",
            "--intnet1",
            LAN_INTNET_NAME,
            "--nicpromisc1",
            "allow-vms",
        ]

        bridge_interface = get_active_bridged_interface(vboxmanage)
        if not bridge_interface:
            raise RuntimeError(
                "Router WAN requires a bridged VirtualBox adapter, but VirtualBox reported none. "
                "Connect or enable a host network adapter, then rebuild."
            )
        wan_nic_args = ["--nic2", "bridged", "--bridgeadapter2", bridge_interface]
        wan_note = f"bridged -> {bridge_interface!r} (WAN / uplink)"

        # Ensure VirtualBox can create VM log files.
        logs_dir = Path(vm_base) / "Logs"
        os.makedirs(logs_dir, exist_ok=True)

        print(f"Configuring VM {VM_NAME}...")
        print(f"  LAN (NIC1): internal network {LAN_INTNET_NAME!r} - stock OpenWrt ``br-lan`` on ``eth0``.")
        print(f"  WAN (NIC2): {wan_note} - stock OpenWrt ``wan`` on ``eth1``.")
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

    def configure_vm_serial() -> None:
        configure_router_serial(vboxmanage, serial_endpoint)

    def attach_storage() -> None:
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

    def assign_fresh_router_macs() -> None:
        # Fresh Verizon FiOS G3100-style MACs on every create. The VM must be powered off.
        assign_g3100_macs(vboxmanage)

    def start_router_vm() -> None:
        nonlocal router_started
        if options.start_type == "none":
            print("VM configured. Skipping start because --start-type none was selected.")
            return

        print(f"Starting VM ({options.start_type})...")
        run_vboxmanage(vboxmanage, ["startvm", VM_NAME, "--type", options.start_type])
        wait_for_router_running(vboxmanage, timeout_s=90.0)
        print(f"[+] VM is running with --type {options.start_type!r}.")
        router_started = True

    def bootstrap_mullvad_dot() -> None:
        nonlocal dot_verified
        if not router_started:
            return
        # First boot has an injected init.d job that applies Mullvad DoT. Serial verification
        # is useful when available, but VirtualBox's TCP serial backend can be flaky on GUI
        # starts; do not fail the whole VM build solely because COM1 is unavailable.
        try:
            ensure_mullvad_dot_over_serial(
                timeout_s=30.0,
                vboxmanage=vboxmanage,
                allow_serial_upload=False,
            )
            dot_verified = True
        except Exception as exc:
            print(f"[!] Mullvad DoT serial verification did not complete: {exc}")
            print(
                "[!] Continuing VM build; OpenWrt first-boot init will apply the injected "
                "Mullvad DoT config. Re-run --apply-mullvad-only later for strict verification."
            )

    def print_router_access_instructions() -> None:
        helper = require_apply_helper()
        print(mullvad_dot_console_instructions(helper))
        print(router_serial_instructions(vboxmanage, serial_endpoint))
        if not dot_verified:
            print("[!] Mullvad DoT was not serial-verified during create.")

    def attach_router_serial() -> None:
        if not router_started:
            return
        if options.connect_serial:
            time.sleep(1)
            # New window by default - keep the create/start shell free.
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

    steps = [
        BuildStep("cleanup.existing-vm", "remove previous VM and disk", remove_previous_vm),
        BuildStep("workspace.prepare", "prepare workspace", ensure_workspace),
        BuildStep("image.download-base", "download OpenWrt base image", download_base_image),
        BuildStep("dot.helpers", "prepare Mullvad DoT helper scripts", prepare_mullvad_dot_helpers),
        BuildStep(
            "dot.package-cache",
            "download Mullvad DoT package cache",
            fetch_mullvad_dot_packages,
            description="Future optional boundary for Stubby and DNS-over-TLS package injection.",
        ),
        BuildStep("dot.inject-assets", "inject Mullvad DoT scripts and packages", inject_mullvad_dot_assets),
        BuildStep("disk.convert-vdi", "convert image to VDI", convert_image_to_vdi),
        BuildStep("vbox.register", "create VirtualBox VM registration", create_vm_registration),
        BuildStep("vbox.firmware", "configure VM firmware", configure_vm_firmware),
        BuildStep("vbox.network", "configure router network adapters", configure_vm_network_and_hardware),
        BuildStep("vbox.serial", "configure router serial endpoint", configure_vm_serial),
        BuildStep("vbox.storage", "attach VDI storage", attach_storage),
        BuildStep("vbox.macs", "assign fresh Verizon router MACs", assign_fresh_router_macs),
        BuildStep("vbox.start", "start router VM", start_router_vm, enabled=options.start_type != "none"),
        BuildStep("dot.bootstrap", "bootstrap and verify Mullvad DoT", bootstrap_mullvad_dot, enabled=lambda: router_started),
        BuildStep("instructions.print", "print router access instructions", print_router_access_instructions),
        BuildStep("serial.attach", "open router serial console", attach_router_serial, enabled=lambda: router_started and options.connect_serial),
    ]
    run_openwrt_router_pipeline(steps)


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
        choices=("gui", "headless", "separate", "none"),
        default="gui",
        help=(
            "How to start the VM after creation.\n"
            "Default: gui."
        ),
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
    parser.add_argument(
        "--apply-mullvad-only",
        action="store_true",
        help="Do not recreate the VM; only upload/run Mullvad DoT apply over serial and verify.",
    )
    parser.add_argument(
        "--start-alpine-client",
        action="store_true",
        help="Start the Alpine client VM after the router is ready.",
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
    if args.apply_mullvad_only:
        paths = get_system_paths(VM_NAME)
        vboxmanage = find_vboxmanage(paths)
        if not vboxmanage:
            raise RuntimeError(get_vboxmanage_install_hint())
        if get_vm_state(vboxmanage, VM_NAME) != "running":
            raise RuntimeError(f"{VM_NAME} is not running. Start it first.")
        print("Close any OpenWrt serial window on TCP 2324 (this needs exclusive access).")
        ensure_mullvad_dot_over_serial(
            timeout_s=240.0,
            vboxmanage=vboxmanage,
            allow_serial_upload=False,
        )
        print("[+] Mullvad DoT OK. On Alpine: dig +short whoami.akamai.net  # Mullvad anycast or PoP")
        return
    setup_openwrt_vm(
        start_type=args.start_type,
        connect_serial=not args.no_connect_serial,
    )

    if args.start_alpine_client:
        if setup_alpine_client_vm:
            print("\n--- Starting Alpine Client VM ---")
            try:
                setup_alpine_client_vm(
                    start_vm=True,
                    connect_serial=not args.no_connect_serial,
                )
                print("[+] Alpine client VM started successfully.")
            except Exception as e:
                print(f"[!] Failed to start Alpine client VM: {e}")
                raise
        else:
            raise RuntimeError("Alpine client setup script not found, cannot start Alpine VM.")


if __name__ == "__main__":
    main()
