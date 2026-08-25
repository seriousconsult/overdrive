#!/usr/bin/env python3
"""
Bootstrap a project-local Python virtual environment for Overdrive automation.

- Creates ./virtual_env next to this script
- Installs Python deps into the venv (requests, selenium, httpx, scapy, zeroconf)
- Installs OS deps via apt (Ubuntu/Debian), dnf (Fedora/RHEL), or apk (Alpine) —
  including curl/iproute/iptables/ping/WireGuard tools (distro package names vary;
  Debian uses ``iputils-ping``), network diagnostics (nmap, dig, tcpdump), and a
  browser/driver for Selenium
- Applies file capabilities to the venv interpreter (so Scapy can use raw sockets without sudo)
- Drops into an interactive bash with venv activated (skipped with ``--non-interactive``)

The Alpine LAN client primes by copying this script to ``/root`` and running it
with ``--non-interactive`` (do not apk-add those checker packages in
``package_assets.py``).
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import venv
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
VENV_DIR = REPO_ROOT / "virtual_env"
VENV_PYTHON = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
    "python.exe" if sys.platform == "win32" else "python"
)

PY_DEPS = [
    "requests",
    "selenium",
    "httpx[http2]",
    "scapy",
    "zeroconf",
]

# OS packages that provide the ``dig`` CLI (name differs by distro).
DIG_PACKAGE_BY_MGR = {
    "apt": "dnsutils",
    "dnf": "bind-utils",
    "apk": "bind-tools",
}

# Core networking packages used by the Alpine lab client (and useful on hosts).
# Installed here — not by VM/alpine_client/package_assets.py.
# Package names differ by distro (Debian has iputils-ping, not iputils).
NET_BASE_PACKAGES_BY_MGR: dict[str, tuple[str, ...]] = {
    "apt": ("curl", "iproute2", "iptables", "iputils-ping", "wireguard-tools"),
    "dnf": ("curl", "iproute", "iptables", "iputils", "wireguard-tools"),
    "apk": ("curl", "iproute2", "iptables", "iputils", "wireguard-tools"),
}

# Real, non-GUI runtime assets that make headless Chromium less skeletal on the
# Alpine lab client. These improve measured fonts/rendering/media capability;
# they do not mask headless automation or spoof browser identity.
ALPINE_BROWSER_SUPPORT_PACKAGES: tuple[str, ...] = (
    "fontconfig",
    "ttf-dejavu",
    "ttf-liberation",
    "msttcorefonts-installer",
    "font-croscore",
    "font-crosextra-caladea",
    "font-crosextra-carlito",
    "font-noto",
    "font-noto-cjk",
    "font-noto-emoji",
    "font-noto-extra",
    "font-roboto",
    "font-droid",
    "ttf-opensans",
    "freetype",
    "harfbuzz",
    "icu-data-full",
    "musl-locales",
    "musl-locales-lang",
    "mesa-dri-gallium",
    "mesa-egl",
    "mesa-gl",
    "libdrm",
    "alsa-lib",
    "alsa-plugins",
    "alsa-utils",
    "pulseaudio-libs",
)

APT_LOCK_TIMEOUT_SECONDS = 180
APT_LOCK_WAIT_SECONDS = 60
APT_LOCK_POLL_SECONDS = 2
APT_LOCK_REPORT_SECONDS = 15
APT_LOCK_MAX_ATTEMPTS = 5
APT_UPDATE_MAX_AGE_SECONDS = 24 * 60 * 60
APT_LOCK_PATHS = (
    "/var/lib/apt/lists/lock",
    "/var/cache/apt/archives/lock",
    "/var/lib/dpkg/lock-frontend",
    "/var/lib/dpkg/lock",
)
APT_LOCK_PROCESS_NAMES = {
    "apt",
    "apt-get",
    "apt.systemd.daily",
    "dpkg",
    "unattended-upgr",
    "unattended-upgrades",
    "packagekitd",
}


class AptLockError(subprocess.CalledProcessError):
    """Raised when apt/dpkg is still locked after polite waiting."""


APT_UPDATED = False

def get_linux_info():
    if shutil.which("apk"):
        return {
            "mgr": "apk",
            "pcap": "libpcap",
            "7zip_sets": [["7zip"], ["p7zip"]],
            # Not useful inside the Alpine lab guest; host WSL uses apt/dnf.
            "guestfs_sets": [],
            "cap_provider_sets": [["libcap-utils"], ["libcap"]],
            "chrome_cmd": "chromium",
            "chrome_packages": ["chromium", "chromium-chromedriver"],
            "socat": "socat",
            "minicom": "minicom",
            "nmap": "nmap",
            "tcpdump": "tcpdump",
            "curl": "curl",
        }
    if shutil.which("dnf"):
        return {
            "mgr": "dnf",
            "pcap": "libpcap-devel",
            "7zip_sets": [["p7zip", "p7zip-plugins"], ["7zip"]],
            # guestfs tools package name can vary; we try a couple
            "guestfs_sets": [["guestfs-tools"], ["libguestfs-tools"]],
            "cap_provider_sets": [["libcap"], ["libcap-tools"]],
            "chrome_cmd": "google-chrome",
            "chrome_packages": [],
            "socat": "socat",
            "minicom": "minicom",
            "nmap": "nmap",
            "tcpdump": "tcpdump",
            "curl": "curl",
        }
    if shutil.which("apt"):
        return {
            "mgr": "apt",
            "pcap": "libpcap-dev",
            "7zip_sets": [["p7zip-full"], ["p7zip"], ["7zip"]],
            "guestfs_sets": [["libguestfs-tools"], ["guestfs-tools"]],
            "cap_provider_sets": [["libcap2-bin"], ["libcap-bin"]],
            "chrome_cmd": "google-chrome",
            "chrome_packages": [],
            "socat": "socat",
            "minicom": "minicom",
            "nmap": "nmap",
            "tcpdump": "tcpdump",
            "curl": "curl",
        }
    return None


def enable_alpine_community_repo() -> None:
    """Uncomment/add Alpine community (chromium, many py3-* packages)."""
    repos = Path("/etc/apk/repositories")
    if not repos.is_file():
        return
    try:
        text = repos.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    lines = text.splitlines()
    changed = False
    new_lines: list[str] = []
    has_community = False
    main_line = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") and "/community" in stripped:
            uncommented = stripped.lstrip("#").strip()
            new_lines.append(uncommented)
            changed = True
            has_community = True
            continue
        if stripped and not stripped.startswith("#") and "/community" in stripped:
            has_community = True
        if stripped and not stripped.startswith("#") and stripped.endswith("/main") and not main_line:
            main_line = stripped
        new_lines.append(line)
    if not has_community and main_line:
        new_lines.append(main_line.replace("/main", "/community"))
        changed = True
    if changed:
        repos.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
        print("[*] Enabled Alpine community repository.")

def have_cmd(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0

def add_sudo(cmd: list[str], *, non_interactive: bool) -> list[str]:
    if is_root():
        return cmd
    if not have_cmd("sudo"):
        raise RuntimeError("sudo is required for this step, but it is not installed.")

    sudo_cmd = ["sudo"]
    if non_interactive:
        sudo_cmd.append("-n")
    return [*sudo_cmd, *cmd]

def run_cmd(
    cmd: list[str],
    *,
    use_sudo: bool = True,
    non_interactive: bool = False,
    env: dict[str, str] | None = None,
):
    # If running as root, never require sudo.
    if use_sudo:
        cmd = add_sudo(cmd, non_interactive=non_interactive)
    subprocess.run(cmd, check=True, env=env)


def apt_base_command(args: list[str]) -> list[str]:
    apt_bin = "apt-get" if have_cmd("apt-get") else "apt"
    return [
        apt_bin,
        "-o",
        f"DPkg::Lock::Timeout={APT_LOCK_TIMEOUT_SECONDS}",
        "-o",
        f"APT::Get::Lock::Timeout={APT_LOCK_TIMEOUT_SECONDS}",
        *args,
    ]


def package_name_needs_apt_index(package: str) -> bool:
    return not package.startswith("/") and not package.endswith(".deb")


def apt_lists_are_fresh() -> bool:
    lists_dir = Path("/var/lib/apt/lists")
    try:
        newest = max(
            path.stat().st_mtime
            for path in lists_dir.iterdir()
            if path.is_file() and path.name != "lock"
        )
    except (OSError, ValueError):
        return False
    return time.time() - newest <= APT_UPDATE_MAX_AGE_SECONDS


def ensure_apt_updated_for(packages: list[str], *, non_interactive: bool) -> None:
    global APT_UPDATED

    if APT_UPDATED:
        return
    if not any(package_name_needs_apt_index(package) for package in packages):
        return
    if apt_lists_are_fresh():
        print("[*] apt package lists are fresh; skipping apt-get update.")
        return

    print(f"[*] apt-get update (waits up to {APT_LOCK_WAIT_SECONDS}s for apt locks)")
    run_apt(["update"], non_interactive=non_interactive)
    APT_UPDATED = True


def active_package_processes() -> list[str]:
    found: list[str] = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return found

    for proc_dir in proc_root.iterdir():
        if not proc_dir.name.isdigit():
            continue
        try:
            comm = (proc_dir / "comm").read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            continue
        if comm not in APT_LOCK_PROCESS_NAMES:
            continue
        try:
            cmdline_raw = (proc_dir / "cmdline").read_bytes()
            cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
        except OSError:
            cmdline = comm
        found.append(f"pid={proc_dir.name} {cmdline or comm}")
    return found


def proc_cmdline(pid: int) -> str:
    proc_dir = Path("/proc") / str(pid)
    try:
        cmdline_raw = (proc_dir / "cmdline").read_bytes()
        cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
        if cmdline:
            return cmdline
    except OSError:
        pass
    try:
        return (proc_dir / "comm").read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return "(process exited)"


def passive_package_watchers() -> list[str]:
    watchers: list[str] = []
    for line in active_package_processes():
        if "unattended-upgrade-shutdown" in line:
            watchers.append(line)
    return watchers


def apt_lock_holder_pids(*, non_interactive: bool) -> set[int]:
    existing_locks = [path for path in APT_LOCK_PATHS if Path(path).exists()]
    if not existing_locks or not have_cmd("fuser"):
        return set()

    commands = [["fuser", *existing_locks]]
    if not is_root() and have_cmd("sudo"):
        try:
            commands.append(add_sudo(["fuser", *existing_locks], non_interactive=non_interactive))
        except RuntimeError:
            pass

    for cmd in commands:
        try:
            proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        except OSError:
            continue
        if proc.returncode != 0:
            continue
        pids = {int(match) for match in re.findall(r"\b\d+\b", proc.stdout)}
        if pids:
            return pids
    return set()


def apt_lock_holder_details(*, non_interactive: bool) -> str:
    details: list[str] = []
    holder_pids = sorted(apt_lock_holder_pids(non_interactive=non_interactive))
    if holder_pids:
        details.append(
            "apt/dpkg lock holders:\n"
            + "\n".join(f"  pid={pid} {proc_cmdline(pid)}" for pid in holder_pids)
        )

    watchers = passive_package_watchers()
    if watchers:
        details.append(
            "Package watcher processes not treated as lock holders:\n"
            + "\n".join(f"  {line}" for line in watchers)
        )

    return "\n".join(details)


def apt_likely_locked(*, non_interactive: bool) -> bool:
    if apt_lock_holder_pids(non_interactive=non_interactive):
        return True

    if have_cmd("fuser"):
        return False

    package_processes = [
        line
        for line in active_package_processes()
        if "unattended-upgrade-shutdown" not in line
    ]
    return bool(package_processes)


def wait_for_apt_locks(*, non_interactive: bool) -> None:
    deadline = time.monotonic() + APT_LOCK_WAIT_SECONDS
    last_report = 0.0
    last_pids: set[int] | None = None

    while True:
        holder_pids = apt_lock_holder_pids(non_interactive=non_interactive)
        if not holder_pids:
            return

        now = time.monotonic()
        remaining = max(0, int(deadline - now))
        if remaining <= 0:
            print("[-] apt/dpkg is still locked; not removing lock files.")
            details = apt_lock_holder_details(non_interactive=non_interactive)
            if details:
                print(details)
            raise AptLockError(100, ["apt-lock-wait"])

        if holder_pids != last_pids or now - last_report >= APT_LOCK_REPORT_SECONDS:
            print(
                "[*] apt/dpkg lock is busy; waiting without touching lock files "
                f"(up to {remaining}s left)."
            )
            details = apt_lock_holder_details(non_interactive=non_interactive)
            if details:
                print(details)
            last_report = now
            last_pids = set(holder_pids)

        time.sleep(min(APT_LOCK_POLL_SECONDS, remaining))


def run_apt(
    args: list[str],
    *,
    non_interactive: bool = False,
) -> None:
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["APT_LISTCHANGES_FRONTEND"] = "none"

    cmd = apt_base_command(args)
    if not is_root():
        cmd = add_sudo(
            ["env", "DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none", *cmd],
            non_interactive=non_interactive,
        )

    for attempt in range(1, APT_LOCK_MAX_ATTEMPTS + 1):
        if attempt > 1:
            print(f"[*] Retrying apt command (attempt {attempt}/{APT_LOCK_MAX_ATTEMPTS})...")

        wait_for_apt_locks(non_interactive=non_interactive)
        proc = subprocess.run(cmd, env=env if is_root() else None)
        if proc.returncode == 0:
            return

        locked = apt_likely_locked(non_interactive=non_interactive)
        if proc.returncode != 100 or not locked or attempt == APT_LOCK_MAX_ATTEMPTS:
            if locked:
                print("[-] apt/dpkg still appears to be busy; not removing lock files.")
                details = apt_lock_holder_details(non_interactive=non_interactive)
                if details:
                    print(details)
                raise AptLockError(proc.returncode, cmd)
            raise subprocess.CalledProcessError(proc.returncode, cmd)

        wait_for_apt_locks(non_interactive=non_interactive)



def install_packages(info, packages: list[str], *, non_interactive: bool = False) -> None:
    mgr = info["mgr"]
    if mgr == "apt":
        ensure_apt_updated_for(packages, non_interactive=non_interactive)
        run_apt(["install", "-y", *packages], non_interactive=non_interactive)
    elif mgr == "apk":
        run_cmd(["apk", "add", "--no-cache", *packages], non_interactive=non_interactive)
    else:
        run_cmd([mgr, "install", "-y", *packages], non_interactive=non_interactive)



def install_first_available(
    info,
    package_sets: list[list[str]],
    *,
    non_interactive: bool = False,
):
    last_exc = None
    for packages in package_sets:
        try:
            install_packages(info, packages, non_interactive=non_interactive)
            return
        except AptLockError:
            raise
        except subprocess.CalledProcessError as exc:
            last_exc = exc
            print(f"[-] Failed installing: {' '.join(packages)}; trying next...")
    if last_exc:
        raise last_exc


def install_optional_packages(
    info,
    packages: list[str],
    *,
    non_interactive: bool = False,
) -> None:
    """Install optional runtime packages one-by-one, warning but continuing on miss."""
    for package in packages:
        if package_installed(info, package):
            print(f"[*] Optional package already installed: {package}")
            continue
        try:
            print(f"[*] Installing optional package: {package}...")
            install_packages(info, [package], non_interactive=non_interactive)
        except subprocess.CalledProcessError:
            print(f"[-] Optional package unavailable or failed to install: {package}; continuing.")


def refresh_font_cache_if_available() -> None:
    if have_cmd("update-ms-fonts"):
        try:
            print("[*] Installing Microsoft core web fonts via update-ms-fonts...")
            run_cmd(["update-ms-fonts"], use_sudo=False)
        except subprocess.CalledProcessError:
            print("[-] Microsoft core web font install failed; continuing.")
    if not have_cmd("fc-cache"):
        return
    try:
        print("[*] Refreshing fontconfig cache...")
        run_cmd(["fc-cache", "-f"], use_sudo=False)
    except subprocess.CalledProcessError:
        print("[-] Fontconfig cache refresh failed; continuing.")


def package_installed(info, package: str) -> bool:
    if package.startswith("/") or package.endswith(".deb"):
        return False

    mgr = info["mgr"]
    if mgr == "apt" and have_cmd("dpkg-query"):
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", package],
            text=True,
            capture_output=True,
            check=False,
        )
        return proc.returncode == 0 and "install ok installed" in proc.stdout
    if mgr == "dnf" and have_cmd("rpm"):
        proc = subprocess.run(["rpm", "-q", package], capture_output=True, check=False)
        return proc.returncode == 0
    if mgr == "apk" and have_cmd("apk"):
        proc = subprocess.run(
            ["apk", "info", "-e", package],
            capture_output=True,
            check=False,
        )
        return proc.returncode == 0
    return False

def distro_success_label():
    info = get_linux_info()
    if not info:
        return "this system (unknown package manager—install deps manually if needed)"
    labels = {
        "dnf": "Fedora / RHEL-family (dnf)",
        "apt": "Debian / Ubuntu (apt)",
        "apk": "Alpine (apk)",
    }
    return labels.get(info["mgr"], info["mgr"])

def install_system_deps(*, non_interactive: bool = False):
    info = get_linux_info()
    if not info:
        print("⚠️ Unknown OS: install system dependencies manually if needed.")
        return

    mgr = info["mgr"]
    print(f"Detected {mgr} package manager. Installing system deps...")

    if mgr == "apk":
        enable_alpine_community_repo()
        print("[*] apk update...")
        run_cmd(["apk", "update"], non_interactive=non_interactive)

    # 1) libpcap
    if not package_installed(info, info["pcap"]):
        print(f"[*] Installing {info['pcap']}...")
        install_packages(info, [info["pcap"]], non_interactive=non_interactive)
    else:
        print(f"[*] {info['pcap']} already installed.")

    # 2) 7zip (host tooling; optional on Alpine guest)
    if mgr != "apk":
        if not have_cmd("7z"):
            print("[*] Installing 7-Zip (first available option)...")
            install_first_available(
                info,
                info["7zip_sets"],
                non_interactive=non_interactive,
            )
        else:
            print("[*] 7-Zip already installed.")

    # 3) Browser for Selenium
    chrome_packages = info.get("chrome_packages") or []
    if chrome_packages:
        need_browser = not (
            have_cmd("chromium")
            or have_cmd("chromium-browser")
            or have_cmd(info["chrome_cmd"])
        )
        need_driver = not have_cmd("chromedriver")
        if need_browser or need_driver:
            print(f"[*] Installing browser packages: {' '.join(chrome_packages)}...")
            install_packages(info, chrome_packages, non_interactive=non_interactive)
        else:
            print("[*] Chromium + chromedriver already installed.")
    elif not have_cmd(info["chrome_cmd"]):
        print("[*] Installing Google Chrome...")
        if mgr == "dnf":
            chrome_url = "https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm"
            run_cmd(
                ["dnf", "install", "-y", chrome_url],
                use_sudo=True,
                non_interactive=non_interactive,
            )
        elif mgr == "apt":
            deb_url = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
            fd, deb_path = tempfile.mkstemp(suffix=".deb")
            os.close(fd)
            try:
                print("[*] Downloading Chrome .deb...")
                urllib.request.urlretrieve(deb_url, deb_path)
                install_packages(info, [deb_path], non_interactive=non_interactive)
            finally:
                try:
                    os.unlink(deb_path)
                except OSError:
                    pass
        else:
            print("[*] No Chrome installer path for this package manager; install a browser manually.")
    else:
        print("[*] Chrome already installed.")

    # 4) Alpine no-GUI browser runtime support: fonts, media, and software GL.
    if mgr == "apk":
        install_optional_packages(
            info,
            list(ALPINE_BROWSER_SUPPORT_PACKAGES),
            non_interactive=non_interactive,
        )
        refresh_font_cache_if_available()

    # 5) Core networking (lab client + hosts): curl, iproute, iptables, ping, WireGuard tools
    net_pkgs = list(NET_BASE_PACKAGES_BY_MGR.get(mgr, NET_BASE_PACKAGES_BY_MGR["apk"]))
    net_needed = [pkg for pkg in net_pkgs if not package_installed(info, pkg)]
    # Also treat missing CLIs as needing install (busybox may shadow package checks).
    ping_pkg = "iputils-ping" if mgr == "apt" else "iputils"
    ip_pkg = "iproute" if mgr == "dnf" else "iproute2"
    cli_to_pkg = {
        "curl": "curl",
        "ip": ip_pkg,
        "iptables": "iptables",
        "ping": ping_pkg,
        "wg": "wireguard-tools",
    }
    for cmd, pkg in cli_to_pkg.items():
        if not have_cmd(cmd) and pkg not in net_needed:
            net_needed.append(pkg)
    if net_needed:
        print(f"[*] Installing network base packages: {' '.join(net_needed)}...")
        install_packages(info, net_needed, non_interactive=non_interactive)
    else:
        print(f"[*] Network base packages already present: {' '.join(net_pkgs)}.")

    # 6) Network diagnostics + helpers: nmap, dig, tcpdump, socat [, minicom]
    diag_cmds = [
        ("nmap", info["nmap"]),
        ("tcpdump", info.get("tcpdump") or "tcpdump"),
        ("socat", info["socat"]),
    ]
    if mgr != "apk":
        diag_cmds.append(("minicom", info["minicom"]))

    for cmd, package in diag_cmds:
        if have_cmd(cmd):
            print(f"[*] {cmd} already installed.")
            continue
        print(f"[*] Installing {package} (provides {cmd})...")
        try:
            install_packages(info, [package], non_interactive=non_interactive)
        except subprocess.CalledProcessError:
            print(f"[-] Failed installing {package}; continuing.")

    dig_pkg = DIG_PACKAGE_BY_MGR.get(mgr)
    if dig_pkg:
        if have_cmd("dig"):
            print("[*] dig already installed.")
        else:
            print(f"[*] Installing {dig_pkg} (provides dig)...")
            install_packages(info, [dig_pkg], non_interactive=non_interactive)

    # 7) guestfs tools (for virt-customize on host builders — skip on Alpine guests)
    if info.get("guestfs_sets"):
        if not have_cmd("virt-customize"):
            print("[*] Installing guestfs tools for virt-customize (first available option)...")
            install_first_available(
                info,
                info["guestfs_sets"],
                non_interactive=non_interactive,
            )
        else:
            print("[*] virt-customize already available.")

    # 8) capability tool provider (setcap)
    if not have_cmd("setcap"):
        print("[*] Installing libcap tooling (first available option)...")
        install_first_available(
            info,
            info["cap_provider_sets"],
            non_interactive=non_interactive,
        )
    else:
        print("[*] setcap already available.")

def apply_network_capabilities(interpreter_path: Path, *, non_interactive: bool = False):
    if sys.platform == "win32":
        print("[*] Skipping setcap (not applicable on Windows).")
        return

    if not interpreter_path.exists():
        print(f"[-] Venv interpreter not found: {interpreter_path}")
        return

    if not have_cmd("setcap"):
        print("[-] 'setcap' not found. Install libcap tooling for your distro first.")
        return

    # Optional idempotency: if getcap exists and shows our desired caps, skip.
    if have_cmd("getcap"):
        try:
            out = subprocess.check_output(["getcap", str(interpreter_path)], stderr=subprocess.STDOUT).decode("utf-8", "ignore").strip()
            if "cap_net_raw" in out and "cap_net_admin" in out:
                print("[*] Network capabilities already set on venv interpreter; skipping setcap.")
                return
        except subprocess.CalledProcessError:
            pass

    print(f"[*] Applying network capabilities to venv Python: {interpreter_path}")
    try:
        run_cmd(
            ["setcap", "cap_net_raw,cap_net_admin+eip", str(interpreter_path)],
            use_sudo=True,
            non_interactive=non_interactive,
        )
        print("[+] Success! Run Scapy with this venv Python (or after activate).")
    except subprocess.CalledProcessError:
        print("[-] Failed to apply setcap. Ensure you have sudo privileges.")
        if non_interactive:
            raise
    except FileNotFoundError:
        print("[-] setcap utility not found. Install it with your distro's libcap package.")




def ensure_venv_support(*, non_interactive: bool = False):
    """
    Ensures the host python has ensurepip/venv support so `venv.create(..., with_pip=True)`
    can bootstrap pip. On Ubuntu/Debian this is typically python3-venv / pythonX.Y-venv.
    """
    if sys.platform == "win32":
        return

    # If ensurepip exists, we're good
    try:
        import ensurepip  # noqa: F401
        return
    except Exception:
        pass

    info = get_linux_info()
    if not info:
        raise RuntimeError(
            "Host python lacks ensurepip; please install venv support manually "
            "(e.g., apt install python3-venv on Ubuntu/Debian)."
        )

    pyver = f"{sys.version_info.major}.{sys.version_info.minor}"
    mgr = info["mgr"]

    # Install alternatives (Ubuntu/Debian are usually version-specific; Fedora varies)
    if mgr == "apt":
        candidates = [f"python{pyver}-venv", "python3-venv"]
    elif mgr == "apk":
        enable_alpine_community_repo()
        run_cmd(["apk", "update"], non_interactive=non_interactive)
        candidates = ["py3-pip", "python3"]
    else:  # dnf
        candidates = [f"python{pyver}-venv", "python3-venv"]

    print("[*] Host python missing ensurepip/venv support. Installing required package...")
    install_first_available(info, [[c] for c in candidates], non_interactive=non_interactive)

    # Alpine: py3-pip often provides ensurepip; re-check after install.
    if mgr == "apk":
        try:
            import ensurepip  # noqa: F401
            return
        except Exception:
            print(
                "[*] ensurepip still unavailable; venv will be created and pip "
                "bootstrapped via get-pip if needed."
            )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create the Overdrive virtual environment and optional system setup."
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help=(
            "Never prompt for input. Privileged commands use sudo -n and fail if "
            "passwordless sudo is unavailable. Also skips opening an activated shell."
        ),
    )
    parser.add_argument(
        "--apt-lock-wait",
        type=int,
        default=APT_LOCK_WAIT_SECONDS,
        metavar="SECONDS",
        help=(
            "Maximum time to wait for apt/dpkg lock holders before failing "
            f"(default: {APT_LOCK_WAIT_SECONDS})."
        ),
    )
    return parser.parse_args()



def main():
    args = parse_args()
    global APT_LOCK_WAIT_SECONDS
    APT_LOCK_WAIT_SECONDS = max(0, args.apt_lock_wait)

    # 0) Ensure host python can create venvs with pip
    ensure_venv_support(non_interactive=args.non_interactive)

    # 1) Always delete and recreate venv (fresh start)
    if VENV_DIR.exists():
        print(f"[!] Removing existing venv: {VENV_DIR}")
        shutil.rmtree(VENV_DIR)

    print(f"[*] Creating venv in {VENV_DIR}...")
    try:
        venv.create(str(VENV_DIR), with_pip=True)
    except Exception as exc:
        print(f"[*] venv.create(with_pip=True) failed ({exc}); retrying without pip...")
        if VENV_DIR.exists():
            shutil.rmtree(VENV_DIR)
        venv.create(str(VENV_DIR), with_pip=False)

    python_exe = str(VENV_PYTHON)
    if not Path(python_exe).exists():
        print(f"[-] Expected venv python not found at: {python_exe}")
        sys.exit(1)

    # Bootstrap pip when ensurepip was unavailable (common on minimal Alpine).
    pip_probe = subprocess.run(
        [python_exe, "-m", "pip", "--version"],
        capture_output=True,
        check=False,
    )
    if pip_probe.returncode != 0:
        print("[*] Bootstrapping pip into venv via ensurepip/get-pip...")
        ensure = subprocess.run(
            [python_exe, "-m", "ensurepip", "--upgrade"],
            capture_output=True,
            check=False,
        )
        if ensure.returncode != 0:
            get_pip = Path(tempfile.gettempdir()) / "get-pip.py"
            urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", get_pip)
            subprocess.check_call([python_exe, str(get_pip)])

    # 2) Install Python libs
    print("Installing Python packages into venv...")
    subprocess.check_call([python_exe, "-m", "pip", "install", "--no-input", *PY_DEPS])

    # 3) Install system deps (apt/dnf/apk)
    install_system_deps(non_interactive=args.non_interactive)

    print(f"\nSuccess! Virtual environment is ready on {distro_success_label()}.")

    # 4) Apply capabilities only when bootstrapping from system Python.
    if sys.platform != "win32" and sys.prefix == sys.base_prefix:
        print("[*] Running from system Python; applying capabilities to venv interpreter.")
        apply_network_capabilities(
            Path(python_exe),
            non_interactive=args.non_interactive,
        )

    # 5) Enter shell with venv activated
    if args.non_interactive:
        print(f"Activate it later with: source {VENV_DIR / 'bin' / 'activate'}")
        return 0

    print("Entering virtual environment... (Type 'exit' to leave)")
    activate = str(VENV_DIR / "bin" / "activate")
    subprocess.call(
        ["/bin/bash", "-i", "-c", f"source '{activate}'; exec /bin/bash -i"]
    )
    return 0


def command_text(cmd) -> str:
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(part) for part in cmd)
    return str(cmd)

def used_noninteractive_sudo(cmd) -> bool:
    return isinstance(cmd, (list, tuple)) and "sudo" in cmd and "-n" in cmd

if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(
            f"[-] Command failed with exit code {exc.returncode}: {command_text(exc.cmd)}",
            file=sys.stderr,
        )
        if used_noninteractive_sudo(exc.cmd):
            print(
                "[-] Non-interactive sudo was denied. Configure passwordless sudo "
                "or run the script interactively.",
                file=sys.stderr,
            )
        sys.exit(exc.returncode)
