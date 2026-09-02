"""Stage guest files and run virt-customize prime steps."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import shutil
import subprocess
import time

from VM.alpine_client.browser_audio import (
    ClientBrowserAudioAssets,
    stage_client_browser_audio,
    virt_customize_browser_audio_args,
)
from VM.alpine_client.browser_cookies import (
    ClientBrowserCookieAssets,
    stage_client_browser_cookies,
    virt_customize_browser_cookie_args,
)
from VM.alpine_client.browser_fonts import (
    ClientBrowserFontAssets,
    stage_client_browser_fonts,
    virt_customize_browser_font_args,
)
from VM.alpine_client.browser_webgl import (
    ClientBrowserWebGLAssets,
    stage_client_browser_webgl,
    virt_customize_browser_webgl_args,
)
from VM.kali_client.client_config import CLIENT_GUEST_HOSTNAME, REPO_ROOT
from VM.kali_client.guest_scripts import (
    ASSERT_NO_REMOTE_BOOT_HOOKS_COMMAND,
    CLEAN_CLIENT_PRIME_HELPERS_COMMAND,
    CLIENT_IDENTITY_COMMAND,
    CLIENT_IP_TIMEZONE_SCRIPT,
    CLIENT_IP_TIMEZONE_SERVICE,
    CONFIGURE_CLIENT_SERVICES_AND_BOOT_COMMAND,
    INSTALL_DETECTION_LIBRARIES_COMMAND,
    LAB_NET_TROUBLESHOOT_SCRIPT,
    LAB_NET_UP_SCRIPT,
    LAB_NET_UP_SERVICE,
    LAUNCH_IDENTITY_SCRIPT,
    LAUNCH_IDENTITY_SERVICE,
    REMOVE_CLIENT_INSTALL_PY_COMMAND,
)
from VM.kali_client.image_tools import libguestfs_env, require_vdi_prime_tools
from VM.kali_client.kali_client_hardening import (
    CLIENT_FIREWALL_SCRIPT,
    CLIENT_FIREWALL_SERVICE,
    CLIENT_HARDENING_SCRIPT,
)
from VM.kali_client.package_assets import client_package_install_script
from VM.vm_config import kali_client_root_password

_DEBUG_LOG_PATH = Path(__file__).resolve().parents[2] / "debug-52b023.log"


def _agent_debug_log(*, hypothesis_id: str, location: str, message: str, data: dict) -> None:
    # #region agent log
    try:
        payload = {
            "sessionId": "52b023",
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data,
            "timestamp": int(time.time() * 1000),
        }
        with _DEBUG_LOG_PATH.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(payload) + "\n")
    except OSError:
        pass
    # #endregion


__all__ = [
    "ClientPrimeAssets",
    "configure_client_guest_services_and_boot",
    "copy_client_payloads_and_service_assets",
    "harden_and_clean_client_guest_image",
    "install_client_detection_libraries",
    "prepare_client_prime_assets",
    "prime_client_identity_and_base_packages",
    "prime_client_vdi_for_intnet_lab",
    "run_client_virt_customize",
]


@dataclass(frozen=True)
class ClientPrimeAssets:
    troubleshoot_host: Path
    lab_net_up_host: Path
    lab_net_up_service_host: Path
    client_firewall_host: Path
    client_firewall_service_host: Path
    hardening_script_host: Path
    package_script_host: Path
    timezone_script_host: Path
    timezone_service_host: Path
    launch_identity_host: Path
    launch_identity_service_host: Path
    root_password_file: Path
    local_host_payload_host: Path
    detections_payload_host: Path
    setup_venv_host: Path
    browser_fonts: ClientBrowserFontAssets
    browser_audio: ClientBrowserAudioAssets
    browser_webgl: ClientBrowserWebGLAssets
    browser_cookies: ClientBrowserCookieAssets


def prepare_client_prime_assets(work_root: Path) -> ClientPrimeAssets:
    """Write host-side files that later virt-customize stages copy into the guest."""
    troubleshoot_host = work_root / "lab_net_troubleshoot.sh"
    troubleshoot_host.write_text(LAB_NET_TROUBLESHOOT_SCRIPT, encoding="utf-8", newline="\n")

    lab_net_up_host = work_root / "lab-net-up"
    lab_net_up_host.write_text(LAB_NET_UP_SCRIPT, encoding="utf-8", newline="\n")

    lab_net_up_service_host = work_root / "lab-net-up.service.tmp"
    lab_net_up_service_host.write_text(LAB_NET_UP_SERVICE, encoding="utf-8", newline="\n")

    client_firewall_host = work_root / "client-firewall"
    client_firewall_host.write_text(CLIENT_FIREWALL_SCRIPT, encoding="utf-8", newline="\n")

    client_firewall_service_host = work_root / "client-firewall.service.tmp"
    client_firewall_service_host.write_text(CLIENT_FIREWALL_SERVICE, encoding="utf-8", newline="\n")

    hardening_script_host = work_root / "harden-client.sh"
    hardening_script_host.write_text(CLIENT_HARDENING_SCRIPT, encoding="utf-8", newline="\n")
    hardening_script_host.chmod(0o700)

    package_script_host = work_root / "install-client-packages.sh"
    package_script_host.write_text(
        client_package_install_script(),
        encoding="utf-8",
        newline="\n",
    )
    package_script_host.chmod(0o700)

    timezone_script_host = work_root / "overdrive-ip-timezone"
    timezone_script_host.write_text(CLIENT_IP_TIMEZONE_SCRIPT, encoding="utf-8", newline="\n")

    timezone_service_host = work_root / "overdrive-ip-timezone.service.tmp"
    timezone_service_host.write_text(CLIENT_IP_TIMEZONE_SERVICE, encoding="utf-8", newline="\n")

    launch_identity_host = work_root / "overdrive-launch-identity"
    launch_identity_host.write_text(LAUNCH_IDENTITY_SCRIPT, encoding="utf-8", newline="\n")

    launch_identity_service_host = work_root / "overdrive-launch-identity.service.tmp"
    launch_identity_service_host.write_text(LAUNCH_IDENTITY_SERVICE, encoding="utf-8", newline="\n")

    root_password_file = work_root / "kali-root-password"
    root_password_file.write_text(kali_client_root_password(), encoding="utf-8", newline="\n")
    root_password_file.chmod(0o600)

    local_host_payload_host = work_root / "local_host"
    if local_host_payload_host.exists():
        shutil.rmtree(local_host_payload_host)
    detections_payload_host = work_root / "detections"
    if detections_payload_host.exists():
        shutil.rmtree(detections_payload_host)
    shutil.copytree(
        Path(REPO_ROOT) / "local_host",
        local_host_payload_host,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    shutil.copytree(
        Path(REPO_ROOT) / "detections",
        detections_payload_host,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    setup_venv_host = work_root / "install.py"
    shutil.copy2(Path(REPO_ROOT) / "install.py", setup_venv_host)
    browser_fonts = stage_client_browser_fonts(work_root)
    browser_audio = stage_client_browser_audio(work_root)
    browser_webgl = stage_client_browser_webgl(work_root)
    browser_cookies = stage_client_browser_cookies(work_root)

    return ClientPrimeAssets(
        troubleshoot_host=troubleshoot_host,
        lab_net_up_host=lab_net_up_host,
        lab_net_up_service_host=lab_net_up_service_host,
        client_firewall_host=client_firewall_host,
        client_firewall_service_host=client_firewall_service_host,
        hardening_script_host=hardening_script_host,
        package_script_host=package_script_host,
        timezone_script_host=timezone_script_host,
        timezone_service_host=timezone_service_host,
        launch_identity_host=launch_identity_host,
        launch_identity_service_host=launch_identity_service_host,
        root_password_file=root_password_file,
        local_host_payload_host=local_host_payload_host,
        detections_payload_host=detections_payload_host,
        setup_venv_host=setup_venv_host,
        browser_fonts=browser_fonts,
        browser_audio=browser_audio,
        browser_webgl=browser_webgl,
        browser_cookies=browser_cookies,
    )


def run_client_virt_customize(
    vdi_linux: str,
    args: list[str],
    *,
    skip_prime: bool,
    network: bool = False,
) -> None:
    vc = require_vdi_prime_tools(skip_prime=skip_prime)
    virt_env = libguestfs_env()
    command = [vc, "-a", vdi_linux]
    if network:
        command.append("--network")
    command.extend(args)
    # #region agent log
    _agent_debug_log(
        hypothesis_id="H3",
        location="guest_prime.py:run_client_virt_customize",
        message="virt-customize start",
        data={"vdi_linux": vdi_linux, "network": network, "arg_count": len(args)},
    )
    # #endregion
    result = subprocess.run(command, capture_output=True, text=True, env=virt_env)
    # #region agent log
    _agent_debug_log(
        hypothesis_id="H3",
        location="guest_prime.py:run_client_virt_customize",
        message="virt-customize result",
        data={
            "returncode": result.returncode,
            "stdout_tail": (result.stdout or "")[-800:],
            "stderr_tail": (result.stderr or "")[-800:],
        },
    )
    # #endregion
    if result.returncode != 0:
        detail = ((result.stderr or "") + (result.stdout or "")).strip()
        raise RuntimeError(
            f"virt-customize failed (exit {result.returncode}).\n{detail[-4000:]}"
        ) from subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)


def prime_client_identity_and_base_packages(
    vdi_linux: str,
    assets: ClientPrimeAssets,
    *,
    skip_prime: bool,
) -> None:
    """Set guest identity/password; OS packages are installed by install.py."""
    run_client_virt_customize(
        vdi_linux,
        [
            "--hostname",
            CLIENT_GUEST_HOSTNAME,
            "--root-password",
            f"file:{assets.root_password_file}",
            "--run-command",
            CLIENT_IDENTITY_COMMAND,
        ],
        skip_prime=skip_prime,
        network=False,
    )


def copy_client_payloads_and_service_assets(
    vdi_linux: str,
    assets: ClientPrimeAssets,
    *,
    skip_prime: bool,
) -> None:
    """Copy local payloads and service scripts into the guest image."""
    customize_args = [
        "--copy-in",
        f"{assets.troubleshoot_host}:/usr/local/sbin",
        "--copy-in",
        f"{assets.lab_net_up_host}:/usr/local/sbin",
        "--copy-in",
        f"{assets.lab_net_up_service_host}:/etc/systemd/system",
        "--copy-in",
        f"{assets.client_firewall_host}:/usr/local/sbin",
        "--copy-in",
        f"{assets.client_firewall_service_host}:/etc/systemd/system",
        "--copy-in",
        f"{assets.timezone_script_host}:/usr/local/sbin",
        "--copy-in",
        f"{assets.timezone_service_host}:/etc/systemd/system",
        "--copy-in",
        f"{assets.launch_identity_host}:/usr/local/sbin",
        "--copy-in",
        f"{assets.launch_identity_service_host}:/etc/systemd/system",
        "--copy-in",
        f"{assets.local_host_payload_host}:/root",
        "--copy-in",
        f"{assets.detections_payload_host}:/root",
        "--copy-in",
        f"{assets.setup_venv_host}:/root",
    ]
    customize_args.extend(virt_customize_browser_font_args(assets.browser_fonts))
    customize_args.extend(virt_customize_browser_audio_args(assets.browser_audio))
    customize_args.extend(virt_customize_browser_webgl_args(assets.browser_webgl))
    customize_args.extend(virt_customize_browser_cookie_args(assets.browser_cookies))
    run_client_virt_customize(
        vdi_linux,
        customize_args,
        skip_prime=skip_prime,
    )


def install_client_detection_libraries(
    vdi_linux: str,
    assets: ClientPrimeAssets,
    *,
    skip_prime: bool,
) -> None:
    """Run repo install.py inside the guest; installs network/detection libraries."""
    customize_args = [
        "--run-command",
        INSTALL_DETECTION_LIBRARIES_COMMAND,
        "--run-command",
        REMOVE_CLIENT_INSTALL_PY_COMMAND,
        "--run-command",
        "fc-cache -f 2>/dev/null || true",
    ]
    customize_args.extend(virt_customize_browser_cookie_args(assets.browser_cookies))
    customize_args.extend(virt_customize_browser_audio_args(assets.browser_audio))
    run_client_virt_customize(
        vdi_linux,
        customize_args,
        skip_prime=skip_prime,
        network=True,
    )


def configure_client_guest_services_and_boot(
    vdi_linux: str,
    *,
    skip_prime: bool,
) -> None:
    """Wire copied scripts into systemd and make the bootloader serial/unattended."""
    run_client_virt_customize(
        vdi_linux,
        [
            "--run-command",
            CONFIGURE_CLIENT_SERVICES_AND_BOOT_COMMAND,
        ],
        skip_prime=skip_prime,
    )


def harden_and_clean_client_guest_image(
    vdi_linux: str,
    assets: ClientPrimeAssets,
    *,
    skip_prime: bool,
) -> None:
    """Apply privacy hardening and prove unwanted remote-login hooks are absent."""
    run_client_virt_customize(
        vdi_linux,
        [
            "--run",
            str(assets.hardening_script_host),
            "--run-command",
            ASSERT_NO_REMOTE_BOOT_HOOKS_COMMAND,
            "--run-command",
            CLEAN_CLIENT_PRIME_HELPERS_COMMAND,
        ],
        skip_prime=skip_prime,
    )


def prime_client_vdi_for_intnet_lab(
    vdi_linux: str,
    work_root: Path,
    *,
    skip_prime: bool,
) -> bool:
    """Compatibility wrapper for older callers; setup_clientk_vm uses discrete steps."""
    print("Injecting custom configuration and packages into Kali image...")
    assets = prepare_client_prime_assets(work_root)
    prime_client_identity_and_base_packages(vdi_linux, assets, skip_prime=skip_prime)
    copy_client_payloads_and_service_assets(vdi_linux, assets, skip_prime=skip_prime)
    install_client_detection_libraries(vdi_linux, assets, skip_prime=skip_prime)
    configure_client_guest_services_and_boot(vdi_linux, skip_prime=skip_prime)
    harden_and_clean_client_guest_image(vdi_linux, assets, skip_prime=skip_prime)
    return True
