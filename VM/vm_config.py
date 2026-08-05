"""
Configuration constants for the VirtualBox lab VMs.
"""

from __future__ import annotations

import os
from pathlib import Path


VM_ENV_PATH = Path(__file__).resolve().with_name(".env")


def _load_vm_env(path: Path = VM_ENV_PATH) -> None:
    """Load VM secrets from VM/.env without overriding explicit environment variables."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError(f"Could not read VM password env file {path}: {exc}") from exc

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key:
            os.environ.setdefault(key, value)


def vm_secret(name: str, *, min_len: int = 24) -> str:
    """Return a required VM secret from environment / VM/.env."""
    value = (os.environ.get(name) or "").strip()
    if not value:
        raise RuntimeError(
            f"Missing required VM secret {name}. Add it to {VM_ENV_PATH} "
            "or export it before creating VMs."
        )
    if len(value) < min_len:
        raise RuntimeError(f"VM secret {name} is too short; use at least {min_len} characters.")
    return value


_load_vm_env()

# Mullvad public DNS-over-TLS (DoT). Plain UDP/53 is refused; use stubby on OpenWrt.
# https://mullvad.net/en/help/dns-over-https-and-dns-over-tls
MULLVAD_DOT_RESOLVERS: tuple[tuple[str, str], ...] = (
    ("194.242.2.2", "dns.mullvad.net"),  # unfiltered
    ("194.242.2.3", "adblock.dns.mullvad.net"),  # adblock
)
MULLVAD_DOT_PORT = 853
OPENWRT_LAN_DNS = "192.168.1.1"
OPENWRT_STUBBY_LISTEN = "127.0.0.1#5453"

ALPINE_CLIENT_ROOT_PASSWORD_ENV = "ALPINE_CLIENT_ROOT_PASSWORD"
OPENWRT_ROOT_PASSWORD_ENV = "OPENWRT_ROOT_PASSWORD"
OSBOXES_LOGIN_PASSWORD_ENV = "OSBOXES_LOGIN_PASSWORD"


def alpine_client_root_password() -> str:
    return vm_secret(ALPINE_CLIENT_ROOT_PASSWORD_ENV)


def openwrt_root_password() -> str:
    return vm_secret(OPENWRT_ROOT_PASSWORD_ENV)


def osboxes_login_password() -> str:
    return vm_secret(OSBOXES_LOGIN_PASSWORD_ENV)
