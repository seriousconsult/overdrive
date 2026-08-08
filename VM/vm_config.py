"""
Configuration constants for the VirtualBox lab VMs.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path


VM_ENV_PATH = Path(__file__).resolve().with_name(".env")

# Verizon FiOS G3100 (Arcadyan OEM). Field OUI commonly seen on G3100 LAN/WAN.
# Note: Greenwave Systems made the earlier G1100; G3100 hardware is Arcadyan.
# https://wikidevi.wi-cat.ru/Verizon_G3100
G3100_MAC_OUI = "3cbdc5"

# Common PC NIC OUI (Realtek) for the Alpine LAN client — not VirtualBox 080027,
# and not the router G3100 OUI, so router vs client stay distinct on the wire.
CLIENT_NIC_OUI = "00e04c"


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
    return vm_secret(ALPINE_CLIENT_ROOT_PASSWORD_ENV, min_len=1)


def openwrt_root_password() -> str:
    return vm_secret(OPENWRT_ROOT_PASSWORD_ENV)


def osboxes_login_password() -> str:
    return vm_secret(OSBOXES_LOGIN_PASSWORD_ENV)


def random_g3100_mac_vbox(*, oui: str = G3100_MAC_OUI) -> str:
    """Return a random G3100-style MAC as 12 hex digits for ``VBoxManage --macaddressN``."""
    return _random_mac_vbox(oui)


def random_client_mac_vbox(*, oui: str = CLIENT_NIC_OUI) -> str:
    """Return a random consumer-PC-style MAC as 12 hex digits for ``VBoxManage --macaddressN``."""
    return _random_mac_vbox(oui)


def _random_mac_vbox(oui: str) -> str:
    prefix = oui.lower().replace(":", "").replace("-", "")
    if len(prefix) != 6 or any(c not in "0123456789abcdef" for c in prefix):
        raise ValueError(f"Invalid OUI {oui!r}; expected 3 hex octets")
    # Avoid all-zero / all-FF NIC suffixes (invalid / broadcast-ish).
    while True:
        nic = secrets.token_hex(3)
        if nic not in ("000000", "ffffff"):
            return prefix + nic


def format_mac_colon(mac_hex12: str) -> str:
    """``aabbccddeeff`` → ``aa:bb:cc:dd:ee:ff``."""
    m = mac_hex12.lower().replace(":", "").replace("-", "")
    if len(m) != 12:
        raise ValueError(f"Expected 12 hex digits, got {mac_hex12!r}")
    return ":".join(m[i : i + 2] for i in range(0, 12, 2))
