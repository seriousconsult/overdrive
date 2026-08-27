"""Allow first-party cookies and local storage for Chromium probes.

Each DevTools probe uses a temporary profile, so a Chromium *managed policy* is
applied instead of a shared user-data-dir (which would leak cookies across probes).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "GUEST_COOKIE_POLICY_DIR",
    "GUEST_COOKIE_POLICY_FILE",
    "ClientBrowserCookieAssets",
    "stage_client_browser_cookies",
    "virt_customize_browser_cookie_args",
]

GUEST_COOKIE_POLICY_DIR = "/etc/chromium/policies/managed"
GUEST_COOKIE_POLICY_FILE = f"{GUEST_COOKIE_POLICY_DIR}/overdrive-cookies.json"

_COOKIE_POLICY = {
    "DefaultCookiesSetting": 1,
    "DefaultLocalStorageSetting": 1,
    "CookieControlsMode": 0,
}


@dataclass(frozen=True)
class ClientBrowserCookieAssets:
    """Host path virt-customize copies into the Alpine VDI."""

    policy_json: Path


def stage_client_browser_cookies(work_root: Path) -> ClientBrowserCookieAssets:
    """Write the Chromium managed cookie policy for virt-customize."""
    path = work_root / "overdrive-cookies.json"
    path.write_text(json.dumps(_COOKIE_POLICY, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("[overdrive] Staged Chromium managed policy (allow first-party cookies/storage).")
    return ClientBrowserCookieAssets(policy_json=path)


def virt_customize_browser_cookie_args(assets: ClientBrowserCookieAssets) -> list[str]:
    """virt-customize flags to install the Chromium cookie policy."""
    return [
        "--mkdir",
        GUEST_COOKIE_POLICY_DIR,
        "--copy-in",
        f"{assets.policy_json}:{GUEST_COOKIE_POLICY_DIR}",
    ]
