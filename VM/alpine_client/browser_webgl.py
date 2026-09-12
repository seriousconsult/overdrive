"""Keep Chromium on a software GL path without 3D passthrough.

Hardware/3D acceleration would leak hypervisor renderer strings. Chromium still
draws WebGL via SwiftShader on the Xvfb display; detections spoof Intel ANGLE
names in-page.
``LIBGL_ALWAYS_SOFTWARE=1`` forces Mesa softpipe/llvmpipe even if a probe
ever drops ``--use-gl=swiftshader``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "GUEST_WEBGL_PROFILE_D",
    "ClientBrowserWebGLAssets",
    "stage_client_browser_webgl",
    "virt_customize_browser_webgl_args",
]

GUEST_WEBGL_PROFILE_D = "/etc/profile.d/97-overdrive-webgl.sh"

_WEBGL_PROFILE = """\
# Overdrive: software GL only. Do not enable guest 3D acceleration.
export LIBGL_ALWAYS_SOFTWARE=1
"""


@dataclass(frozen=True)
class ClientBrowserWebGLAssets:
    """Host path virt-customize copies into the Alpine disk image."""

    profile_d: Path


def stage_client_browser_webgl(work_root: Path) -> ClientBrowserWebGLAssets:
    """Write the software-GL profile snippet for virt-customize."""
    path = work_root / "97-overdrive-webgl.sh"
    path.write_text(_WEBGL_PROFILE, encoding="utf-8", newline="\n")
    print("[overdrive] Staged LIBGL_ALWAYS_SOFTWARE profile (no guest GUI / 3D).")
    return ClientBrowserWebGLAssets(profile_d=path)


def virt_customize_browser_webgl_args(assets: ClientBrowserWebGLAssets) -> list[str]:
    """virt-customize flags to install the software-GL profile snippet."""
    return [
        "--copy-in",
        f"{assets.profile_d}:/etc/profile.d",
        "--run-command",
        "grep -q '^LIBGL_ALWAYS_SOFTWARE=' /etc/environment 2>/dev/null || "
        "echo LIBGL_ALWAYS_SOFTWARE=1 >> /etc/environment",
    ]
