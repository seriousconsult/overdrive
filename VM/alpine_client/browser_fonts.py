"""Stage Windows core fonts into the test client image.

Chromium still uses fontconfig under the client Xvfb display. Canvas
``measureText`` only counts a family as present when its width differs from
generic CSS fallbacks. Distro fonts (DejaVu/Liberation) often *are* those
fallbacks, so they score 0 hits. Copying real Arial/Calibri/Georgia/… from the
Windows host makes the existing font_enumeration probe see a Linux-plausible
surface.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "CLIENT_WINDOWS_FONT_DIR_NAME",
    "GUEST_WINDOWS_FONT_DIR",
    "GUEST_FONTCONFIG_CONF",
    "ClientBrowserFontAssets",
    "stage_client_browser_fonts",
    "virt_customize_browser_font_args",
]

CLIENT_WINDOWS_FONT_DIR_NAME = "overdrive-windows-fonts"
GUEST_WINDOWS_FONT_DIR = f"/usr/share/fonts/{CLIENT_WINDOWS_FONT_DIR_NAME}"
GUEST_FONTCONFIG_CONF = "/etc/fonts/conf.d/99-overdrive-windows-fonts.conf"
_MIN_COPIED_FONTS = 8

# Filenames under C:\\Windows\\Fonts (lowercase). Enough named families for
# font_enumeration's Linux bar (≥8 distinguishable hits) sit at the front of
# CANDIDATE_FONTS: Arial, Calibri, Cambria, Comic Sans, Consolas, Courier New,
# Georgia, Tahoma, Times New Roman, Trebuchet, Verdana, Segoe UI.
WINDOWS_BROWSER_FONT_FILENAMES = (
    "arial.ttf",
    "arialbd.ttf",
    "arialbi.ttf",
    "ariali.ttf",
    "ariblk.ttf",
    "comic.ttf",
    "comicbd.ttf",
    "comici.ttf",
    "comicz.ttf",
    "cour.ttf",
    "courbd.ttf",
    "courbi.ttf",
    "couri.ttf",
    "georgia.ttf",
    "georgiab.ttf",
    "georgiai.ttf",
    "georgiaz.ttf",
    "impact.ttf",
    "times.ttf",
    "timesbd.ttf",
    "timesbi.ttf",
    "timesi.ttf",
    "trebuc.ttf",
    "trebucbd.ttf",
    "trebucbi.ttf",
    "trebucit.ttf",
    "verdana.ttf",
    "verdanab.ttf",
    "verdanai.ttf",
    "verdanaz.ttf",
    "webdings.ttf",
    "calibri.ttf",
    "calibrib.ttf",
    "calibrii.ttf",
    "calibriz.ttf",
    "calibril.ttf",
    "calibrili.ttf",
    "cambria.ttc",
    "cambriab.ttf",
    "cambriai.ttf",
    "cambriaz.ttf",
    "candara.ttf",
    "candarab.ttf",
    "candarai.ttf",
    "candaraz.ttf",
    "candaral.ttf",
    "candarali.ttf",
    "consola.ttf",
    "consolab.ttf",
    "consolai.ttf",
    "consolaz.ttf",
    "lucon.ttf",
    "l_10646.ttf",
    "micross.ttf",
    "pala.ttf",
    "palab.ttf",
    "palabi.ttf",
    "palai.ttf",
    "segoeui.ttf",
    "segoeuib.ttf",
    "segoeuii.ttf",
    "segoeuiz.ttf",
    "segoeuil.ttf",
    "seguili.ttf",
    "segoeuisl.ttf",
    "seguisli.ttf",
    "seguisb.ttf",
    "seguisbi.ttf",
    "seguiemj.ttf",
    "seguisym.ttf",
    "tahoma.ttf",
    "tahomabd.ttf",
    "wingding.ttf",
)

_FONTCONFIG_CONF = f"""\
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <dir>{GUEST_WINDOWS_FONT_DIR}</dir>
</fontconfig>
"""


@dataclass(frozen=True)
class ClientBrowserFontAssets:
    """Host paths virt-customize copies into the Alpine VDI."""

    fonts_dir: Path
    fontconfig_conf: Path


def _host_windows_font_dirs() -> list[Path]:
    candidates = [
        Path("/mnt/c/Windows/Fonts"),
        Path("/mnt/c/windows/Fonts"),
    ]
    windir = os.environ.get("WINDIR") or os.environ.get("windir")
    if windir:
        candidates.append(Path(windir) / "Fonts")
    return candidates


def stage_client_browser_fonts(work_root: Path) -> ClientBrowserFontAssets:
    """Copy allowlisted Windows TTFs into ``work_root``; required for Alpine prime."""
    source_dir = next((path for path in _host_windows_font_dirs() if path.is_dir()), None)
    if source_dir is None:
        searched = ", ".join(str(path) for path in _host_windows_font_dirs())
        raise RuntimeError(
            "Test client needs Windows core fonts for the browser fonts probe, "
            f"but no Fonts directory was found ({searched})."
        )

    available = {
        path.name.lower(): path
        for path in source_dir.iterdir()
        if path.is_file() and path.suffix.lower() in {".ttf", ".ttc", ".otf"}
    }
    selected = [available[name] for name in WINDOWS_BROWSER_FONT_FILENAMES if name in available]
    if len(selected) < _MIN_COPIED_FONTS:
        raise RuntimeError(
            f"Test client needs at least {_MIN_COPIED_FONTS} allowlisted Windows fonts "
            f"from {source_dir}; found {len(selected)}."
        )

    fonts_dir = work_root / CLIENT_WINDOWS_FONT_DIR_NAME
    if fonts_dir.exists():
        shutil.rmtree(fonts_dir)
    fonts_dir.mkdir(parents=True)
    for source in selected:
        shutil.copy2(source, fonts_dir / source.name)

    conf_path = work_root / "99-overdrive-windows-fonts.conf"
    conf_path.write_text(_FONTCONFIG_CONF, encoding="utf-8", newline="\n")

    missing = len(WINDOWS_BROWSER_FONT_FILENAMES) - len(selected)
    extra = f", {missing} allowlisted files missing." if missing else "."
    print(
        f"[overdrive] Staged Windows browser fonts: {len(selected)} copied from {source_dir}{extra}"
    )
    return ClientBrowserFontAssets(fonts_dir=fonts_dir, fontconfig_conf=conf_path)


def virt_customize_browser_font_args(assets: ClientBrowserFontAssets) -> list[str]:
    """virt-customize flags to install fonts + fontconfig and refresh the cache."""
    return [
        "--run-command",
        "mkdir -p /usr/share/fonts /etc/fonts/conf.d /var/cache/fontconfig",
        "--copy-in",
        f"{assets.fonts_dir}:/usr/share/fonts",
        "--copy-in",
        f"{assets.fontconfig_conf}:/etc/fonts/conf.d",
        "--run-command",
        f"chmod -R a+rX {GUEST_WINDOWS_FONT_DIR} 2>/dev/null || true",
        "--run-command",
        "fc-cache -f 2>/dev/null || true",
    ]
