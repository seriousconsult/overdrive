"""Stage a dummy ALSA default device into the test client image (no GUI).

Headless Chromium's live ``AudioContext`` still talks to a default PCM. Without
a card, construction/resume can fail and the audio_fingerprint probe falls
through to zeros. A userspace ``type null`` device needs ``alsa-plugins``, not
``snd-dummy``, PulseAudio, or X11. OfflineAudioContext rendering is CPU-side
and does not need a speaker.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "GUEST_ASOUND_CONF",
    "GUEST_ALSA_PROFILE",
    "ClientBrowserAudioAssets",
    "stage_client_browser_audio",
    "virt_customize_browser_audio_args",
]

GUEST_ASOUND_CONF = "/etc/asound.conf"
GUEST_ALSA_PROFILE = "/etc/profile.d/99-overdrive-alsa.sh"

_ASOUND_CONF = """\
# Overdrive: null default PCM so headless Chromium can open AudioContext
# without a sound card, Pulse, or a display server.
pcm.!default {
    type null
}
ctl.!default {
    type null
}
"""

_ALSA_PROFILE = """\
# Overdrive headless client: route Chromium through our null ALSA default.
# Do not use PulseAudio or a desktop sound server.
unset PULSE_SERVER
unset PULSE_COOKIE
export ALSA_CARD=default
export ALSA_PCM_CARD=default
"""


@dataclass(frozen=True)
class ClientBrowserAudioAssets:
    """Host paths virt-customize copies into the Alpine VDI."""

    asound_conf: Path
    alsa_profile: Path


def stage_client_browser_audio(work_root: Path) -> ClientBrowserAudioAssets:
    """Write ALSA assets into ``work_root`` for virt-customize."""
    conf_path = work_root / "asound.conf"
    conf_path.write_text(_ASOUND_CONF, encoding="utf-8", newline="\n")

    profile_path = work_root / "99-overdrive-alsa.sh"
    profile_path.write_text(_ALSA_PROFILE, encoding="utf-8", newline="\n")

    print("[overdrive] Staged dummy ALSA asound.conf (null PCM, no GUI audio stack).")
    return ClientBrowserAudioAssets(asound_conf=conf_path, alsa_profile=profile_path)


def virt_customize_browser_audio_args(assets: ClientBrowserAudioAssets) -> list[str]:
    """virt-customize flags to install ALSA config for headless Chromium audio."""
    return [
        "--mkdir",
        "/etc/profile.d",
        "--copy-in",
        f"{assets.asound_conf}:/etc",
        "--copy-in",
        f"{assets.alsa_profile}:/etc/profile.d",
        "--run-command",
        "chmod 0644 /etc/asound.conf /etc/profile.d/99-overdrive-alsa.sh",
    ]
