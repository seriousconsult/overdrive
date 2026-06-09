#!/usr/bin/env python3
"""
Audio Context Fingerprint Detection

Detects audio context fingerprinting by probing the browser's
Web Audio / AudioContext APIs and checking whether audio rendering is
available, stable, and consistent with a normal residential browser.

Measured attributes:
- AudioContext / OfflineAudioContext availability.
- oscillator/analyser pipeline support.
- ability to render audio data and compute a stable fingerprint.
- surrounding browser profile signals like navigator.webdriver,
  navigator.languages, plugins, and screen metrics.

Score: 1-5
1 = normal browser audio profile and no strong automation signals
2 = mostly normal audio profile with mild browser anomalies
3 = inconclusive or mixed audio/browser result
4 = unusual or blocked audio APIs for a home browser
5 = strongly non-home-like automation/browser fingerprinting profile
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_browser import (
    DEFAULT_TIMEOUT,
    build_driver_with_fallback,
    print_browser_detection_header,
    print_browser_detection_score_footer,
)


AUDIO_PROBE_JS = r"""
const done = arguments[arguments.length - 1];

function toHex(buffer) {
  const view = new Uint8Array(buffer);
  return Array.from(view)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function normalizeSample(value) {
  return Math.round((Number(value) || 0) * 1000000) / 1000000;
}

function floatArrayToString(array) {
  return Array.from(array).slice(0, 128).map(normalizeSample).join(",");
}

async function sha256(text) {
  if (!(window.crypto && window.crypto.subtle && typeof window.crypto.subtle.digest === "function")) {
    return null;
  }
  const encoded = new TextEncoder().encode(text);
  const digest = await window.crypto.subtle.digest("SHA-256", encoded);
  return toHex(digest);
}

async function renderOffline(context) {
  const oscillator = context.createOscillator();
  const gain = context.createGain();
  oscillator.type = "triangle";
  oscillator.frequency.value = 440;
  gain.gain.value = 0.2;
  oscillator.connect(gain);
  gain.connect(context.destination);
  oscillator.start(0);
  const buffer = await context.startRendering();
  const data = buffer.getChannelData(0);
  const prefix = floatArrayToString(data);
  const hash = await sha256(prefix);
  return {
    outputPrefix: prefix,
    hash,
    average: data.reduce((acc, value) => acc + value, 0) / data.length,
    zeroOutput: data.every((value) => normalizeSample(value) === 0),
  };
}

async function renderOnline(context) {
  const analyser = context.createAnalyser();
  const gain = context.createGain();
  const oscillator = context.createOscillator();
  oscillator.type = "triangle";
  oscillator.frequency.value = 440;
  gain.gain.value = 0.15;
  oscillator.connect(gain);
  gain.connect(analyser);
  if (context.destination) {
    analyser.connect(context.destination);
  }
  oscillator.start(0);
  if (typeof context.resume === "function") {
    try {
      await context.resume();
    } catch (ignore) {
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 250));
  const buffer = new Float32Array(analyser.fftSize);
  analyser.getFloatTimeDomainData(buffer);
  const prefix = floatArrayToString(buffer);
  const hash = await sha256(prefix);
  try {
    oscillator.stop(0);
  } catch (ignore) {
  }
  return {
    outputPrefix: prefix,
    hash,
    average: buffer.reduce((acc, value) => acc + value, 0) / buffer.length,
    zeroOutput: buffer.every((value) => normalizeSample(value) === 0),
  };
}

function makeProfile() {
  return {
    userAgent: navigator.userAgent || "",
    vendor: navigator.vendor || "",
    platform: navigator.platform || "",
    languages: Array.from(navigator.languages || []),
    language: navigator.language || "",
    webdriver: navigator.webdriver === true,
    pluginsLength: navigator.plugins ? navigator.plugins.length : null,
    mimeTypesLength: navigator.mimeTypes ? navigator.mimeTypes.length : null,
    hardwareConcurrency: navigator.hardwareConcurrency || null,
    deviceMemory: navigator.deviceMemory || null,
    maxTouchPoints: navigator.maxTouchPoints || 0,
    cookieEnabled: navigator.cookieEnabled,
    screenWidth: screen.width || null,
    screenHeight: screen.height || null,
    colorDepth: screen.colorDepth || null,
    pixelDepth: screen.pixelDepth || null,
    outerWidth: window.outerWidth || null,
    outerHeight: window.outerHeight || null,
  };
}

(async () => {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    const OfflineAudioContextClass = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    const apis = {
      audioContext: !!AudioContextClass,
      offlineAudioContext: !!OfflineAudioContextClass,
      webkitAudioContext: Boolean(window.webkitAudioContext),
      hasOscillator: false,
      hasAnalyser: false,
      cryptoDigest: Boolean(window.crypto && window.crypto.subtle && typeof window.crypto.subtle.digest === "function"),
    };
    const profile = makeProfile();

    if (!AudioContextClass && !OfflineAudioContextClass) {
      done({
        ok: true,
        apis,
        profile,
        available: false,
        reason: "AudioContext/OfflineAudioContext unavailable",
      });
      return;
    }

    const buildContext = () => {
      if (OfflineAudioContextClass) {
        return new OfflineAudioContextClass(1, 44100, 44100);
      }
      return new AudioContextClass({ sampleRate: 44100 });
    };

    const sampleResult = async (ctx) => {
      apis.hasOscillator = apis.hasOscillator || typeof ctx.createOscillator === "function";
      apis.hasAnalyser = apis.hasAnalyser || typeof ctx.createAnalyser === "function";
      if (typeof ctx.startRendering === "function") {
        return renderOffline(ctx);
      }
      if (typeof ctx.createAnalyser === "function" && typeof ctx.createOscillator === "function") {
        return renderOnline(ctx);
      }
      return {
        outputPrefix: null,
        hash: null,
        average: null,
        zeroOutput: true,
        reason: "Audio context exists but render pipeline is unavailable",
      };
    };

    const firstCtx = buildContext();
    const first = await sampleResult(firstCtx);
    const secondCtx = buildContext();
    const second = await sampleResult(secondCtx);

    const stable = first.hash && second.hash ? first.hash === second.hash : null;
    const hash = first.hash || second.hash || null;
    const zeroOutput = Boolean(first.zeroOutput && second.zeroOutput);

    done({
      ok: true,
      apis,
      profile,
      available: true,
      stable,
      hash,
      average: first.average,
      zeroOutput,
      reason: hash ? "Audio probe completed" : "Audio probe completed without digest support",
    });
  } catch (e) {
    done({ ok: false, error: String(e && e.message ? e.message : e) });
  }
})();
"""


def _browser_profile_issues(profile: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return ``(strong_issues, soft_issues)`` for browser-profile coherence."""
    strong: list[str] = []
    soft: list[str] = []

    ua = str(profile.get("userAgent") or "")
    vendor = str(profile.get("vendor") or "")
    languages = profile.get("languages") or []
    plugins_len = profile.get("pluginsLength")
    color_depth = profile.get("colorDepth")
    width = profile.get("screenWidth")
    height = profile.get("screenHeight")
    outer_width = profile.get("outerWidth")
    outer_height = profile.get("outerHeight")

    ua_lower = ua.lower()
    is_chrome = "chrome/" in ua_lower or "chromium/" in ua_lower or "edg/" in ua_lower
    is_firefox = "firefox/" in ua_lower
    is_safari = "safari/" in ua_lower and "chrome/" not in ua_lower

    if profile.get("webdriver"):
        strong.append("navigator.webdriver is true")
    if "headless" in ua_lower:
        strong.append("User-Agent exposes headless browser")
    if not any((is_chrome, is_firefox, is_safari)):
        strong.append("User-Agent does not look like a common residential browser")

    if is_chrome and "google inc" not in vendor.lower() and "microsoft" not in vendor.lower():
        soft.append("Chrome-like UA has an unusual navigator.vendor")
    if not languages:
        soft.append("navigator.languages is empty")
    if plugins_len == 0 and (is_chrome or is_firefox):
        soft.append("navigator.plugins is empty")
    if color_depth not in (24, 30, 32, None):
        soft.append(f"unusual screen color depth {color_depth}")
    if isinstance(width, int) and isinstance(height, int) and (width < 800 or height < 600):
        soft.append(f"unusually small screen size {width}x{height}")
    if outer_width == 0 or outer_height == 0:
        soft.append("window.outerWidth/outerHeight are zero")

    return strong, soft


def _score_audio_result(result: dict[str, Any]) -> tuple[int, str]:
    if not result.get("ok"):
        return 3, f"Inconclusive: audio probe failed: {result.get('error', 'unknown error')}"

    if not result.get("available"):
        reason = result.get("reason", "Audio APIs unavailable or blocked")
        return 4, f"Unusual for a home setup: audio APIs unavailable or blocked ({reason})."

    strong_issues, soft_issues = _browser_profile_issues(result.get("profile") or {})
    reason = result.get("reason") or "audio probe completed"

    if result.get("zeroOutput"):
        return 4, f"Unusual for a home setup: audio rendering returned all zero samples. {reason}."

    if result.get("stable") is False:
        suffix = (
            f" Profile issues: {'; '.join(strong_issues + soft_issues)}." if strong_issues or soft_issues else ""
        )
        return 4, f"Unusual for a home setup: audio output was unstable across repeated probes.{suffix}"

    if strong_issues:
        return 5, (
            "Strongly non-home-like profile: audio APIs are available, but browser signals indicate automation: "
            f"{' ; '.join(strong_issues)}. {reason}."
        )

    if result.get("stable") is True:
        if soft_issues:
            return 2, f"Mostly home-like audio profile with minor browser anomalies: {reason}. Issues: {'; '.join(soft_issues)}."
        return 1, f"Home-like audio profile detected: {reason}."

    return 2, f"Audio APIs are available and probe completed, but the result is not fully definitive. {reason}."


def check_audio_fingerprint() -> tuple[int, str]:
    """
    Check for audio context fingerprinting.
    Returns (score, description)
    """
    try:
        driver = build_driver_with_fallback()
    except Exception as exc:
        return 3, f"Unable to start Selenium WebDriver: {type(exc).__name__}: {exc}"

    try:
        driver.set_script_timeout(DEFAULT_TIMEOUT)
        driver.get("about:blank")
        result = driver.execute_async_script(AUDIO_PROBE_JS)
    except Exception as exc:
        try:
            driver.quit()
        except Exception:
            pass
        return 3, f"Selenium run failed: {type(exc).__name__}: {exc}"

    try:
        driver.quit()
    except Exception:
        pass

    if not isinstance(result, dict):
        return 3, "Audio fingerprint detection returned unexpected data."

    return _score_audio_result(result)


def main():
    print_browser_detection_header("Audio Context Fingerprint Detection")
    score, description = check_audio_fingerprint()
    print_browser_detection_score_footer(score, description)


if __name__ == "__main__":
    main()
