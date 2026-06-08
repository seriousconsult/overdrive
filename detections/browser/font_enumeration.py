#!/usr/bin/env python3
"""Font Enumeration Home-Browser Plausibility Check.

Checks whether browser-exposed font behavior looks like a normal residential
browser setup. Ordinary browsers usually expose a modest set of measurable
system fonts through canvas text metrics; hardened, remote, minimal, or
automated profiles may expose almost none, unstable metrics, or browser signals
that do not match the claimed environment.

Measured attributes:
- Canvas text measurement support through CanvasRenderingContext2D.measureText.
- Presence of common Windows, macOS, Linux, Android, and generic web fonts.
- Stability of repeated text-width probes.
- User-Agent, navigator.webdriver, languages, plugins, platform, vendor, and
  screen attributes for surrounding browser-profile coherence.

Score: 1-5
1 = Strongly home-like browser/font profile
2 = Mostly home-like with minor anomalies
3 = Inconclusive or mixed browser/font profile
4 = Unusual for a home setup
5 = Strongly non-home-like automation/headless profile
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


FONT_PROBE_JS = r"""
const done = arguments[arguments.length - 1];

const CANDIDATE_FONTS = [
  "Arial",
  "Arial Black",
  "Calibri",
  "Cambria",
  "Candara",
  "Comic Sans MS",
  "Consolas",
  "Courier New",
  "Georgia",
  "Impact",
  "Lucida Console",
  "Lucida Sans Unicode",
  "Microsoft Sans Serif",
  "Palatino Linotype",
  "Segoe UI",
  "Tahoma",
  "Times New Roman",
  "Trebuchet MS",
  "Verdana",
  "Webdings",
  "Wingdings",
  "San Francisco",
  "Helvetica Neue",
  "Helvetica",
  "Menlo",
  "Monaco",
  "Avenir",
  "DIN Alternate",
  "Gill Sans",
  "Hoefler Text",
  "Apple Color Emoji",
  "Ubuntu",
  "Ubuntu Mono",
  "DejaVu Sans",
  "DejaVu Serif",
  "DejaVu Sans Mono",
  "Liberation Sans",
  "Liberation Serif",
  "Liberation Mono",
  "Noto Sans",
  "Noto Serif",
  "Noto Color Emoji",
  "Roboto",
  "Droid Sans",
  "Droid Serif",
];

const BASE_FAMILIES = ["monospace", "sans-serif", "serif"];
const TEST_TEXT = "mmmmmmmmmmlliWW@@@12345";

function roundWidth(value) {
  return Math.round(Number(value || 0) * 1000) / 1000;
}

function measureFont(ctx, fontName, baseFamily) {
  ctx.font = "72px " + JSON.stringify(fontName) + ", " + baseFamily;
  return roundWidth(ctx.measureText(TEST_TEXT).width);
}

function measureBase(ctx, baseFamily) {
  ctx.font = "72px " + baseFamily;
  return roundWidth(ctx.measureText(TEST_TEXT).width);
}

function detectFonts() {
  const canvas = document.createElement("canvas");
  canvas.width = 1024;
  canvas.height = 256;
  const ctx = canvas.getContext("2d");
  if (!ctx || typeof ctx.measureText !== "function") {
    return { ok: false, reason: "canvas text measurement unavailable" };
  }

  const baseWidths = {};
  for (const base of BASE_FAMILIES) {
    baseWidths[base] = measureBase(ctx, base);
  }

  const detected = [];
  const measurements = {};
  for (const font of CANDIDATE_FONTS) {
    const widths = {};
    let differs = false;
    for (const base of BASE_FAMILIES) {
      const width = measureFont(ctx, font, base);
      widths[base] = width;
      if (Math.abs(width - baseWidths[base]) > 0.01) {
        differs = true;
      }
    }
    measurements[font] = widths;
    if (differs) {
      detected.push(font);
    }
  }

  const secondPass = [];
  for (const font of CANDIDATE_FONTS) {
    let differs = false;
    for (const base of BASE_FAMILIES) {
      const width = measureFont(ctx, font, base);
      if (Math.abs(width - baseWidths[base]) > 0.01) {
        differs = true;
      }
    }
    if (differs) {
      secondPass.push(font);
    }
  }

  const firstSet = detected.slice().sort().join("|");
  const secondSet = secondPass.slice().sort().join("|");
  return {
    ok: true,
    baseWidths,
    detected,
    detectedCount: detected.length,
    candidateCount: CANDIDATE_FONTS.length,
    stable: firstSet === secondSet,
    measurements,
  };
}

(async () => {
  try {
    const fontProbe = detectFonts();
    const profile = {
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
    done({ ok: true, fontProbe, profile });
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
    platform = str(profile.get("platform") or "")
    languages = profile.get("languages") or []
    plugins_len = profile.get("pluginsLength")
    color_depth = profile.get("colorDepth")
    width = profile.get("screenWidth")
    height = profile.get("screenHeight")
    outer_width = profile.get("outerWidth")
    outer_height = profile.get("outerHeight")

    ua_lower = ua.lower()
    platform_lower = platform.lower()
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
    if "windows" in ua_lower and "win" not in platform_lower:
        soft.append(f"Windows UA has unusual platform {platform or 'empty'}")
    if "mac os x" in ua_lower and "mac" not in platform_lower:
        soft.append(f"macOS UA has unusual platform {platform or 'empty'}")
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


def _expected_font_hits(profile: dict[str, Any]) -> tuple[int, int]:
    """Return loose ``(low, normal)`` thresholds for the claimed platform."""
    ua = str(profile.get("userAgent") or "").lower()
    platform = str(profile.get("platform") or "").lower()
    platform_text = f"{ua} {platform}"

    if "android" in platform_text or "iphone" in platform_text or "ipad" in platform_text:
        return 2, 5
    if "linux" in platform_text or "x11" in platform_text:
        return 4, 8
    if "mac" in platform_text:
        return 5, 10
    if "win" in platform_text:
        return 8, 14
    return 4, 8


def _score_font_result(result: dict[str, Any]) -> tuple[int, str]:
    if not result.get("ok"):
        return 3, f"Inconclusive: font/home-profile probe failed: {result.get('error', 'unknown error')}"

    font_probe = result.get("fontProbe") or {}
    profile = result.get("profile") or {}
    if not isinstance(font_probe, dict) or not isinstance(profile, dict):
        return 3, "Inconclusive: font probe returned unexpected data."

    if not font_probe.get("ok"):
        reason = font_probe.get("reason", "unknown reason")
        return 4, f"Unusual for a home setup: font measurement is unavailable ({reason})."

    detected = font_probe.get("detected") or []
    detected_count = int(font_probe.get("detectedCount") or 0)
    candidate_count = int(font_probe.get("candidateCount") or 0)
    stable = bool(font_probe.get("stable"))
    low_threshold, normal_threshold = _expected_font_hits(profile)
    strong_issues, soft_issues = _browser_profile_issues(profile)

    sample_fonts = ", ".join(str(font) for font in detected[:8]) or "none"
    font_summary = (
        f"detected {detected_count}/{candidate_count} tested fonts"
        f" (sample: {sample_fonts})"
    )

    if strong_issues:
        return 5, (
            "Strongly non-home-like profile: font probing worked, but browser signals indicate automation: "
            f"{'; '.join(strong_issues)}; {font_summary}."
        )
    if not stable:
        suffix = f" Additional signals: {'; '.join(soft_issues)}." if soft_issues else ""
        return 4, f"Unusual for a home setup: repeated font enumeration was unstable; {font_summary}.{suffix}"
    if detected_count == 0:
        return 4, (
            "Unusual for a home setup: no tested system fonts were distinguishable from generic fallbacks. "
            "This can indicate a minimal, hardened, or remote browser profile."
        )
    if detected_count < low_threshold:
        suffix = f" Browser signals: {'; '.join(soft_issues)}." if soft_issues else ""
        return 3, (
            "Mixed home-profile confidence: unusually sparse font surface for the claimed platform; "
            f"{font_summary}.{suffix}"
        )
    if detected_count < normal_threshold or soft_issues:
        issues = f" Minor browser signals: {'; '.join(soft_issues)}." if soft_issues else ""
        return 2, f"Mostly home-like: modest but plausible font surface; {font_summary}.{issues}"

    return 1, f"Strongly home-like: stable, platform-plausible font surface; {font_summary}."


def _try_selenium_font_check(timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str]:
    """Run an in-browser font probe and return ``(score, description)``."""
    try:
        import selenium  # noqa: F401
    except Exception:
        return 4, "Inconclusive: Selenium is unavailable, so the browser font profile could not be probed."

    driver = None
    try:
        driver = build_driver_with_fallback()
    except Exception as exc:
        return 3, f"Unable to start Selenium WebDriver: {type(exc).__name__}: {exc}"

    try:
        driver.set_page_load_timeout(timeout)
        driver.set_script_timeout(timeout)
        driver.get("about:blank")
        result = driver.execute_async_script(FONT_PROBE_JS)
        if not isinstance(result, dict):
            return 3, f"Font probe returned unexpected data: {result!r}"
        return _score_font_result(result)
    except Exception as exc:
        return 3, f"Browser font probe failed: {type(exc).__name__}: {exc}"
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass


def check_font_enumeration() -> tuple[int, str]:
    """Check whether browser font enumeration looks home-like."""
    return _try_selenium_font_check()


def main() -> None:
    score, description = check_font_enumeration()
    print_browser_detection_header("Font Enumeration Home-Browser Plausibility Check")
    print_browser_detection_score_footer(score, description)
    print(f"STATUS: {description}")


if __name__ == "__main__":
    main()
