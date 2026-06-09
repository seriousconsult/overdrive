#!/usr/bin/env python3
"""
Cookie Tracking Detection

Detects whether browser cookies are available and behave like a typical
residential browser. A browser that blocks or fails to persist cookies is
less likely to match a normal home browser profile.

Measured attributes:
- navigator.cookieEnabled
- document.cookie write/read roundtrip
- browser profile coherence around automation signals

Score: 1-5
1 = authentic residential browser cookie behavior
2 = mostly normal cookie behavior with minor browser anomalies
3 = inconclusive browser/javascript result
4 = unusual browser behavior for a typical home setup
5 = strongly non-home-like automation/browser profile
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

COOKIE_PROBE_JS = r"""
const done = arguments[arguments.length - 1];

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

try {
  const profile = makeProfile();
  const cookieProbeName = "overdrive_cookie_tracking_probe";
  const cookieProbeValue = "1";
  const cookieEnabled = Boolean(navigator.cookieEnabled);

  let canSetCookie = false;
  let cookieString = "";
  let reason = null;

  try {
    document.cookie = `${cookieProbeName}=${cookieProbeValue}; path=/`;
    cookieString = document.cookie || "";
    canSetCookie = cookieString.includes(`${cookieProbeName}=${cookieProbeValue}`);
    if (!canSetCookie) {
      document.cookie = `${cookieProbeName}=${cookieProbeValue}; path=/; SameSite=Lax`;
      cookieString = document.cookie || "";
      canSetCookie = cookieString.includes(`${cookieProbeName}=${cookieProbeValue}`);
    }
  } catch (e) {
    reason = String(e && e.message ? e.message : e);
  }

  done({
    ok: true,
    profile,
    cookieEnabled,
    canSetCookie,
    cookieString,
    reason: reason || "cookie probe completed",
  });
} catch (e) {
  done({ ok: false, error: String(e && e.message ? e.message : e) });
}
"""


def _browser_profile_issues(profile: dict[str, Any]) -> tuple[list[str], list[str]]:
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


def _score_cookie_result(result: dict[str, Any]) -> tuple[int, str]:
    if not result.get("ok"):
        return 3, f"Inconclusive: cookie probe failed: {result.get('error', 'unknown error')}"

    strong_issues, soft_issues = _browser_profile_issues(result.get("profile") or {})
    cookie_enabled = result.get("cookieEnabled") is True
    can_set = result.get("canSetCookie") is True
    cookie_string = str(result.get("cookieString") or "")
    reason = result.get("reason") or "cookie probe completed"

    if not cookie_enabled or not can_set:
        score = 5 if strong_issues else 4
        return (
            score,
            f"Unusual cookie behavior: cookies are not writable/readable in this browser probe. {reason}."
        )

    if strong_issues:
        return (
            5,
            "Strongly non-home-like profile: cookies are available, but browser signals indicate automation: "
            f"{' ; '.join(strong_issues)}. {reason}."
        )

    if soft_issues:
        return (
            2,
            "Mostly home-like cookie behavior with minor browser anomalies: "
            f"{reason}. Issues: {'; '.join(soft_issues)}."
        )

    return 1, f"Home-like cookie behavior detected: {reason}."


def check_cookie_tracking() -> tuple[int, str]:
    try:
        driver = build_driver_with_fallback()
    except Exception as exc:
        return 3, f"Unable to start Selenium WebDriver: {type(exc).__name__}: {exc}"

    try:
        driver.set_script_timeout(DEFAULT_TIMEOUT)
        driver.get("about:blank")
        result = driver.execute_script(COOKIE_PROBE_JS)
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
        return 3, "Cookie tracking detection returned unexpected data."

    return _score_cookie_result(result)


def main():
    print_browser_detection_header("Cookie Tracking Detection")
    score, description = check_cookie_tracking()
    print_browser_detection_score_footer(score, description)


if __name__ == "__main__":
    main()
