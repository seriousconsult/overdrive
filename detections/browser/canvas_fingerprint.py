#!/usr/bin/env python3
"""Canvas Home-Browser Plausibility Check.

Checks whether the canvas/browser surface looks like a normal residential
browser setup. Canvas fingerprintability is expected for ordinary home browsers;
this script flags blocked, noised, headless, automated, or otherwise unusual
canvas/browser profiles.

Measured canvas attributes:
- Canvas API presence: HTMLCanvasElement, getContext(), and toDataURL().
- 2D rendering availability: successful creation of a 2D drawing context.
- Readback availability: PNG data URL from toDataURL() and pixel data from
  getImageData().
- Render stability: two identical draw/read cycles should produce identical
  data URL and pixel-prefix values.
- Fingerprint value: SHA-256 over the PNG data URL plus sampled pixel prefix.

Measured surrounding browser attributes:
- User-Agent family, headless marker, navigator.webdriver, navigator.vendor.
- navigator.languages, plugin count, MIME type count.
- hardwareConcurrency, deviceMemory, maxTouchPoints, cookieEnabled.
- screen size, color depth, pixel depth, devicePixelRatio, and window geometry.

Score: 1-5
1 = Strongly home-like browser/canvas profile
2 = Mostly home-like with minor anomalies
3 = Inconclusive or mixed browser/canvas profile
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


CANVAS_PROBE_JS = r"""
const done = arguments[arguments.length - 1];

function hex(buffer) {
  const view = new Uint8Array(buffer);
  let out = "";
  for (let i = 0; i < view.length; i++) {
    out += ("00" + view[i].toString(16)).slice(-2);
  }
  return out;
}

function drawCanvas() {
  // Canvas attributes measured here:
  // - 2D context availability
  // - deterministic text/shape/raster rendering
  // - toDataURL("image/png") readback
  // - getImageData() pixel readback from a fixed region
  const canvas = document.createElement("canvas");
  canvas.width = 300;
  canvas.height = 150;
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    throw new Error("2D canvas context unavailable");
  }

  ctx.fillStyle = "#f2f2f2";
  ctx.fillRect(0, 0, 300, 150);
  ctx.textBaseline = "top";
  ctx.font = "16px Arial";
  ctx.fillStyle = "rgb(255,0,0)";
  ctx.fillText("ThumbmarkJS canvas probe - test", 2, 2);
  ctx.fillStyle = "rgba(0,0,255,0.7)";
  ctx.fillRect(10, 30, 80, 50);
  ctx.beginPath();
  ctx.arc(200, 75, 30, 0, Math.PI * 2);
  ctx.fillStyle = "green";
  ctx.fill();

  const dataUrl = canvas.toDataURL("image/png");
  let imageDataPrefix = "";
  try {
    const imageData = ctx.getImageData(0, 0, 32, 32).data;
    imageDataPrefix = Array.from(imageData.slice(0, 64)).join(",");
  } catch (e) {
    imageDataPrefix = "getImageData-error:" + String(e && e.message ? e.message : e);
  }

  return { dataUrl, imageDataPrefix };
}

(async () => {
  try {
    const apis = {
      // API presence is expected for an ordinary residential browser.
      htmlCanvas: typeof HTMLCanvasElement !== "undefined",
      canvasToDataURL:
        typeof HTMLCanvasElement !== "undefined" &&
        typeof HTMLCanvasElement.prototype.toDataURL === "function",
      canvasGetContext:
        typeof HTMLCanvasElement !== "undefined" &&
        typeof HTMLCanvasElement.prototype.getContext === "function",
      cryptoDigest: Boolean(window.crypto && crypto.subtle && crypto.subtle.digest),
    };
    const profile = {
      // Surrounding browser attributes help distinguish a normal home browser
      // from headless automation or an unusually hardened/noised profile.
      userAgent: navigator.userAgent || "",
      appVersion: navigator.appVersion || "",
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
      hasChromeObject: Boolean(window.chrome),
      screenWidth: screen.width || null,
      screenHeight: screen.height || null,
      colorDepth: screen.colorDepth || null,
      pixelDepth: screen.pixelDepth || null,
      devicePixelRatio: window.devicePixelRatio || null,
      innerWidth: window.innerWidth || null,
      innerHeight: window.innerHeight || null,
      outerWidth: window.outerWidth || null,
      outerHeight: window.outerHeight || null,
    };

    if (!apis.htmlCanvas || !apis.canvasToDataURL || !apis.canvasGetContext) {
      done({
        ok: true,
        apis,
        profile,
        readback: false,
        reason: "required canvas APIs unavailable",
      });
      return;
    }

    const first = drawCanvas();
    const second = drawCanvas();
    if (!first.dataUrl || first.dataUrl === "data:,") {
      done({
        ok: true,
        apis,
        profile,
        readback: false,
        reason: "toDataURL returned no image data",
      });
      return;
    }

    const stable = first.dataUrl === second.dataUrl &&
      first.imageDataPrefix === second.imageDataPrefix;
    const payload = first.dataUrl + "|" + first.imageDataPrefix;
    let hash = null;
    if (apis.cryptoDigest) {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
      hash = hex(digest);
    }

    done({
      ok: true,
      apis,
      profile,
      readback: true,
      stable,
      dataUrlLength: first.dataUrl.length,
      hash,
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


def _score_canvas_result(result: dict[str, Any]) -> tuple[int, str]:
    if not result.get("ok"):
        return 3, f"Inconclusive: canvas/home-profile probe failed: {result.get('error', 'unknown error')}"

    apis = result.get("apis") or {}
    profile = result.get("profile") or {}
    strong_issues, soft_issues = _browser_profile_issues(profile)
    issue_text = "; ".join(strong_issues + soft_issues)

    if not apis.get("htmlCanvas"):
        return 4, "Unusual for a home setup: Canvas API is unavailable."
    if not (apis.get("canvasToDataURL") and apis.get("canvasGetContext")):
        return 4, "Unusual for a home setup: canvas readback APIs are unavailable or blocked."
    if not result.get("readback"):
        reason = result.get("reason", "no image data returned")
        return 4, f"Unusual for a home setup: canvas readback blocked or empty ({reason})."

    fp = result.get("hash") or "digest unavailable"
    size = result.get("dataUrlLength") or "unknown"
    if not result.get("stable"):
        suffix = f" Profile issues: {issue_text}." if issue_text else ""
        return 4, f"Unusual for a home setup: canvas output changed between identical renders.{suffix}"

    if strong_issues:
        return 5, (
            "Strongly non-home-like profile: stable canvas is present, but browser signals indicate automation: "
            f"{'; '.join(strong_issues)}. hash={fp}, dataURL bytes={size}."
        )
    if len(soft_issues) >= 2:
        return 3, (
            "Mixed home-profile confidence: canvas is stable, but browser signals are atypical: "
            f"{'; '.join(soft_issues)}. hash={fp}, dataURL bytes={size}."
        )
    if soft_issues:
        return 2, (
            "Mostly home-like: stable fingerprintable canvas with one minor browser anomaly: "
            f"{'; '.join(soft_issues)}. hash={fp}, dataURL bytes={size}."
        )

    return 1, (
        "Strongly home-like: stable fingerprintable canvas and coherent ordinary browser signals. "
        f"hash={fp}, dataURL bytes={size}."
    )


def _try_selenium_canvas_check(timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str]:
    """Run an in-browser canvas probe and return ``(score, description)``."""
    try:
        import selenium  # noqa: F401
    except Exception:
        return 4, "Inconclusive: Selenium is unavailable, so the home-browser canvas profile could not be probed."

    driver = None
    try:
        driver = build_driver_with_fallback()
    except Exception as e:
        return 3, str(e)

    try:
        driver.set_page_load_timeout(timeout)
        driver.set_script_timeout(timeout)
        driver.get("about:blank")
        result = driver.execute_async_script(CANVAS_PROBE_JS)
        if not isinstance(result, dict):
            return 3, f"Canvas probe returned an unexpected result: {result!r}"
        return _score_canvas_result(result)
    except Exception as e:
        return 3, f"Browser canvas probe failed: {e}"
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass


def check_canvas_fingerprint() -> tuple[int, str]:
    """Check whether the canvas/browser profile looks home-like."""
    return _try_selenium_canvas_check()


def main() -> None:
    score, description = check_canvas_fingerprint()
    print_browser_detection_header("Canvas Home-Browser Plausibility Check")
    print_browser_detection_score_footer(score, description)
    print(f"STATUS: {description}")


if __name__ == "__main__":
    main()
