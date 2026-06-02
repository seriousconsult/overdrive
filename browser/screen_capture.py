#!/usr/bin/env python3
"""
Screen Capture API Detection

Detects if screen capture APIs (getDisplayMedia, getUserMedia with video)
are available and being used for fingerprinting.

Score: 1-5
5 = Screen capture APIs exposed (privacy risk)
4 = Screen capture APIs available but not used (potential risk)
3 = Screen capture APIs available but not tested (unknown risk)
2 = Screen capture APIs not available (reduced attack surface)
1 = Screen capture APIs not available and not used (secure)
"""

import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from common.common_browser import (
    build_driver,
    print_browser_detection_header,
    print_browser_detection_score_footer,
)


_DETECTION_SCRIPT = r"""
const out = {
  hasMediaDevices: !!navigator.mediaDevices,
  hasGetDisplayMedia: false,
  hasGetUserMedia: false,
  displayMediaPermission: null,
  userMediaPermission: null,
  displayMediaTest: null,
  userMediaTest: null,
};

if (navigator.mediaDevices) {
  out.hasGetDisplayMedia = typeof navigator.mediaDevices.getDisplayMedia === "function";
  out.hasGetUserMedia = typeof navigator.mediaDevices.getUserMedia === "function";
}

function safeQueryPermission(name) {
  if (!navigator.permissions || typeof navigator.permissions.query !== "function") {
    return Promise.resolve(null);
  }
  return navigator.permissions
    .query({ name })
    .then((p) => (p && p.state ? p.state : null))
    .catch(() => null);
}

function safeCapture(fn) {
  try {
    const promise = fn();
    if (!(promise instanceof Promise)) {
      return Promise.resolve({ status: "unsupported" });
    }

    const timeout = new Promise((resolve) =>
      setTimeout(() => resolve({ status: "timeout" }), 5000)
    );

    return Promise.race([
      promise
        .then((stream) => {
          try {
            if (stream && typeof stream.getTracks === "function") {
              stream.getTracks().forEach((track) => track.stop());
            }
          } catch (ignore) {
          }
          return { status: "allowed" };
        })
        .catch((err) => ({ status: "error", name: err?.name || null, message: err?.message || null })),
      timeout,
    ]);
  } catch (err) {
    return Promise.resolve({ status: "exception", name: err?.name || null, message: err?.message || null });
  }
}

(async () => {
  if (out.hasGetDisplayMedia) {
    out.displayMediaTest = await safeCapture(() => navigator.mediaDevices.getDisplayMedia({ video: true }));
    out.displayMediaPermission = await safeQueryPermission("display-capture");
  }

  if (out.hasGetUserMedia) {
    out.userMediaTest = await safeCapture(() => navigator.mediaDevices.getUserMedia({ video: true }));
    out.userMediaPermission = await safeQueryPermission("camera");
  }

  return out;
})();
"""


def _format_result(status: Any, name: Any = None, message: Any = None) -> str:
    if not isinstance(status, str):
        return "unknown"
    if status == "allowed":
        return "allowed"
    if status in {"error", "exception", "timeout", "unsupported"}:
        details = []
        if name:
            details.append(str(name))
        if message:
            details.append(str(message))
        return f"{status}: {'; '.join(details)}" if details else status
    return status


def check_screen_capture() -> tuple[int, str]:
    """
    Check for screen capture API availability.
    Returns (score, description)
    """
    try:
        driver = build_driver()
    except Exception as exc:
        return 3, f"Unable to start Selenium WebDriver: {type(exc).__name__}: {exc}"

    try:
        driver.get("about:blank")
        detection = driver.execute_async_script(
            "const callback = arguments[arguments.length - 1];"
            + "(async () => {"
            + _DETECTION_SCRIPT
            + "})().then(result => callback(result)).catch(err => callback({ status: 'js-error', name: err?.name || null, message: err?.message || null }));"
        )
    except Exception as exc:
        driver.quit()
        return 3, f"Selenium run failed: {type(exc).__name__}: {exc}"

    driver.quit()

    if not isinstance(detection, dict):
        return 5, "Screen capture detection returned unexpected data."

    has_display = bool(detection.get("hasGetDisplayMedia"))
    has_user = bool(detection.get("hasGetUserMedia"))
    display_test = detection.get("displayMediaTest")
    user_test = detection.get("userMediaTest")

    if has_display:
        status = display_test.get("status") if isinstance(display_test, dict) else None
        if status == "allowed":
            return 5, (
                "navigator.mediaDevices.getDisplayMedia is supported and a capture request was accepted. "
                "Screen capture API is exposed."
            )

        return 4, (
            "navigator.mediaDevices.getDisplayMedia is supported. "
            f"Capture request result: {_format_result(status, display_test.get('name') if isinstance(display_test, dict) else None, display_test.get('message') if isinstance(display_test, dict) else None)}."
        )

    if has_user:
        status = user_test.get("status") if isinstance(user_test, dict) else None
        if status == "allowed":
            return 4, (
                "navigator.mediaDevices.getUserMedia(video:true) is supported and the request completed. "
                "Video capture API is available."
            )

        return 4, (
            "navigator.mediaDevices.getUserMedia(video:true) is supported. "
            f"Request result: {_format_result(status, user_test.get('name') if isinstance(user_test, dict) else None, user_test.get('message') if isinstance(user_test, dict) else None)}."
        )

    if detection.get("hasMediaDevices"):
        return 2, (
            "navigator.mediaDevices exists, but no screen capture API was detected. "
            "This reduces the browser attack surface for screen capture tracking."
        )

    return 1, (
        "No navigator.mediaDevices or capture APIs were detected. "
        "Screen capture APIs are not available and not used."
    )


def main():
    print_browser_detection_header("Screen Capture API Detection")
    score, description = check_screen_capture()
    print_browser_detection_score_footer(score, description)


if __name__ == "__main__":
    main()