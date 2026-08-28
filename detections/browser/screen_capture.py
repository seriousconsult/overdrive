#!/usr/bin/env python3
"""
Screen Capture API Detection

Probes whether the browser exposes a normal Screen Capture surface
(``navigator.mediaDevices.getDisplayMedia``) and whether an invoke behaves
like a real browser (permission/picker denial is expected without a user
gesture; silent absence is not).

Also weighs surrounding automation / headless signals so a headless Chromium
lab client is not mistaken for a residential desktop browser.

Host-authenticity score:
1 = normal residential browser screen-capture surface
2 = mostly normal with minor atypical details
3 = inconclusive browser result
4 = unusual or hardened browser behavior for a home setup
5 = strongly non-home-like automation/hardened profile
"""

from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from detections.common.common_browser import (
    DEFAULT_TIMEOUT,
    print_browser_detection_header,
    print_browser_detection_score_footer,
)
from detections.common.direct_chromium import run_async_script

# Keep invoke short: real pickers need a user gesture; headless usually denies fast.
_INVOKE_TIMEOUT_MS = 2500

_DETECTION_SCRIPT = rf"""
const done = arguments[arguments.length - 1];
const INVOKE_TIMEOUT_MS = {_INVOKE_TIMEOUT_MS};

function makeProfile() {{
  return {{
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
    hasChromeObject: Boolean(window.chrome),
    screenWidth: screen.width || null,
    screenHeight: screen.height || null,
    colorDepth: screen.colorDepth || null,
    pixelDepth: screen.pixelDepth || null,
    outerWidth: window.outerWidth || null,
    outerHeight: window.outerHeight || null,
  }};
}}

function safeQueryPermission(name) {{
  if (!navigator.permissions || typeof navigator.permissions.query !== "function") {{
    return Promise.resolve(null);
  }}
  return navigator.permissions
    .query({{ name }})
    .then((p) => (p && p.state ? p.state : null))
    .catch(() => null);
}}

function invokeGetDisplayMedia() {{
  const md = navigator.mediaDevices;
  if (!md || typeof md.getDisplayMedia !== "function") {{
    return Promise.resolve({{ status: "missing" }});
  }}
  try {{
    const promise = md.getDisplayMedia({{
      video: true,
      audio: false,
      preferCurrentTab: false,
    }});
    if (!(promise instanceof Promise)) {{
      return Promise.resolve({{ status: "unsupported", detail: "non-promise return" }});
    }}
    const timeout = new Promise((resolve) =>
      setTimeout(() => resolve({{ status: "timeout" }}), INVOKE_TIMEOUT_MS)
    );
    return Promise.race([
      promise
        .then((stream) => {{
          try {{
            if (stream && typeof stream.getTracks === "function") {{
              stream.getTracks().forEach((track) => track.stop());
            }}
          }} catch (ignore) {{
          }}
          return {{ status: "allowed" }};
        }})
        .catch((err) => ({{
          status: "error",
          name: err && err.name ? String(err.name) : null,
          message: err && err.message ? String(err.message) : null,
        }})),
      timeout,
    ]);
  }} catch (err) {{
    return Promise.resolve({{
      status: "exception",
      name: err && err.name ? String(err.name) : null,
      message: err && err.message ? String(err.message) : null,
    }});
  }}
}}

(async () => {{
  try {{
    const md = navigator.mediaDevices || null;
    const proto = window.MediaDevices && MediaDevices.prototype
      ? MediaDevices.prototype
      : null;

    const out = {{
      ok: true,
      secureContext: window.isSecureContext === true,
      hasMediaDevices: Boolean(md),
      hasGetDisplayMedia: Boolean(md && typeof md.getDisplayMedia === "function"),
      hasGetUserMedia: Boolean(md && typeof md.getUserMedia === "function"),
      hasEnumerateDevices: Boolean(md && typeof md.enumerateDevices === "function"),
      prototypeHasGetDisplayMedia: Boolean(
        proto && typeof proto.getDisplayMedia === "function"
      ),
      displayCapturePermission: null,
      supportedConstraintKeys: null,
      deviceSummary: null,
      displayMediaInvoke: null,
      profile: makeProfile(),
    }};

    if (md && typeof md.getSupportedConstraints === "function") {{
      try {{
        const constraints = md.getSupportedConstraints() || {{}};
        out.supportedConstraintKeys = Object.keys(constraints)
          .filter((k) => constraints[k])
          .sort();
      }} catch (ignore) {{
        out.supportedConstraintKeys = null;
      }}
    }}

    if (out.hasEnumerateDevices) {{
      try {{
        const devices = await md.enumerateDevices();
        const kinds = {{ audioinput: 0, audiooutput: 0, videoinput: 0, other: 0 }};
        for (const d of devices || []) {{
          const kind = d && d.kind ? String(d.kind) : "other";
          if (Object.prototype.hasOwnProperty.call(kinds, kind)) {{
            kinds[kind] += 1;
          }} else {{
            kinds.other += 1;
          }}
        }}
        out.deviceSummary = {{
          total: (devices || []).length,
          kinds,
        }};
      }} catch (err) {{
        out.deviceSummary = {{
          error: err && err.name ? String(err.name) : "enumerateDevices failed",
        }};
      }}
    }}

    out.displayCapturePermission = await safeQueryPermission("display-capture");

    if (out.hasGetDisplayMedia || out.prototypeHasGetDisplayMedia) {{
      out.displayMediaInvoke = await invokeGetDisplayMedia();
    }}

    done(out);
  }} catch (e) {{
    done({{
      ok: false,
      error: String(e && e.message ? e.message : e),
    }});
  }}
}})();
"""

# Expected when APIs work but there is no user gesture / picker acceptance.
_EXPECTED_DENIAL_NAMES = frozenset(
    {
        "NotAllowedError",
        "AbortError",
        "NotFoundError",
        "InvalidStateError",
        "NotReadableError",
        "SecurityError",
    }
)


class _ScreenCaptureProbeHandler(BaseHTTPRequestHandler):
    server_version = "OverdriveScreenCaptureProbe/1.0"

    def log_message(self, _fmt: str, *_args) -> None:
        return

    def do_GET(self) -> None:
        body = (
            b"<!doctype html><html><head><meta charset='utf-8'>"
            b"<title>Screen Capture Probe</title></head><body></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_screen_capture_probe_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ScreenCaptureProbeHandler)
    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
        name="screen-capture-probe",
    )
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/"


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


def _format_invoke(invoke: Any) -> str:
    if not isinstance(invoke, dict):
        return "unknown"
    status = invoke.get("status")
    if status == "allowed":
        return "allowed"
    if status == "timeout":
        return "timeout (picker/gesture wait)"
    if status in {"error", "exception"}:
        name = invoke.get("name") or "Error"
        message = invoke.get("message")
        return f"{status}: {name}" + (f" ({message})" if message else "")
    return str(status or "unknown")


def _invoke_looks_functional(invoke: Any) -> bool:
    """True when getDisplayMedia is wired (allow, expected deny, or picker timeout)."""
    if not isinstance(invoke, dict):
        return False
    status = invoke.get("status")
    if status in {"allowed", "timeout"}:
        return True
    if status in {"error", "exception"}:
        name = str(invoke.get("name") or "")
        return name in _EXPECTED_DENIAL_NAMES or name == ""
    return False


def _score_screen_capture(result: dict[str, Any]) -> tuple[int, str]:
    if not result.get("ok"):
        return 3, f"Inconclusive: screen-capture probe failed: {result.get('error', 'unknown error')}"

    profile = result.get("profile") if isinstance(result.get("profile"), dict) else {}
    strong_issues, soft_issues = _browser_profile_issues(profile)
    issue_text = "; ".join(strong_issues + soft_issues)

    has_md = bool(result.get("hasMediaDevices"))
    has_gdm = bool(result.get("hasGetDisplayMedia") or result.get("prototypeHasGetDisplayMedia"))
    secure = result.get("secureContext")
    perm = result.get("displayCapturePermission")
    invoke = result.get("displayMediaInvoke")
    invoke_text = _format_invoke(invoke)
    functional = _invoke_looks_functional(invoke)

    api_bits = []
    if has_md:
        api_bits.append("mediaDevices")
    if has_gdm:
        api_bits.append("getDisplayMedia")
    if result.get("hasEnumerateDevices"):
        api_bits.append("enumerateDevices")
    if perm is not None:
        api_bits.append(f"permission={perm}")
    api_bits.append(f"invoke={invoke_text}")
    if secure is False:
        api_bits.append("insecure-context")
    surface = ", ".join(api_bits)

    # Missing capture surface — hardened / non-browser.
    if not has_md:
        if strong_issues:
            return 5, (
                "Strongly non-home-like: no navigator.mediaDevices and automation signals: "
                f"{'; '.join(strong_issues)}."
            )
        return 5, (
            "No navigator.mediaDevices — not typical for a residential browser "
            "(hardened or non-browser profile)."
        )

    if not has_gdm:
        base_note = (
            "navigator.mediaDevices exists but getDisplayMedia is missing — "
            "unusual for a modern home browser (locked-down / hardened)."
        )
        if strong_issues:
            return 5, f"{base_note} Automation signals: {'; '.join(strong_issues)}."
        if soft_issues:
            return 4, f"{base_note} Also atypical: {'; '.join(soft_issues)}."
        return 4, base_note

    # getDisplayMedia present.
    if not functional and isinstance(invoke, dict) and invoke.get("status") not in (None, "missing"):
        # Odd failure mode for an exposed API.
        soft_issues = list(soft_issues) + [f"getDisplayMedia invoke looked broken ({invoke_text})"]

    if strong_issues:
        return 5, (
            "Strongly non-home-like profile: screen-capture APIs are present, "
            f"but browser signals indicate automation: {'; '.join(strong_issues)}. "
            f"Surface: {surface}."
        )

    if len(soft_issues) >= 2:
        return 3, (
            "Mixed confidence: getDisplayMedia is exposed, but browser signals are atypical: "
            f"{'; '.join(soft_issues)}. Surface: {surface}."
        )

    if soft_issues:
        return 2, (
            "Mostly home-like screen-capture surface with one minor anomaly: "
            f"{'; '.join(soft_issues)}. Surface: {surface}."
        )

    if functional or invoke is None:
        return 1, (
            "Home-like: getDisplayMedia is exposed and behaves like a normal browser "
            f"(permission/picker denial without a user gesture is expected). Surface: {surface}."
        )

    return 2, (
        f"getDisplayMedia is exposed. Capture invoke result: {invoke_text}. "
        "Still browser-like, though not fully definitive."
        + (f" Profile notes: {issue_text}." if issue_text else "")
    )


def check_screen_capture() -> tuple[int, str]:
    """Check screen-capture API surface and behavior. Returns (score, description)."""
    # Invoke race + permission queries need headroom beyond INVOKE_TIMEOUT_MS.
    script_timeout = max(DEFAULT_TIMEOUT, (_INVOKE_TIMEOUT_MS // 1000) + 6)
    server = None
    try:
        server, url = _start_screen_capture_probe_server()
        detection, error = run_async_script(_DETECTION_SCRIPT, timeout=script_timeout, url=url)
        if error:
            return 3, f"Chromium DevTools run failed: {error}"
    except OSError as exc:
        return 3, f"local screen-capture probe server could not start: {type(exc).__name__}: {exc}"
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()

    if not isinstance(detection, dict):
        return 3, f"Screen capture detection returned unexpected data: {detection!r}"

    return _score_screen_capture(detection)


def main() -> None:
    print_browser_detection_header("Screen Capture API Detection")
    score, description = check_screen_capture()
    print_browser_detection_score_footer(score, description)


if __name__ == "__main__":
    main()
