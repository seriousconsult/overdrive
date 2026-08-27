#!/usr/bin/env python3
"""WebGL GPU Model and Browser Graphics Fingerprint Check.

Checks GPU-identifying data exposed through WebGL APIs. Ordinary browsers often
expose a hardware renderer string through ANGLE/WebGL, while privacy-hardened,
remote, headless, software-rendered, or VM/browser-automation setups may expose
SwiftShader, llvmpipe, VirtualBox, VMware, Parallels, QEMU, or other synthetic
graphics identities.

Measured attributes:
- WebGL and WebGL2 availability.
- Masked and unmasked WebGL vendor / renderer strings.
- WEBGL_debug_renderer_info exposure.
- Supported extension names and counts.
- Graphics limits such as texture size, viewport dimensions, draw buffers, and
  shader precision.
- A tiny deterministic WebGL render hash to show the graphics path is readable.
- Surrounding browser signals: User-Agent, navigator.webdriver, platform, vendor,
  languages, screen size, and color depth.

Score: 1-5
1 = Hardware GPU identity exposed and browser profile is coherent/home-like
2 = GPU data exposed but somewhat generic or mildly atypical
3 = Inconclusive or mixed graphics profile
4 = WebGL blocked/minimal, or likely software/remote graphics path
5 = Explicit automation/headless/VM/software renderer evidence
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from detections.common.common_browser import (
        DEFAULT_TIMEOUT,
        print_browser_detection_header,
        print_browser_detection_score_footer,
    )
    from detections.common.direct_chromium import run_async_script
    COMMON_BROWSER_IMPORT_ERROR: Exception | None = None
except Exception as exc:
    DEFAULT_TIMEOUT = 8
    COMMON_BROWSER_IMPORT_ERROR = exc
    run_async_script = None  # type: ignore[assignment]

    def print_browser_detection_header(title: str, *, width: int = 60) -> None:
        bar = "=" * width
        print(bar)
        print(title)
        print(bar)
        print()

    def print_browser_detection_score_footer(score: int, description: str, *, width: int = 60) -> None:
        print(f"Score: {score}")
        print(f"  {description}")
        print()
        print("=" * width)


GPU_WEBGL_PROBE_JS = r"""
const done = arguments[arguments.length - 1];

function makeHash(values) {
  let h = 2166136261 >>> 0;
  for (const value of values) {
    const text = String(value);
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
  }
  return ("00000000" + h.toString(16)).slice(-8);
}

function safeParam(gl, name) {
  try {
    const value = gl.getParameter(gl[name]);
    if (value && typeof value.length === "number" && typeof value !== "string") {
      return Array.from(value);
    }
    return value;
  } catch (e) {
    return null;
  }
}

function precision(gl, shaderType, precisionType) {
  try {
    const p = gl.getShaderPrecisionFormat(shaderType, precisionType);
    if (!p) return null;
    return { rangeMin: p.rangeMin, rangeMax: p.rangeMax, precision: p.precision };
  } catch (e) {
    return null;
  }
}

function renderHash(gl) {
  try {
    const vsSource = [
      "attribute vec2 a_position;",
      "void main() {",
      "  gl_Position = vec4(a_position, 0.0, 1.0);",
      "}"
    ].join("\n");
    const fsSource = [
      "precision mediump float;",
      "void main() {",
      "  gl_FragColor = vec4(0.125, 0.375, 0.75, 1.0);",
      "}"
    ].join("\n");
    function shader(type, source) {
      const s = gl.createShader(type);
      gl.shaderSource(s, source);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
        throw new Error(gl.getShaderInfoLog(s) || "shader compile failed");
      }
      return s;
    }
    const program = gl.createProgram();
    gl.attachShader(program, shader(gl.VERTEX_SHADER, vsSource));
    gl.attachShader(program, shader(gl.FRAGMENT_SHADER, fsSource));
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      throw new Error(gl.getProgramInfoLog(program) || "program link failed");
    }
    gl.useProgram(program);
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]),
      gl.STATIC_DRAW
    );
    const loc = gl.getAttribLocation(program, "a_position");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    gl.viewport(0, 0, 16, 16);
    gl.clearColor(0.0, 0.0, 0.0, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    const pixels = new Uint8Array(16 * 16 * 4);
    gl.readPixels(0, 0, 16, 16, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
    return makeHash(Array.from(pixels.slice(0, 128)));
  } catch (e) {
    return "render-error:" + String(e && e.message ? e.message : e);
  }
}

function probeContext(kind) {
  const canvas = document.createElement("canvas");
  canvas.width = 64;
  canvas.height = 64;
  const names = kind === "webgl2" ? ["webgl2"] : ["webgl", "experimental-webgl"];
  let gl = null;
  let contextName = null;
  for (const name of names) {
    try {
      gl = canvas.getContext(name, { antialias: true, preserveDrawingBuffer: true });
      if (gl) {
        contextName = name;
        break;
      }
    } catch (e) {}
  }
  if (!gl) {
    return { available: false };
  }

  let debugInfo = null;
  let unmaskedVendor = null;
  let unmaskedRenderer = null;
  try {
    debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
    if (debugInfo) {
      unmaskedVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
      unmaskedRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    }
  } catch (e) {}

  const extensions = Array.from(gl.getSupportedExtensions() || []).sort();
  const limits = {
    vendor: safeParam(gl, "VENDOR"),
    renderer: safeParam(gl, "RENDERER"),
    version: safeParam(gl, "VERSION"),
    shadingLanguageVersion: safeParam(gl, "SHADING_LANGUAGE_VERSION"),
    maxTextureSize: safeParam(gl, "MAX_TEXTURE_SIZE"),
    maxCubeMapTextureSize: safeParam(gl, "MAX_CUBE_MAP_TEXTURE_SIZE"),
    maxRenderbufferSize: safeParam(gl, "MAX_RENDERBUFFER_SIZE"),
    maxViewportDims: safeParam(gl, "MAX_VIEWPORT_DIMS"),
    maxVertexAttribs: safeParam(gl, "MAX_VERTEX_ATTRIBS"),
    maxVaryingVectors: safeParam(gl, "MAX_VARYING_VECTORS"),
    maxVertexTextureImageUnits: safeParam(gl, "MAX_VERTEX_TEXTURE_IMAGE_UNITS"),
    maxTextureImageUnits: safeParam(gl, "MAX_TEXTURE_IMAGE_UNITS"),
    maxCombinedTextureImageUnits: safeParam(gl, "MAX_COMBINED_TEXTURE_IMAGE_UNITS"),
    aliasedLineWidthRange: safeParam(gl, "ALIASED_LINE_WIDTH_RANGE"),
    aliasedPointSizeRange: safeParam(gl, "ALIASED_POINT_SIZE_RANGE"),
    redBits: safeParam(gl, "RED_BITS"),
    greenBits: safeParam(gl, "GREEN_BITS"),
    blueBits: safeParam(gl, "BLUE_BITS"),
    alphaBits: safeParam(gl, "ALPHA_BITS"),
    depthBits: safeParam(gl, "DEPTH_BITS"),
    stencilBits: safeParam(gl, "STENCIL_BITS"),
  };

  return {
    available: true,
    contextName,
    contextAttributes: gl.getContextAttributes ? gl.getContextAttributes() : null,
    debugRendererInfo: Boolean(debugInfo),
    maskedVendor: limits.vendor,
    maskedRenderer: limits.renderer,
    unmaskedVendor,
    unmaskedRenderer,
    version: limits.version,
    shadingLanguageVersion: limits.shadingLanguageVersion,
    limits,
    extensions,
    extensionCount: extensions.length,
    precision: {
      vertexHighFloat: precision(gl, gl.VERTEX_SHADER, gl.HIGH_FLOAT),
      fragmentHighFloat: precision(gl, gl.FRAGMENT_SHADER, gl.HIGH_FLOAT),
      fragmentMediumFloat: precision(gl, gl.FRAGMENT_SHADER, gl.MEDIUM_FLOAT),
    },
    renderHash: renderHash(gl),
  };
}

(async () => {
  try {
    const profile = {
      userAgent: navigator.userAgent || "",
      vendor: navigator.vendor || "",
      platform: navigator.platform || "",
      languages: Array.from(navigator.languages || []),
      language: navigator.language || "",
      webdriver: navigator.webdriver === true,
      hardwareConcurrency: navigator.hardwareConcurrency || null,
      deviceMemory: navigator.deviceMemory || null,
      pluginsLength: navigator.plugins ? navigator.plugins.length : null,
      mimeTypesLength: navigator.mimeTypes ? navigator.mimeTypes.length : null,
      screenWidth: screen.width || null,
      screenHeight: screen.height || null,
      colorDepth: screen.colorDepth || null,
      pixelDepth: screen.pixelDepth || null,
      devicePixelRatio: window.devicePixelRatio || null,
      innerWidth: window.innerWidth || null,
      innerHeight: window.innerHeight || null,
      outerWidth: window.outerWidth || null,
      outerHeight: window.outerHeight || null,
      hasChromeObject: Boolean(window.chrome),
    };

    const apis = {
      webglRenderingContext: typeof WebGLRenderingContext !== "undefined",
      webgl2RenderingContext: typeof WebGL2RenderingContext !== "undefined",
    };
    const webgl = probeContext("webgl");
    const webgl2 = probeContext("webgl2");
    const fingerprintPayload = JSON.stringify({ webgl, webgl2, profile });
    done({
      ok: true,
      apis,
      profile,
      webgl,
      webgl2,
      fingerprintHash: makeHash([fingerprintPayload]),
    });
  } catch (e) {
    done({ ok: false, error: String(e && e.message ? e.message : e) });
  }
})();
"""


def _text_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_text_values(item))
        return out
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(_text_values(item))
        return out
    return [str(value)]


def _primary_renderer(result: dict[str, Any]) -> tuple[str, str]:
    for key in ("webgl2", "webgl"):
        ctx = result.get(key) or {}
        if not isinstance(ctx, dict) or not ctx.get("available"):
            continue
        renderer = str(ctx.get("unmaskedRenderer") or ctx.get("maskedRenderer") or "")
        vendor = str(ctx.get("unmaskedVendor") or ctx.get("maskedVendor") or "")
        if renderer or vendor:
            return vendor, renderer
    return "", ""


def _browser_profile_issues(profile: dict[str, Any]) -> tuple[list[str], list[str]]:
    strong: list[str] = []
    soft: list[str] = []

    ua = str(profile.get("userAgent") or "")
    vendor = str(profile.get("vendor") or "")
    languages = profile.get("languages") or []
    plugins_len = profile.get("pluginsLength")
    outer_width = profile.get("outerWidth")
    outer_height = profile.get("outerHeight")
    color_depth = profile.get("colorDepth")
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
        soft.append("Chrome-like UA has unusual navigator.vendor")
    if not languages:
        soft.append("navigator.languages is empty")
    if plugins_len == 0 and (is_chrome or is_firefox):
        soft.append("navigator.plugins is empty")
    if outer_width == 0 or outer_height == 0:
        soft.append("window.outerWidth/outerHeight are zero")
    if color_depth not in (24, 30, 32, None):
        soft.append(f"unusual color depth {color_depth}")

    return strong, soft


def _graphics_issues(result: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """Return ``(strong, soft, positive)`` graphics signals."""
    strong: list[str] = []
    soft: list[str] = []
    positive: list[str] = []

    ctxs = [ctx for ctx in (result.get("webgl"), result.get("webgl2")) if isinstance(ctx, dict)]
    available = [ctx for ctx in ctxs if ctx.get("available")]
    if not available:
        strong.append("WebGL contexts are unavailable or blocked")
        return strong, soft, positive

    vendor, renderer = _primary_renderer(result)
    identity_blob = " ".join(_text_values({"vendor": vendor, "renderer": renderer})).lower()
    all_blob = " ".join(_text_values(result)).lower()

    explicit_vm_terms = (
        "virtualbox",
        "vmware",
        "parallels",
        "qemu",
        "virtio",
        "hyper-v",
        "hyperv",
        "svga3d",
        "vbox",
    )
    software_terms = (
        "swiftshader",
        "llvmpipe",
        "lavapipe",
        "softpipe",
        "software rasterizer",
        "software adapter",
        "microsoft basic render driver",
        "mesa offscreen",
        "osmesa",
    )
    remote_terms = ("remote desktop", "rdp", "citrix", "llvmpipe")

    if any(term in all_blob for term in explicit_vm_terms):
        strong.append("WebGL renderer/vendor exposes a virtual GPU or hypervisor graphics stack")
    if any(term in all_blob for term in software_terms):
        strong.append("WebGL renderer/vendor exposes software rendering")
    if any(term in all_blob for term in remote_terms):
        soft.append("WebGL renderer/vendor suggests remote or indirect graphics")

    hardware_terms = ("intel", "nvidia", "geforce", "quadro", "amd", "radeon", "apple", "mali", "adreno", "powervr")
    if any(term in identity_blob for term in hardware_terms):
        positive.append("specific hardware GPU family is exposed")
    elif renderer or vendor:
        soft.append("GPU renderer/vendor is exposed but generic or hard to classify")

    debug_count = sum(1 for ctx in available if ctx.get("debugRendererInfo"))
    if debug_count:
        positive.append("WEBGL_debug_renderer_info exposes unmasked vendor/renderer")
    else:
        soft.append("unmasked WebGL renderer extension is not exposed")

    for name, ctx in (("WebGL", result.get("webgl") or {}), ("WebGL2", result.get("webgl2") or {})):
        if not isinstance(ctx, dict) or not ctx.get("available"):
            continue
        ext_count = int(ctx.get("extensionCount") or 0)
        limits = ctx.get("limits") or {}
        max_texture = int(limits.get("maxTextureSize") or 0)
        render_hash = str(ctx.get("renderHash") or "")
        if ext_count < 12:
            soft.append(f"{name} exposes a sparse extension surface ({ext_count} extensions)")
        if max_texture and max_texture < 4096:
            soft.append(f"{name} max texture size is unusually low ({max_texture})")
        if render_hash.startswith("render-error:"):
            soft.append(f"{name} render/readback failed: {render_hash[:80]}")

    return strong, soft, positive


def _score_gpu_result(result: dict[str, Any]) -> tuple[int, str]:
    if not result.get("ok"):
        return 3, f"Inconclusive: GPU/WebGL probe failed: {result.get('error', 'unknown error')}"

    profile = result.get("profile") or {}
    strong_browser, soft_browser = _browser_profile_issues(profile)
    strong_graphics, soft_graphics, positive_graphics = _graphics_issues(result)
    vendor, renderer = _primary_renderer(result)
    renderer_label = renderer or "unknown renderer"
    vendor_label = vendor or "unknown vendor"
    fp_hash = result.get("fingerprintHash") or "hash unavailable"

    if strong_browser:
        return 5, (
            "Strongly non-home-like browser/GPU profile: "
            f"{'; '.join(strong_browser)}. WebGL renderer={renderer_label!r}, vendor={vendor_label!r}, hash={fp_hash}."
        )
    if strong_graphics:
        return 5, (
            "Strong VM/software graphics evidence exposed via WebGL: "
            f"{'; '.join(strong_graphics)}. renderer={renderer_label!r}, vendor={vendor_label!r}, hash={fp_hash}."
        )

    if soft_graphics and not positive_graphics:
        return 4, (
            "Unusual graphics profile: GPU identity is blocked, sparse, software-like, or generic: "
            f"{'; '.join(soft_graphics[:4])}. renderer={renderer_label!r}, vendor={vendor_label!r}, hash={fp_hash}."
        )

    all_soft = soft_graphics + soft_browser
    if positive_graphics and not all_soft:
        return 1, (
            "Hardware GPU identity is exposed through WebGL and the browser profile is coherent. "
            f"renderer={renderer_label!r}, vendor={vendor_label!r}, signals={'; '.join(positive_graphics)}, hash={fp_hash}."
        )
    if positive_graphics and len(all_soft) <= 2:
        return 2, (
            "GPU identity is exposed and mostly plausible, with minor anomalies: "
            f"{'; '.join(all_soft)}. renderer={renderer_label!r}, vendor={vendor_label!r}, hash={fp_hash}."
        )
    if positive_graphics:
        return 3, (
            "Mixed GPU/browser profile: hardware-like renderer is exposed, but several anomalies are present: "
            f"{'; '.join(all_soft[:5])}. renderer={renderer_label!r}, vendor={vendor_label!r}, hash={fp_hash}."
        )

    return 3, (
        "Inconclusive: WebGL data was present but did not map confidently to hardware, software, or VM graphics. "
        f"renderer={renderer_label!r}, vendor={vendor_label!r}, hash={fp_hash}."
    )


def _print_gpu_details(result: dict[str, Any]) -> None:
    profile = result.get("profile") or {}
    print("[Browser]")
    print(f"User-Agent: {profile.get('userAgent') or '-'}")
    print(f"Platform:   {profile.get('platform') or '-'}")
    print(f"Vendor:     {profile.get('vendor') or '-'}")
    print(f"WebDriver:  {profile.get('webdriver')}")
    print()

    for label in ("webgl", "webgl2"):
        ctx = result.get(label) or {}
        print(f"[{label.upper()}]")
        if not isinstance(ctx, dict) or not ctx.get("available"):
            print("available: false")
            print()
            continue
        print(f"context:            {ctx.get('contextName')}")
        print(f"masked vendor:      {ctx.get('maskedVendor')}")
        print(f"masked renderer:    {ctx.get('maskedRenderer')}")
        print(f"unmasked vendor:    {ctx.get('unmaskedVendor')}")
        print(f"unmasked renderer:  {ctx.get('unmaskedRenderer')}")
        print(f"debug renderer ext: {ctx.get('debugRendererInfo')}")
        print(f"version:            {ctx.get('version')}")
        print(f"shading language:   {ctx.get('shadingLanguageVersion')}")
        print(f"extension count:    {ctx.get('extensionCount')}")
        limits = ctx.get("limits") or {}
        print(f"max texture size:   {limits.get('maxTextureSize')}")
        print(f"max viewport dims:  {limits.get('maxViewportDims')}")
        print(f"render hash:        {ctx.get('renderHash')}")
        extensions = ctx.get("extensions") or []
        print(f"extensions sample:  {', '.join(extensions[:16]) if extensions else '-'}")
        print()


def _try_chromium_gpu_check(timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str, dict[str, Any] | None]:
    if COMMON_BROWSER_IMPORT_ERROR is not None:
        return (
            3,
            f"Inconclusive: browser helper import failed: {type(COMMON_BROWSER_IMPORT_ERROR).__name__}: "
            f"{COMMON_BROWSER_IMPORT_ERROR}",
            None,
        )
    if run_async_script is None:
        return 3, "Inconclusive: direct Chromium helpers are unavailable.", None

    result, error = run_async_script(GPU_WEBGL_PROBE_JS, timeout=timeout)
    if error:
        return 3, f"Browser GPU/WebGL probe failed: {error}", None
    if not isinstance(result, dict):
        return 3, f"GPU/WebGL probe returned unexpected data: {result!r}", None
    score, description = _score_gpu_result(result)
    return score, description, result


def check_gpu_webgl_fingerprint() -> tuple[int, str, dict[str, Any] | None]:
    return _try_chromium_gpu_check()


def main() -> None:
    score, description, result = check_gpu_webgl_fingerprint()
    print_browser_detection_header("WebGL GPU Model and Graphics Fingerprint Check")
    if result:
        _print_gpu_details(result)
    print_browser_detection_score_footer(score, description)
    print(f"STATUS: {description}")


if __name__ == "__main__":
    main()
