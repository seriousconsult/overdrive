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

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

from detections.common.common_browser import is_browser_timeout_error
from detections.common.direct_chromium import run_async_script


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


DEFAULT_TIMEOUT = _env_int("OVERDRIVE_BROWSER_TIMEOUT", 8)
DEFAULT_REPORT_WIDTH = 60


def print_browser_detection_header(title: str, *, width: int = DEFAULT_REPORT_WIDTH) -> None:
    bar = "=" * width
    print(bar)
    print(title)
    print(bar)
    print()


def print_browser_detection_score_footer(
    score: int,
    description: str,
    *,
    width: int = DEFAULT_REPORT_WIDTH,
) -> None:
    print(f"Score: {score}")
    print(f"  {description}")
    print()
    print("=" * width)


def _is_browser_timeout_error(reason: str) -> bool:
    return is_browser_timeout_error(reason)


def print_browser_probe_error(reason: str, *, width: int = DEFAULT_REPORT_WIDTH) -> int:
    label = "TIMEOUT" if _is_browser_timeout_error(reason) else "ERROR"
    print("SCORE: Error")
    print(f"STATUS: {label}: {reason}")
    print()
    print("=" * width)
    return 2


FONT_PROBE_TIMEOUT = max(DEFAULT_TIMEOUT, 25)

FONT_PROBE_JS = r"""
const callback = arguments[arguments.length - 1];
function finish(value) {
  if (typeof callback === "function") {
    callback(value);
  }
}

const CANDIDATE_FONTS = [
  "Arial",
  "Arial Black",
  "Bahnschrift",
  "Calibri",
  "Cambria",
  "Cambria Math",
  "Candara",
  "Comic Sans MS",
  "Consolas",
  "Constantia",
  "Corbel",
  "Courier New",
  "Ebrima",
  "Franklin Gothic Medium",
  "Gadugi",
  "Georgia",
  "HoloLens MDL2 Assets",
  "Impact",
  "Ink Free",
  "Javanese Text",
  "Leelawadee UI",
  "Lucida Console",
  "Lucida Sans Unicode",
  "Malgun Gothic",
  "Marlett",
  "Microsoft Himalaya",
  "Microsoft JhengHei",
  "Microsoft New Tai Lue",
  "Microsoft PhagsPa",
  "Microsoft Sans Serif",
  "Microsoft Tai Le",
  "Microsoft YaHei",
  "Microsoft Yi Baiti",
  "MingLiU-ExtB",
  "Mongolian Baiti",
  "MS Gothic",
  "MV Boli",
  "Myanmar Text",
  "Nirmala UI",
  "Palatino Linotype",
  "Segoe Fluent Icons",
  "Segoe MDL2 Assets",
  "Segoe Print",
  "Segoe Script",
  "Segoe UI",
  "Segoe UI Emoji",
  "Segoe UI Historic",
  "Segoe UI Symbol",
  "SimSun",
  "Sitka",
  "Sylfaen",
  "Symbol",
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
const CORE_TEST_SAMPLES = {
  latin: TEST_TEXT,
  mixedCase: "The quick brown fox jumps over WINDOWS 11",
  digits: "0123456789 42.195 100%",
  symbols: "!@#$%^&*()[]{}<>?/\\|~",
};
const EXPENSIVE_TEST_SAMPLES = {
  emoji: "hello 😀🚀⭐ windows",
  cjk: "漢字かなカナ한글中文 Windows",
};
const FONT_VARIANTS = [
  { label: "regular", style: "normal", weight: "400" },
  { label: "bold", style: "normal", weight: "700" },
  { label: "italic", style: "italic", weight: "400" },
  { label: "boldItalic", style: "italic", weight: "700" },
];
const FALLBACK_STACKS = [
  { name: "genericSans", family: "sans-serif" },
  { name: "genericSerif", family: "serif" },
  { name: "genericMono", family: "monospace" },
  { name: "windowsUi", family: '"Segoe UI", Arial, sans-serif' },
  { name: "windowsSerif", family: 'Cambria, Georgia, "Times New Roman", serif' },
  { name: "windowsMono", family: 'Consolas, "Courier New", monospace' },
  { name: "windowsEmoji", family: '"Segoe UI Emoji", "Segoe UI Symbol", sans-serif' },
  { name: "windowsCjk", family: '"Microsoft YaHei", "Microsoft JhengHei", "Malgun Gothic", "MS Gothic", sans-serif' },
  { name: "appleSans", family: '"San Francisco", "Helvetica Neue", Helvetica, sans-serif' },
  { name: "linuxSans", family: '"Noto Sans", "DejaVu Sans", "Liberation Sans", sans-serif' },
  { name: "androidSans", family: 'Roboto, "Droid Sans", sans-serif' },
];
const PROBE_TIME_BUDGET_MS = 5000;
const YIELD_EVERY_OPS = 24;

function roundWidth(value) {
  return Math.round(Number(value || 0) * 1000) / 1000;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function makeScheduler() {
  const startedAt = performance.now();
  let ops = 0;
  const skipped = [];
  return {
    skipped,
    elapsedMs() {
      return Math.round(performance.now() - startedAt);
    },
    overBudget() {
      return performance.now() - startedAt > PROBE_TIME_BUDGET_MS;
    },
    async tick(label) {
      ops += 1;
      if (ops % YIELD_EVERY_OPS === 0) {
        await sleep(0);
      }
      if (this.overBudget()) {
        skipped.push(label);
        return false;
      }
      return true;
    },
  };
}

function measureFont(ctx, fontName, baseFamily) {
  ctx.font = "72px " + JSON.stringify(fontName) + ", " + baseFamily;
  return roundWidth(ctx.measureText(TEST_TEXT).width);
}

function measureFontVariant(ctx, fontName, baseFamily, variant, sample = TEST_TEXT) {
  ctx.font = `${variant.style} ${variant.weight} 72px ${JSON.stringify(fontName)}, ${baseFamily}`;
  return roundWidth(ctx.measureText(sample).width);
}

function measureBase(ctx, baseFamily) {
  ctx.font = "72px " + baseFamily;
  return roundWidth(ctx.measureText(TEST_TEXT).width);
}

function measureStack(ctx, family, sample, size = 40) {
  ctx.font = `${size}px ${family}`;
  return roundWidth(ctx.measureText(sample).width);
}

async function checkDocumentFonts(fonts, scheduler) {
  const checks = {
    available: Boolean(document.fonts && typeof document.fonts.check === "function"),
    values: {},
    errors: {},
  };
  if (!checks.available) {
    return checks;
  }
  for (const font of fonts) {
    if (!(await scheduler.tick("documentFonts"))) {
      checks.truncated = true;
      break;
    }
    try {
      checks.values[font] = document.fonts.check(`16px ${JSON.stringify(font)}`);
    } catch (e) {
      checks.errors[font] = String(e && e.message ? e.message : e);
    }
  }
  return checks;
}

async function detectFonts() {
  const scheduler = makeScheduler();
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
  const variantMeasurements = {};
  for (const font of CANDIDATE_FONTS) {
    if (!(await scheduler.tick("regularMeasurements"))) {
      break;
    }
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
  for (const font of detected) {
    if (!(await scheduler.tick("stabilityPass"))) {
      break;
    }
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

  for (const font of detected) {
    if (!(await scheduler.tick("variantMeasurements"))) {
      break;
    }
    variantMeasurements[font] = {};
    for (const variant of FONT_VARIANTS) {
      const variantWidths = {};
      for (const base of BASE_FAMILIES) {
        variantWidths[base] = measureFontVariant(ctx, font, base, variant);
      }
      variantMeasurements[font][variant.label] = variantWidths;
    }
  }

  const fallbackStackMeasurements = {};
  for (const stack of FALLBACK_STACKS) {
    if (!(await scheduler.tick("fallbackStackMeasurements"))) {
      break;
    }
    fallbackStackMeasurements[stack.name] = {};
    for (const [sampleName, sampleText] of Object.entries(CORE_TEST_SAMPLES)) {
      fallbackStackMeasurements[stack.name][sampleName] = measureStack(ctx, stack.family, sampleText);
    }
  }
  for (const stack of FALLBACK_STACKS.filter((item) => ["genericSans", "windowsEmoji", "windowsCjk", "linuxSans"].includes(item.name))) {
    if (!(await scheduler.tick("expensiveFallbackSamples"))) {
      break;
    }
    fallbackStackMeasurements[stack.name] = fallbackStackMeasurements[stack.name] || {};
    for (const [sampleName, sampleText] of Object.entries(EXPENSIVE_TEST_SAMPLES)) {
      fallbackStackMeasurements[stack.name][sampleName] = measureStack(ctx, stack.family, sampleText);
    }
  }

  return {
    ok: true,
    baseWidths,
    detected,
    detectedCount: detected.length,
    candidateCount: CANDIDATE_FONTS.length,
    stable: firstSet === secondSet,
    measurements,
    variantMeasurements,
    fallbackStackMeasurements,
    documentFonts: await checkDocumentFonts(CANDIDATE_FONTS, scheduler),
    meta: {
      elapsedMs: scheduler.elapsedMs(),
      timeBudgetMs: PROBE_TIME_BUDGET_MS,
      skipped: scheduler.skipped,
      bounded: true,
    },
  };
}

(async () => {
  try {
    const fontProbe = await detectFonts();
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
    finish({ ok: true, fontProbe, profile });
  } catch (e) {
    finish({ ok: false, error: String(e && e.message ? e.message : e) });
  }
})().then(undefined, (e) => finish({ ok: false, error: String(e && e.message ? e.message : e) }));
"""


def _run_direct_chromium_font_probe(
    timeout: int = FONT_PROBE_TIMEOUT,
) -> tuple[dict[str, Any] | None, str | None]:
    value, error = run_async_script(FONT_PROBE_JS, timeout=timeout)
    if not isinstance(value, dict):
        return None, error or "Direct Chromium font probe returned no object result."
    value.setdefault("transport", "chromium-devtools")
    return value, None


POPULAR_WINDOWS_BASELINE_NAME = "popular Windows residential desktop"
POPULAR_WINDOWS_BASELINE_BASIS = (
    "Windows 11 + Google Chrome desktop. This built-in profile compares family "
    "presence and browser-profile signals; use --compare-baseline for exact "
    "canvas measurement diffs from a captured reference machine."
)

POPULAR_WINDOWS_EXPECTED_FONTS = frozenset(
    {
        "Arial",
        "Arial Black",
        "Bahnschrift",
        "Calibri",
        "Cambria",
        "Cambria Math",
        "Candara",
        "Comic Sans MS",
        "Consolas",
        "Constantia",
        "Corbel",
        "Courier New",
        "Ebrima",
        "Franklin Gothic Medium",
        "Gadugi",
        "Georgia",
        "HoloLens MDL2 Assets",
        "Impact",
        "Ink Free",
        "Javanese Text",
        "Leelawadee UI",
        "Lucida Console",
        "Lucida Sans Unicode",
        "Malgun Gothic",
        "Marlett",
        "Microsoft Himalaya",
        "Microsoft JhengHei",
        "Microsoft New Tai Lue",
        "Microsoft PhagsPa",
        "Microsoft Sans Serif",
        "Microsoft Tai Le",
        "Microsoft YaHei",
        "Microsoft Yi Baiti",
        "MingLiU-ExtB",
        "Mongolian Baiti",
        "MS Gothic",
        "MV Boli",
        "Myanmar Text",
        "Nirmala UI",
        "Palatino Linotype",
        "Segoe Fluent Icons",
        "Segoe MDL2 Assets",
        "Segoe Print",
        "Segoe Script",
        "Segoe UI",
        "Segoe UI Emoji",
        "Segoe UI Historic",
        "Segoe UI Symbol",
        "SimSun",
        "Sitka",
        "Sylfaen",
        "Symbol",
        "Tahoma",
        "Times New Roman",
        "Trebuchet MS",
        "Verdana",
        "Webdings",
        "Wingdings",
    }
)

POPULAR_WINDOWS_UNEXPECTED_FONTS = frozenset(
    {
        "San Francisco",
        "Helvetica Neue",
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
    }
)

POPULAR_WINDOWS_NEUTRAL_FONTS = frozenset({"Helvetica"})


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


def _run_font_probe(timeout: int = FONT_PROBE_TIMEOUT) -> tuple[dict[str, Any] | None, str | None]:
    return _run_direct_chromium_font_probe(timeout)


def _run_font_check(timeout: int = FONT_PROBE_TIMEOUT) -> tuple[int, str]:
    """Run an in-browser font probe and return ``(score, description)``."""
    result, error = _run_font_probe(timeout)
    if result is None:
        return 3, error or "Browser font probe failed for an unknown reason."
    return _score_font_result(result)


def check_font_enumeration(timeout: int = FONT_PROBE_TIMEOUT) -> tuple[int, str]:
    """Check whether browser font enumeration looks home-like."""
    return _run_font_check(timeout)


def _baseline_payload(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "overdrive.browser.font_enumeration.baseline.v1",
        "source": "Run this on the reference browser, e.g. Windows Chrome.",
        "result": result,
    }


def _read_probe_result(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    if isinstance(data.get("result"), dict):
        return data["result"]
    if isinstance(data.get("fontProbe"), dict) and isinstance(data.get("profile"), dict):
        return data
    raise ValueError(f"{path} is not a font_enumeration baseline/probe JSON file")


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _fmt(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def _profile_differences(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> list[str]:
    baseline_profile = baseline.get("profile") or {}
    current_profile = current.get("profile") or {}
    if not isinstance(baseline_profile, dict) or not isinstance(current_profile, dict):
        return ["profile data is missing or malformed in one probe result"]

    keys = (
        "userAgent",
        "vendor",
        "platform",
        "languages",
        "language",
        "webdriver",
        "pluginsLength",
        "mimeTypesLength",
        "hardwareConcurrency",
        "deviceMemory",
        "maxTouchPoints",
        "cookieEnabled",
        "screenWidth",
        "screenHeight",
        "colorDepth",
        "pixelDepth",
        "outerWidth",
        "outerHeight",
    )
    differences: list[str] = []
    for key in keys:
        base_value = baseline_profile.get(key)
        current_value = current_profile.get(key)
        if base_value != current_value:
            differences.append(f"{key}: baseline={_fmt(base_value)} current={_fmt(current_value)}")
    return differences


def _measurement_differences(
    baseline_probe: dict[str, Any],
    current_probe: dict[str, Any],
    *,
    threshold: float,
) -> list[str]:
    baseline_measurements = baseline_probe.get("measurements") or {}
    current_measurements = current_probe.get("measurements") or {}
    if not isinstance(baseline_measurements, dict) or not isinstance(current_measurements, dict):
        return ["measurement data is missing or malformed in one probe result"]

    font_names = sorted(set(baseline_measurements) | set(current_measurements))
    differences: list[str] = []
    for font in font_names:
        baseline_widths = baseline_measurements.get(font) or {}
        current_widths = current_measurements.get(font) or {}
        if not isinstance(baseline_widths, dict) or not isinstance(current_widths, dict):
            if baseline_widths != current_widths:
                differences.append(
                    f"{font}: baseline widths={_fmt(baseline_widths)} current widths={_fmt(current_widths)}"
                )
            continue
        bases = sorted(set(baseline_widths) | set(current_widths))
        changed: list[str] = []
        for base in bases:
            base_value = baseline_widths.get(base)
            current_value = current_widths.get(base)
            base_num = _number(base_value)
            current_num = _number(current_value)
            if base_num is not None and current_num is not None:
                delta = current_num - base_num
                if abs(delta) > threshold:
                    changed.append(
                        f"{base}: baseline={base_num:.3f} current={current_num:.3f} delta={delta:+.3f}"
                    )
            elif base_value != current_value:
                changed.append(f"{base}: baseline={_fmt(base_value)} current={_fmt(current_value)}")
        if changed:
            differences.append(f"{font}: " + "; ".join(changed))
    return differences


def _base_width_differences(
    baseline_probe: dict[str, Any],
    current_probe: dict[str, Any],
    *,
    threshold: float,
) -> list[str]:
    baseline_widths = baseline_probe.get("baseWidths") or {}
    current_widths = current_probe.get("baseWidths") or {}
    if not isinstance(baseline_widths, dict) or not isinstance(current_widths, dict):
        return ["base-width data is missing or malformed in one probe result"]

    differences: list[str] = []
    for base in sorted(set(baseline_widths) | set(current_widths)):
        base_value = baseline_widths.get(base)
        current_value = current_widths.get(base)
        base_num = _number(base_value)
        current_num = _number(current_value)
        if base_num is not None and current_num is not None:
            delta = current_num - base_num
            if abs(delta) > threshold:
                differences.append(
                    f"{base}: baseline={base_num:.3f} current={current_num:.3f} delta={delta:+.3f}"
                )
        elif base_value != current_value:
            differences.append(f"{base}: baseline={_fmt(base_value)} current={_fmt(current_value)}")
    return differences


def _nested_numeric_differences(
    baseline_value: Any,
    current_value: Any,
    *,
    threshold: float,
    path: str = "",
) -> list[str]:
    differences: list[str] = []
    if isinstance(baseline_value, dict) and isinstance(current_value, dict):
        for key in sorted(set(baseline_value) | set(current_value)):
            child_path = f"{path}.{key}" if path else str(key)
            differences.extend(
                _nested_numeric_differences(
                    baseline_value.get(key),
                    current_value.get(key),
                    threshold=threshold,
                    path=child_path,
                )
            )
        return differences

    baseline_num = _number(baseline_value)
    current_num = _number(current_value)
    if baseline_num is not None and current_num is not None:
        delta = current_num - baseline_num
        if abs(delta) > threshold:
            differences.append(
                f"{path}: baseline={baseline_num:.3f} current={current_num:.3f} delta={delta:+.3f}"
            )
    elif baseline_value != current_value:
        differences.append(f"{path}: baseline={_fmt(baseline_value)} current={_fmt(current_value)}")
    return differences


def _print_limited(title: str, rows: list[str], *, max_rows: int) -> None:
    print(title)
    if not rows:
        print("  - none")
        return
    shown = rows if max_rows <= 0 else rows[:max_rows]
    for row in shown:
        print(f"  - {row}")
    if max_rows > 0 and len(rows) > max_rows:
        print(f"  - ... {len(rows) - max_rows} more; rerun with --max-diffs 0 to show all")


def _detected_fonts(result: dict[str, Any]) -> set[str]:
    font_probe = result.get("fontProbe") or {}
    if not isinstance(font_probe, dict):
        return set()
    return set(str(font) for font in (font_probe.get("detected") or []))


def _width_signature(widths: Any) -> tuple[tuple[str, float], ...] | None:
    if not isinstance(widths, dict):
        return None
    signature: list[tuple[str, float]] = []
    for base, value in sorted(widths.items()):
        number = _number(value)
        if number is None:
            return None
        signature.append((str(base), round(number, 3)))
    return tuple(signature)


def _font_measurement_deviations(
    font_probe: dict[str, Any],
    detected: set[str],
) -> list[str]:
    measurements = font_probe.get("measurements") or {}
    if not isinstance(measurements, dict):
        return ["regular font measurement table is missing or malformed"]

    deviations: list[str] = []
    signature_to_fonts: dict[tuple[tuple[str, float], ...], list[str]] = {}
    for font in sorted(POPULAR_WINDOWS_EXPECTED_FONTS & detected):
        signature = _width_signature(measurements.get(font))
        if signature is None:
            deviations.append(f"{font}: missing regular width signature")
            continue
        signature_to_fonts.setdefault(signature, []).append(font)

    collapsed_groups = [
        fonts
        for fonts in signature_to_fonts.values()
        if len(fonts) >= 4
    ]
    for fonts in sorted(collapsed_groups, key=lambda item: (-len(item), item[0]))[:12]:
        deviations.append(
            "multiple distinct Windows families share an identical regular width signature: "
            + ", ".join(fonts)
        )

    return deviations


def _font_variant_deviations(
    font_probe: dict[str, Any],
    detected: set[str],
) -> list[str]:
    variant_measurements = font_probe.get("variantMeasurements") or {}
    if not isinstance(variant_measurements, dict):
        return ["style/weight variant measurement table is missing or malformed"]

    deviations: list[str] = []
    collapsed: list[str] = []
    missing: list[str] = []
    expected_variants = {"regular", "bold", "italic", "boldItalic"}
    for font in sorted(POPULAR_WINDOWS_EXPECTED_FONTS & detected):
        variants = variant_measurements.get(font)
        if not isinstance(variants, dict):
            missing.append(font)
            continue
        if set(variants) & expected_variants != expected_variants:
            missing.append(font)
            continue
        regular = _width_signature(variants.get("regular"))
        other_signatures = {
            label: _width_signature(variants.get(label))
            for label in ("bold", "italic", "boldItalic")
        }
        if regular is not None and all(sig == regular for sig in other_signatures.values()):
            collapsed.append(font)

    if missing:
        deviations.append(
            "missing style/weight signatures for expected Windows families: "
            + ", ".join(missing[:20])
            + (f", ... {len(missing) - 20} more" if len(missing) > 20 else "")
        )
    if collapsed:
        deviations.append(
            "bold/italic signatures collapse to regular for expected Windows families: "
            + ", ".join(collapsed[:20])
            + (f", ... {len(collapsed) - 20} more" if len(collapsed) > 20 else "")
        )
    return deviations


def _document_font_deviations(
    font_probe: dict[str, Any],
    detected: set[str],
) -> list[str]:
    document_fonts = font_probe.get("documentFonts") or {}
    if not isinstance(document_fonts, dict):
        return ["document.fonts check table is missing or malformed"]
    if not document_fonts.get("available"):
        return ["document.fonts.check is unavailable"]

    values = document_fonts.get("values") or {}
    errors = document_fonts.get("errors") or {}
    deviations: list[str] = []
    if not isinstance(values, dict):
        deviations.append("document.fonts values are malformed")
        values = {}
    if isinstance(errors, dict) and errors:
        deviations.append(
            "document.fonts.check raised errors for: "
            + ", ".join(sorted(str(font) for font in errors)[:20])
        )

    false_detected = sorted(
        font
        for font in POPULAR_WINDOWS_EXPECTED_FONTS & detected
        if values.get(font) is False
    )
    if false_detected:
        deviations.append(
            "detected Windows families failed document.fonts.check: "
            + ", ".join(false_detected[:20])
            + (f", ... {len(false_detected) - 20} more" if len(false_detected) > 20 else "")
        )

    true_missing = sorted(
        font
        for font in POPULAR_WINDOWS_EXPECTED_FONTS - detected
        if values.get(font) is True
    )
    if true_missing:
        deviations.append(
            "document.fonts.check says available but canvas metrics did not distinguish: "
            + ", ".join(true_missing[:20])
            + (f", ... {len(true_missing) - 20} more" if len(true_missing) > 20 else "")
        )

    return deviations


def _same_stack_signature(stacks: dict[str, Any], left: str, right: str) -> bool:
    left_value = stacks.get(left)
    right_value = stacks.get(right)
    return isinstance(left_value, dict) and left_value == right_value


def _fallback_stack_deviations(font_probe: dict[str, Any]) -> list[str]:
    stacks = font_probe.get("fallbackStackMeasurements") or {}
    if not isinstance(stacks, dict):
        return ["fallback-stack measurement table is missing or malformed"]

    deviations: list[str] = []
    comparisons = (
        ("windowsUi", "genericSans", "Windows UI stack collapses to generic sans-serif"),
        ("windowsUi", "linuxSans", "Windows UI stack matches Linux sans stack"),
        ("windowsUi", "appleSans", "Windows UI stack matches Apple sans stack"),
        ("windowsUi", "androidSans", "Windows UI stack matches Android sans stack"),
        ("windowsSerif", "genericSerif", "Windows serif stack collapses to generic serif"),
        ("windowsMono", "genericMono", "Windows monospace stack collapses to generic monospace"),
        ("windowsEmoji", "genericSans", "Windows emoji stack collapses to generic sans-serif"),
        ("windowsCjk", "genericSans", "Windows CJK stack collapses to generic sans-serif"),
        ("windowsCjk", "linuxSans", "Windows CJK stack matches Linux sans stack"),
    )
    for left, right, message in comparisons:
        if _same_stack_signature(stacks, left, right):
            deviations.append(message)

    required = {
        "genericSans",
        "genericSerif",
        "genericMono",
        "windowsUi",
        "windowsSerif",
        "windowsMono",
        "windowsEmoji",
        "windowsCjk",
    }
    missing = sorted(required - set(stacks))
    if missing:
        deviations.append("missing fallback-stack measurements: " + ", ".join(missing))

    return deviations


def popular_windows_deviation_report(result: dict[str, Any]) -> dict[str, list[str]]:
    font_probe = result.get("fontProbe") or {}
    if not result.get("ok"):
        return {
            "probe": [f"probe failed: {result.get('error', 'unknown error')}"],
            "missing_fonts": [],
            "unexpected_fonts": [],
            "measurement": [],
            "variants": [],
            "font_api": [],
            "fallback": [],
            "notes": [],
        }
    if not isinstance(font_probe, dict) or not font_probe.get("ok"):
        reason = font_probe.get("reason", "unknown reason") if isinstance(font_probe, dict) else "missing fontProbe"
        return {
            "probe": [f"font measurement unavailable: {reason}"],
            "missing_fonts": [],
            "unexpected_fonts": [],
            "measurement": [],
            "variants": [],
            "font_api": [],
            "fallback": [],
            "notes": [],
        }

    detected = _detected_fonts(result)
    missing_fonts = sorted(POPULAR_WINDOWS_EXPECTED_FONTS - detected)
    unexpected_fonts = sorted(POPULAR_WINDOWS_UNEXPECTED_FONTS & detected)
    measurement_deviations = _font_measurement_deviations(font_probe, detected)
    variant_deviations = _font_variant_deviations(font_probe, detected)
    document_font_deviations = _document_font_deviations(font_probe, detected)
    fallback_deviations = _fallback_stack_deviations(font_probe)
    notes: list[str] = []
    neutral_detected = sorted(POPULAR_WINDOWS_NEUTRAL_FONTS & detected)
    if neutral_detected:
        notes.append(
            "neutral cross-platform family detected: "
            + ", ".join(neutral_detected)
        )
    if font_probe.get("stable") is False:
        notes.append("repeated font enumeration was unstable")
    if font_probe.get("detectedCount") != len(detected):
        notes.append("detectedCount does not match the unique detected font set")
    meta = font_probe.get("meta") or {}
    if isinstance(meta, dict):
        skipped = meta.get("skipped") or []
        if skipped:
            unique_skipped = sorted(set(str(item) for item in skipped))
            notes.append(
                "probe workload was bounded/truncated after "
                f"{meta.get('elapsedMs')}ms; skipped sections: {', '.join(unique_skipped)}"
            )
    if not any(
        (
            missing_fonts,
            unexpected_fonts,
            measurement_deviations,
            variant_deviations,
            document_font_deviations,
            fallback_deviations,
        )
    ):
        notes.append("no built-in popular-Windows deviations found")

    return {
        "probe": [],
        "missing_fonts": missing_fonts,
        "unexpected_fonts": unexpected_fonts,
        "measurement": measurement_deviations,
        "variants": variant_deviations,
        "font_api": document_font_deviations,
        "fallback": fallback_deviations,
        "notes": notes,
    }


def _popular_windows_deviation_count(report: dict[str, list[str]]) -> int:
    return sum(len(rows) for key, rows in report.items() if key != "notes")


def print_popular_windows_comparison(
    result: dict[str, Any],
    *,
    max_diffs: int,
) -> None:
    report = popular_windows_deviation_report(result)
    deviation_count = _popular_windows_deviation_count(report)

    print()
    print("Popular Windows Residential Baseline")
    print(f"Reference: {POPULAR_WINDOWS_BASELINE_NAME}")
    print(f"Basis: {POPULAR_WINDOWS_BASELINE_BASIS}")
    print(f"Deviation count: {deviation_count}")
    print()
    _print_limited("Expected Windows font families missing:", report["missing_fonts"], max_rows=max_diffs)


def print_baseline_comparison(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    threshold: float,
    max_diffs: int,
) -> None:
    baseline_probe = baseline.get("fontProbe") or {}
    current_probe = current.get("fontProbe") or {}
    if not isinstance(baseline_probe, dict) or not isinstance(current_probe, dict):
        print("Baseline comparison unavailable: fontProbe data is missing or malformed.")
        return

    baseline_detected = set(str(font) for font in (baseline_probe.get("detected") or []))
    current_detected = set(str(font) for font in (current_probe.get("detected") or []))
    missing = sorted(baseline_detected - current_detected)
    extra = sorted(current_detected - baseline_detected)

    print()
    print("Windows Chrome Baseline Diff")
    print(f"Baseline detected: {len(baseline_detected)}")
    print(f"Current detected:  {len(current_detected)}")
    print(f"Exact detected-set match: {baseline_detected == current_detected}")
    print(f"Measurement threshold: {threshold:g} CSS px")
    print()

    _print_limited("Fonts detected in baseline but not current:", missing, max_rows=max_diffs)
    print()
    _print_limited("Fonts detected in current but not baseline:", extra, max_rows=max_diffs)
    print()
    _print_limited(
        "Generic fallback width differences:",
        _base_width_differences(baseline_probe, current_probe, threshold=threshold),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "Per-font measurement differences:",
        _measurement_differences(baseline_probe, current_probe, threshold=threshold),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "Style/weight variant measurement differences:",
        _nested_numeric_differences(
            baseline_probe.get("variantMeasurements") or {},
            current_probe.get("variantMeasurements") or {},
            threshold=threshold,
            path="variantMeasurements",
        ),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "Fallback-stack measurement differences:",
        _nested_numeric_differences(
            baseline_probe.get("fallbackStackMeasurements") or {},
            current_probe.get("fallbackStackMeasurements") or {},
            threshold=threshold,
            path="fallbackStackMeasurements",
        ),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "document.fonts differences:",
        _nested_numeric_differences(
            baseline_probe.get("documentFonts") or {},
            current_probe.get("documentFonts") or {},
            threshold=threshold,
            path="documentFonts",
        ),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "Browser profile differences:",
        _profile_differences(baseline, current),
        max_rows=max_diffs,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Check and compare browser font enumeration behavior.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=FONT_PROBE_TIMEOUT,
        help="Seconds to wait for Chromium/browser work.",
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        help="Write the raw current probe result as a baseline JSON, e.g. from Windows Chrome.",
    )
    parser.add_argument(
        "--compare-baseline",
        type=Path,
        help="Compare the current probe result against a baseline JSON from --write-baseline.",
    )
    parser.add_argument(
        "--diff-threshold",
        type=float,
        default=0.0,
        help="Ignore numeric canvas width deltas at or below this CSS-pixel threshold.",
    )
    parser.add_argument(
        "--max-diffs",
        type=int,
        default=80,
        help="Maximum rows to print per diff section; use 0 for all.",
    )
    args = parser.parse_args()

    result, error = _run_font_probe(args.timeout)
    popular_report: dict[str, list[str]] | None = None
    if result is None:
        return print_browser_probe_error(error or "Browser font probe failed.")

    score, description = _score_font_result(result)
    popular_report = popular_windows_deviation_report(result)
    deviation_count = _popular_windows_deviation_count(popular_report)
    description = f"{description} Popular Windows baseline deviations: {deviation_count}."

    print_browser_detection_header("Font Enumeration Home-Browser Plausibility Check")
    print_browser_detection_score_footer(score, description)
    print(f"STATUS: {description}")

    if result is not None:
        print_popular_windows_comparison(result, max_diffs=args.max_diffs)

    if result is not None and args.write_baseline:
        args.write_baseline.parent.mkdir(parents=True, exist_ok=True)
        with args.write_baseline.open("w", encoding="utf-8") as fh:
            json.dump(_baseline_payload(result), fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"Baseline written: {args.write_baseline}")

    if result is not None and args.compare_baseline:
        baseline = _read_probe_result(args.compare_baseline)
        print_baseline_comparison(
            baseline,
            result,
            threshold=max(0.0, args.diff_threshold),
            max_diffs=args.max_diffs,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
