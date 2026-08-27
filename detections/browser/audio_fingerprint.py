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

import argparse
import json
import queue
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from detections.common.common_browser import (
    close_driver,
    DEFAULT_TIMEOUT,
    build_driver_with_fallback,
    print_browser_detection_header,
    print_browser_detection_score_footer,
)

DRIVER_START_TIMEOUT = 45
PROGRESS_INTERVAL = 5
AUDIO_PROBE_TIMEOUT = max(DEFAULT_TIMEOUT, 25)


AUDIO_PROBE_JS = r"""
const callback = arguments[arguments.length - 1];
function finish(value) {
  if (typeof callback === "function") {
    callback(value);
  }
}

function toHex(buffer) {
  const view = new Uint8Array(buffer);
  return Array.from(view)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function normalizeSample(value) {
  return Math.round((Number(value) || 0) * 1000000) / 1000000;
}

function samplePrefix(array, limit = 128) {
  return Array.from(array).slice(0, limit).map(normalizeSample);
}

function summarizeAudioBuffer(buffer, label) {
  const channelSummaries = [];
  const hashParts = [];
  for (let channel = 0; channel < buffer.numberOfChannels; channel++) {
    const data = buffer.getChannelData(channel);
    let sum = 0;
    let absSum = 0;
    let sqSum = 0;
    let min = Infinity;
    let max = -Infinity;
    let zeroCrossings = 0;
    let nonZeroCount = 0;
    let prev = 0;
    let peakAbs = 0;
    let peakIndex = 0;
    for (let i = 0; i < data.length; i++) {
      const value = Number(data[i]) || 0;
      const normalized = normalizeSample(value);
      sum += value;
      absSum += Math.abs(value);
      sqSum += value * value;
      if (value < min) min = value;
      if (value > max) max = value;
      if (Math.abs(normalized) > 0) nonZeroCount++;
      if (i > 0 && ((prev < 0 && value >= 0) || (prev >= 0 && value < 0))) {
        zeroCrossings++;
      }
      if (Math.abs(value) > peakAbs) {
        peakAbs = Math.abs(value);
        peakIndex = i;
      }
      prev = value;
    }
    const prefix = samplePrefix(data);
    hashParts.push(prefix.join(","));
    channelSummaries.push({
      channel,
      length: data.length,
      mean: normalizeSample(sum / data.length),
      absMean: normalizeSample(absSum / data.length),
      rms: normalizeSample(Math.sqrt(sqSum / data.length)),
      min: normalizeSample(min),
      max: normalizeSample(max),
      zeroCrossings,
      nonZeroRatio: normalizeSample(nonZeroCount / data.length),
      peakAbs: normalizeSample(peakAbs),
      peakIndex,
      prefix,
    });
  }
  return {
    label,
    sampleRate: buffer.sampleRate,
    length: buffer.length,
    duration: normalizeSample(buffer.duration),
    numberOfChannels: buffer.numberOfChannels,
    channels: channelSummaries,
    hashInput: hashParts.join("|"),
  };
}

async function sha256(text) {
  if (!(window.crypto && window.crypto.subtle && typeof window.crypto.subtle.digest === "function")) {
    return null;
  }
  const encoded = new TextEncoder().encode(text);
  const digest = await window.crypto.subtle.digest("SHA-256", encoded);
  return toHex(digest);
}

async function renderTriangleBasic(context) {
  const oscillator = context.createOscillator();
  const gain = context.createGain();
  oscillator.type = "triangle";
  oscillator.frequency.value = 440;
  gain.gain.value = 0.2;
  oscillator.connect(gain);
  gain.connect(context.destination);
  oscillator.start(0);
  oscillator.stop(0.08);
}

async function renderSineCompressor(context) {
  const oscillator = context.createOscillator();
  const gain = context.createGain();
  const compressor = context.createDynamicsCompressor();
  oscillator.type = "sine";
  oscillator.frequency.value = 997;
  gain.gain.value = 0.35;
  compressor.threshold.value = -50;
  compressor.knee.value = 40;
  compressor.ratio.value = 12;
  compressor.attack.value = 0;
  compressor.release.value = 0.25;
  oscillator.connect(gain);
  gain.connect(compressor);
  compressor.connect(context.destination);
  oscillator.start(0);
  oscillator.stop(0.12);
}

async function renderSawBiquad(context) {
  const oscillator = context.createOscillator();
  const filter = context.createBiquadFilter();
  const gain = context.createGain();
  oscillator.type = "sawtooth";
  oscillator.frequency.value = 223;
  filter.type = "lowpass";
  filter.frequency.value = 1400;
  filter.Q.value = 7.5;
  gain.gain.value = 0.18;
  oscillator.connect(filter);
  filter.connect(gain);
  gain.connect(context.destination);
  oscillator.start(0);
  oscillator.frequency.linearRampToValueAtTime(883, 0.14);
  oscillator.stop(0.16);
}

async function renderStereoPanner(context) {
  const oscillator = context.createOscillator();
  const gain = context.createGain();
  const panner = context.createStereoPanner ? context.createStereoPanner() : null;
  oscillator.type = "square";
  oscillator.frequency.value = 330;
  gain.gain.value = 0.12;
  oscillator.connect(gain);
  if (panner) {
    panner.pan.setValueAtTime(-0.75, 0);
    panner.pan.linearRampToValueAtTime(0.75, 0.12);
    gain.connect(panner);
    panner.connect(context.destination);
  } else {
    gain.connect(context.destination);
  }
  oscillator.start(0);
  oscillator.stop(0.14);
}

async function renderConvolver(context) {
  const oscillator = context.createOscillator();
  const convolver = context.createConvolver();
  const gain = context.createGain();
  const impulse = context.createBuffer(1, 128, context.sampleRate);
  const impulseData = impulse.getChannelData(0);
  for (let i = 0; i < impulseData.length; i++) {
    impulseData[i] = Math.pow(1 - i / impulseData.length, 2) * (i % 2 ? -0.2 : 0.2);
  }
  convolver.buffer = impulse;
  oscillator.type = "triangle";
  oscillator.frequency.value = 523.25;
  gain.gain.value = 0.16;
  oscillator.connect(convolver);
  convolver.connect(gain);
  gain.connect(context.destination);
  oscillator.start(0);
  oscillator.stop(0.08);
}

async function renderGraph(OfflineAudioContextClass, graph) {
  const channels = graph.channels || 1;
  const sampleRate = graph.sampleRate || 44100;
  const length = graph.length || Math.floor(sampleRate * 0.25);
  const context = new OfflineAudioContextClass(channels, length, sampleRate);
  await graph.build(context);
  const buffer = await context.startRendering();
  const summary = summarizeAudioBuffer(buffer, graph.label);
  const hash = await sha256(JSON.stringify(summary));
  summary.hash = hash;
  delete summary.hashInput;
  return {
    ok: true,
    label: graph.label,
    context: {
      sampleRate: context.sampleRate,
      length,
      channels,
    },
    summary,
  };
}

async function renderOnlineProbe(AudioContextClass) {
  const context = new AudioContextClass({ sampleRate: 44100 });
  const analyser = context.createAnalyser();
  const oscillator = context.createOscillator();
  const gain = context.createGain();
  analyser.fftSize = 2048;
  oscillator.type = "triangle";
  oscillator.frequency.value = 440;
  gain.gain.value = 0.15;
  oscillator.connect(gain);
  gain.connect(analyser);
  analyser.connect(context.destination);
  if (typeof context.resume === "function") {
    try { await context.resume(); } catch (ignore) {}
  }
  oscillator.start(0);
  await new Promise((resolve) => setTimeout(resolve, 250));
  const timeDomain = new Float32Array(analyser.fftSize);
  const frequency = new Uint8Array(analyser.frequencyBinCount);
  analyser.getFloatTimeDomainData(timeDomain);
  analyser.getByteFrequencyData(frequency);
  try {
    oscillator.stop();
  } catch (ignore) {}
  try {
    await context.close();
  } catch (ignore) {}
  const timePrefix = samplePrefix(timeDomain);
  const freqPrefix = Array.from(frequency.slice(0, 128));
  return {
    ok: true,
    label: "onlineAnalyser",
    sampleRate: context.sampleRate || null,
    baseLatency: normalizeSample(context.baseLatency),
    outputLatency: normalizeSample(context.outputLatency),
    state: context.state || "",
    timePrefix,
    frequencyPrefix: freqPrefix,
    hash: await sha256(JSON.stringify({ timePrefix, freqPrefix })),
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
    pdfViewerEnabled: navigator.pdfViewerEnabled,
    screenWidth: screen.width || null,
    screenHeight: screen.height || null,
    colorDepth: screen.colorDepth || null,
    pixelDepth: screen.pixelDepth || null,
    outerWidth: window.outerWidth || null,
    outerHeight: window.outerHeight || null,
  };
}

async function collectMediaDeviceSurface() {
  const mediaDevices = navigator.mediaDevices || null;
  const out = {
    mediaDevices: Boolean(mediaDevices),
    enumerateDevices: Boolean(mediaDevices && typeof mediaDevices.enumerateDevices === "function"),
    getUserMedia: Boolean(mediaDevices && typeof mediaDevices.getUserMedia === "function"),
    deviceCounts: {},
    devices: [],
    error: null,
    htmlMediaElementSinkId: "sinkId" in HTMLMediaElement.prototype,
    audioCanPlayType: {},
  };
  const audio = document.createElement("audio");
  for (const [key, mime] of Object.entries({
    wav: "audio/wav",
    mp3: "audio/mpeg",
    opus: 'audio/ogg; codecs="opus"',
    webmOpus: 'audio/webm; codecs="opus"',
    aac: "audio/aac",
  })) {
    try {
      out.audioCanPlayType[key] = audio.canPlayType(mime) || "";
    } catch (e) {
      out.audioCanPlayType[key] = "error:" + String(e && e.message ? e.message : e);
    }
  }
  if (!out.enumerateDevices) {
    return out;
  }
  try {
    const devices = await mediaDevices.enumerateDevices();
    for (const device of devices) {
      const item = {
        kind: device.kind || "",
        hasLabel: Boolean(device.label),
        hasDeviceId: Boolean(device.deviceId),
        hasGroupId: Boolean(device.groupId),
      };
      out.devices.push(item);
      out.deviceCounts[item.kind] = (out.deviceCounts[item.kind] || 0) + 1;
    }
  } catch (e) {
    out.error = String(e && e.message ? e.message : e);
  }
  return out;
}

(async () => {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    const OfflineAudioContextClass = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    const apis = {
      audioContext: !!AudioContextClass,
      offlineAudioContext: !!OfflineAudioContextClass,
      webkitAudioContext: Boolean(window.webkitAudioContext),
      audioWorklet: false,
      hasOscillator: false,
      hasAnalyser: false,
      hasBiquadFilter: false,
      hasDynamicsCompressor: false,
      hasConvolver: false,
      hasStereoPanner: false,
      hasMediaStreamDestination: false,
      hasChannelMerger: false,
      hasChannelSplitter: false,
      cryptoDigest: Boolean(window.crypto && window.crypto.subtle && typeof window.crypto.subtle.digest === "function"),
    };
    const profile = makeProfile();
    const mediaDevices = await collectMediaDeviceSurface();

    if (!AudioContextClass && !OfflineAudioContextClass) {
      finish({
        ok: true,
        apis,
        profile,
        mediaDevices,
        available: false,
        reason: "AudioContext/OfflineAudioContext unavailable",
      });
      return;
    }

    const contextAttributes = {};
    let liveCtx = null;
    if (AudioContextClass) {
      try {
        liveCtx = new AudioContextClass({ sampleRate: 44100 });
        apis.audioWorklet = Boolean(liveCtx.audioWorklet);
        contextAttributes.sampleRate = liveCtx.sampleRate || null;
        contextAttributes.state = liveCtx.state || "";
        contextAttributes.baseLatency = normalizeSample(liveCtx.baseLatency);
        contextAttributes.outputLatency = normalizeSample(liveCtx.outputLatency);
        contextAttributes.destinationMaxChannelCount = liveCtx.destination ? liveCtx.destination.maxChannelCount : null;
        contextAttributes.destinationChannelCount = liveCtx.destination ? liveCtx.destination.channelCount : null;
      } catch (ignore) {
      }
    }
    const probeCtx = OfflineAudioContextClass
      ? new OfflineAudioContextClass(2, 44100, 44100)
      : (liveCtx || new AudioContextClass({ sampleRate: 44100 }));
    apis.audioWorklet = Boolean(probeCtx.audioWorklet);
    apis.audioWorklet = apis.audioWorklet || Boolean(liveCtx && liveCtx.audioWorklet);
    apis.hasOscillator = typeof probeCtx.createOscillator === "function";
    apis.hasAnalyser = typeof probeCtx.createAnalyser === "function";
    apis.hasBiquadFilter = typeof probeCtx.createBiquadFilter === "function";
    apis.hasDynamicsCompressor = typeof probeCtx.createDynamicsCompressor === "function";
    apis.hasConvolver = typeof probeCtx.createConvolver === "function";
    apis.hasStereoPanner = typeof probeCtx.createStereoPanner === "function";
    apis.hasMediaStreamDestination = typeof probeCtx.createMediaStreamDestination === "function";
    apis.hasChannelMerger = typeof probeCtx.createChannelMerger === "function";
    apis.hasChannelSplitter = typeof probeCtx.createChannelSplitter === "function";
    contextAttributes.sampleRate = contextAttributes.sampleRate || probeCtx.sampleRate || null;
    contextAttributes.state = contextAttributes.state || probeCtx.state || "";
    contextAttributes.baseLatency = contextAttributes.baseLatency || normalizeSample(probeCtx.baseLatency);
    contextAttributes.outputLatency = contextAttributes.outputLatency || normalizeSample(probeCtx.outputLatency);
    contextAttributes.destinationMaxChannelCount = contextAttributes.destinationMaxChannelCount || (probeCtx.destination ? probeCtx.destination.maxChannelCount : null);
    contextAttributes.destinationChannelCount = contextAttributes.destinationChannelCount || (probeCtx.destination ? probeCtx.destination.channelCount : null);
    try {
      if (probeCtx !== liveCtx && typeof probeCtx.close === "function") {
        await probeCtx.close();
      }
    } catch (ignore) {}

    const graphs = [];
    const graphErrors = {};
    const offlineGraphs = [
      { label: "triangleBasic", channels: 1, sampleRate: 44100, length: 44100, build: renderTriangleBasic },
      { label: "sineCompressor", channels: 1, sampleRate: 44100, length: 44100, build: renderSineCompressor },
      { label: "sawBiquad", channels: 1, sampleRate: 44100, length: 44100, build: renderSawBiquad },
      { label: "stereoPanner", channels: 2, sampleRate: 44100, length: 44100, build: renderStereoPanner },
      { label: "convolver", channels: 1, sampleRate: 48000, length: 48000, build: renderConvolver },
    ];

    if (OfflineAudioContextClass) {
      for (const graph of offlineGraphs) {
        try {
          graphs.push(await renderGraph(OfflineAudioContextClass, graph));
        } catch (e) {
          graphErrors[graph.label] = String(e && e.message ? e.message : e);
        }
      }
    } else if (AudioContextClass) {
      try {
        graphs.push(await renderOnlineProbe(AudioContextClass));
      } catch (e) {
        graphErrors.onlineAnalyser = String(e && e.message ? e.message : e);
      }
    }

    let repeated = null;
    if (OfflineAudioContextClass) {
      try {
        const first = await renderGraph(OfflineAudioContextClass, offlineGraphs[0]);
        const second = await renderGraph(OfflineAudioContextClass, offlineGraphs[0]);
        repeated = {
          label: "triangleBasic",
          firstHash: first.summary.hash,
          secondHash: second.summary.hash,
          stable: Boolean(first.summary.hash && first.summary.hash === second.summary.hash),
        };
      } catch (e) {
        repeated = { label: "triangleBasic", stable: null, error: String(e && e.message ? e.message : e) };
      }
    }

    try {
      if (liveCtx && typeof liveCtx.close === "function") {
        await liveCtx.close();
      }
    } catch (ignore) {}

    const availableGraphs = graphs.filter((graph) => graph && graph.ok);
    const zeroOutput = availableGraphs.length > 0 && availableGraphs.every((graph) => {
      const channels = graph.summary && graph.summary.channels ? graph.summary.channels : [];
      return channels.every((channel) => channel.nonZeroRatio === 0);
    });
    const hash = availableGraphs.map((graph) => graph.summary && graph.summary.hash).filter(Boolean).join("|") || null;

    finish({
      ok: true,
      apis,
      profile,
      mediaDevices,
      contextAttributes,
      available: true,
      graphs,
      graphErrors,
      repeated,
      stable: repeated ? repeated.stable : null,
      hash,
      zeroOutput,
      reason: availableGraphs.length ? "Audio probe completed" : "Audio APIs exist but no render graph completed",
    });
  } catch (e) {
    finish({ ok: false, error: String(e && e.message ? e.message : e) });
  }
})().then(undefined, (e) => finish({ ok: false, error: String(e && e.message ? e.message : e) }));
"""


class AudioProbeHandler(BaseHTTPRequestHandler):
    server_version = "OverdriveAudioProbe/1.0"

    def log_message(self, _fmt: str, *_args) -> None:
        return

    def do_GET(self) -> None:
        body = b"<!doctype html><meta charset='utf-8'><title>Audio Probe</title>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_audio_probe_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), AudioProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="audio-probe")
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


POPULAR_WINDOWS_AUDIO_BASELINE_NAME = "popular Windows residential desktop audio"
POPULAR_WINDOWS_AUDIO_BASELINE_BASIS = (
    "Windows 11 + Google Chrome desktop. Built-in checks use broad API/profile/render "
    "expectations; use --compare-baseline for exact graph-summary diffs from a captured reference."
)

EXPECTED_AUDIO_APIS = (
    "audioContext",
    "offlineAudioContext",
    "hasOscillator",
    "hasAnalyser",
    "hasBiquadFilter",
    "hasDynamicsCompressor",
    "hasConvolver",
    "hasStereoPanner",
    "hasChannelMerger",
    "hasChannelSplitter",
    "cryptoDigest",
)

EXPECTED_RENDER_GRAPHS = {
    "triangleBasic": {"sampleRate": 44100, "channels": 1},
    "sineCompressor": {"sampleRate": 44100, "channels": 1},
    "sawBiquad": {"sampleRate": 44100, "channels": 1},
    "stereoPanner": {"sampleRate": 44100, "channels": 2},
    "convolver": {"sampleRate": 48000, "channels": 1},
}


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
    if isinstance(baseline_value, list) and isinstance(current_value, list):
        for index in range(max(len(baseline_value), len(current_value))):
            left = baseline_value[index] if index < len(baseline_value) else None
            right = current_value[index] if index < len(current_value) else None
            child_path = f"{path}[{index}]"
            differences.extend(
                _nested_numeric_differences(left, right, threshold=threshold, path=child_path)
            )
        return differences

    baseline_num = _number(baseline_value)
    current_num = _number(current_value)
    if baseline_num is not None and current_num is not None:
        delta = current_num - baseline_num
        if abs(delta) > threshold:
            differences.append(
                f"{path}: baseline={baseline_num:.6f} current={current_num:.6f} delta={delta:+.6f}"
            )
    elif baseline_value != current_value:
        differences.append(f"{path}: baseline={_fmt(baseline_value)} current={_fmt(current_value)}")
    return differences


def _popular_windows_audio_profile_deviations(result: dict[str, Any]) -> list[str]:
    profile = result.get("profile") or {}
    if not isinstance(profile, dict):
        return ["profile data is missing or malformed"]

    deviations: list[str] = []
    ua = str(profile.get("userAgent") or "")
    ua_lower = ua.lower()
    vendor = str(profile.get("vendor") or "")
    platform = str(profile.get("platform") or "")
    platform_lower = platform.lower()
    languages = profile.get("languages") or []
    plugins_len = profile.get("pluginsLength")
    mime_types_len = profile.get("mimeTypesLength")
    color_depth = profile.get("colorDepth")
    width = profile.get("screenWidth")
    height = profile.get("screenHeight")
    outer_width = profile.get("outerWidth")
    outer_height = profile.get("outerHeight")

    if "headless" in ua_lower:
        deviations.append("User-Agent contains a headless browser token")
    if "chrome/" not in ua_lower:
        deviations.append("User-Agent is not Google Chrome-like")
    if "edg/" in ua_lower:
        deviations.append("User-Agent contains an Edge token; reference is Google Chrome")
    if "windows nt 10.0" not in ua_lower:
        deviations.append("User-Agent does not expose the modern Windows NT 10.0 desktop token")
    if platform_lower not in {"win32", "win64"}:
        deviations.append(f"navigator.platform is {platform or 'empty'}, expected Win32 or Win64")
    if vendor != "Google Inc.":
        deviations.append(f"navigator.vendor is {vendor or 'empty'}, expected Google Inc.")
    if profile.get("webdriver"):
        deviations.append("navigator.webdriver is true")
    if not languages:
        deviations.append("navigator.languages is empty")
    if not isinstance(plugins_len, int) or plugins_len <= 0:
        deviations.append(f"navigator.plugins length is {plugins_len}, expected a positive count")
    if not isinstance(mime_types_len, int) or mime_types_len <= 0:
        deviations.append(f"navigator.mimeTypes length is {mime_types_len}, expected a positive count")
    if color_depth not in (24, 30, 32):
        deviations.append(f"screen.colorDepth is {color_depth}, expected 24/30/32")
    if isinstance(width, int) and isinstance(height, int) and (width < 1366 or height < 768):
        deviations.append(f"screen size {width}x{height} is below a common Windows desktop/laptop baseline")
    if outer_width == 0 or outer_height == 0:
        deviations.append("window.outerWidth/outerHeight are zero")

    return deviations


def _audio_api_deviations(result: dict[str, Any]) -> list[str]:
    apis = result.get("apis") or {}
    if not isinstance(apis, dict):
        return ["audio API table is missing or malformed"]

    deviations: list[str] = []
    for key in EXPECTED_AUDIO_APIS:
        if apis.get(key) is not True:
            deviations.append(f"{key} is {apis.get(key)!r}, expected true")
    # AudioWorklet can vary in automation/headless, but modern desktop Chrome usually exposes it.
    if apis.get("audioWorklet") is not True:
        deviations.append(f"audioWorklet is {apis.get('audioWorklet')!r}, expected true in modern Chrome")
    if apis.get("webkitAudioContext"):
        deviations.append("webkitAudioContext legacy alias is exposed")
    return deviations


def _context_deviations(result: dict[str, Any]) -> list[str]:
    context = result.get("contextAttributes") or {}
    if not isinstance(context, dict):
        return ["audio context attributes are missing or malformed"]

    deviations: list[str] = []
    sample_rate = context.get("sampleRate")
    if sample_rate not in (44100, 48000):
        deviations.append(f"context sampleRate is {sample_rate}, expected 44100 or 48000")
    max_channels = context.get("destinationMaxChannelCount")
    if isinstance(max_channels, int) and max_channels < 2:
        deviations.append(f"destination max channel count is {max_channels}, expected at least stereo")
    channel_count = context.get("destinationChannelCount")
    if isinstance(channel_count, int) and channel_count < 1:
        deviations.append(f"destination channel count is {channel_count}, expected a positive count")
    return deviations


def _media_device_deviations(result: dict[str, Any]) -> list[str]:
    media = result.get("mediaDevices") or {}
    if not isinstance(media, dict):
        return ["media-device surface is missing or malformed"]

    deviations: list[str] = []
    if media.get("mediaDevices") is not True:
        deviations.append("navigator.mediaDevices is unavailable")
    if media.get("enumerateDevices") is not True:
        deviations.append("navigator.mediaDevices.enumerateDevices is unavailable")
    if media.get("getUserMedia") is not True:
        deviations.append("navigator.mediaDevices.getUserMedia is unavailable")
    if media.get("htmlMediaElementSinkId") is not True:
        deviations.append("HTMLMediaElement.sinkId is unavailable")
    if media.get("error"):
        deviations.append(f"enumerateDevices error: {media.get('error')}")

    can_play = media.get("audioCanPlayType") or {}
    if not isinstance(can_play, dict):
        deviations.append("audio canPlayType table is missing or malformed")
    else:
        for codec in ("wav", "mp3", "webmOpus"):
            value = str(can_play.get(codec) or "")
            if value not in {"probably", "maybe"}:
                deviations.append(f"audio.canPlayType({codec}) returned {value or 'empty'}")

    counts = media.get("deviceCounts") or {}
    if isinstance(counts, dict):
        if not counts and media.get("enumerateDevices") is True:
            deviations.append("enumerateDevices returned no devices; typical Windows Chrome exposes default redacted devices")
        elif "audiooutput" not in counts:
            deviations.append("enumerateDevices did not expose an audiooutput device kind")
    return deviations


def _graph_by_label(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    graphs = result.get("graphs") or []
    if not isinstance(graphs, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for graph in graphs:
        if isinstance(graph, dict):
            label = str(graph.get("label") or "")
            if label:
                out[label] = graph
    return out


def _render_graph_deviations(result: dict[str, Any]) -> list[str]:
    graphs = _graph_by_label(result)
    deviations: list[str] = []
    graph_errors = result.get("graphErrors") or {}
    if isinstance(graph_errors, dict):
        for label, error in sorted(graph_errors.items()):
            deviations.append(f"{label} render error: {error}")

    for label, expected in EXPECTED_RENDER_GRAPHS.items():
        graph = graphs.get(label)
        if not graph:
            deviations.append(f"missing expected render graph: {label}")
            continue
        summary = graph.get("summary") or {}
        if not isinstance(summary, dict):
            deviations.append(f"{label}: summary is missing or malformed")
            continue
        if summary.get("sampleRate") != expected["sampleRate"]:
            deviations.append(f"{label}: sampleRate={summary.get('sampleRate')} expected {expected['sampleRate']}")
        if summary.get("numberOfChannels") != expected["channels"]:
            deviations.append(f"{label}: channels={summary.get('numberOfChannels')} expected {expected['channels']}")
        if not summary.get("hash"):
            deviations.append(f"{label}: render hash is missing")
        channels = summary.get("channels") or []
        if not isinstance(channels, list) or not channels:
            deviations.append(f"{label}: channel summaries are missing")
            continue
        for channel in channels:
            if not isinstance(channel, dict):
                deviations.append(f"{label}: malformed channel summary")
                continue
            non_zero = _number(channel.get("nonZeroRatio"))
            rms = _number(channel.get("rms"))
            peak = _number(channel.get("peakAbs"))
            if non_zero is None or non_zero < 0.01:
                deviations.append(f"{label}: channel {channel.get('channel')} nonZeroRatio={non_zero}, expected active output")
            if rms is None or rms <= 0 or rms > 0.5:
                deviations.append(f"{label}: channel {channel.get('channel')} rms={rms}, expected non-zero bounded output")
            if peak is None or peak <= 0 or peak > 1.01:
                deviations.append(f"{label}: channel {channel.get('channel')} peakAbs={peak}, expected 0 < peak <= 1")

    repeated = result.get("repeated") or {}
    if not isinstance(repeated, dict):
        deviations.append("repeated render stability data is missing")
    elif repeated.get("stable") is not True:
        deviations.append(f"repeated render stability is {repeated.get('stable')}, expected true")

    if result.get("zeroOutput"):
        deviations.append("all render graphs returned zero output")
    if not result.get("hash"):
        deviations.append("combined audio hash is missing")

    return deviations


def popular_windows_audio_deviation_report(result: dict[str, Any]) -> dict[str, list[str]]:
    if not result.get("ok"):
        return {
            "probe": [f"probe failed: {result.get('error', 'unknown error')}"],
            "profile": [],
            "apis": [],
            "context": [],
            "media_devices": [],
            "render_graphs": [],
            "notes": [],
        }
    notes: list[str] = []
    if not result.get("available"):
        return {
            "probe": [f"audio unavailable: {result.get('reason', 'unknown reason')}"],
            "profile": _popular_windows_audio_profile_deviations(result),
            "apis": _audio_api_deviations(result),
            "context": [],
            "media_devices": _media_device_deviations(result),
            "render_graphs": [],
            "notes": [],
        }

    report = {
        "probe": [],
        "profile": _popular_windows_audio_profile_deviations(result),
        "apis": _audio_api_deviations(result),
        "context": _context_deviations(result),
        "media_devices": _media_device_deviations(result),
        "render_graphs": _render_graph_deviations(result),
        "notes": notes,
    }
    if not any(rows for key, rows in report.items() if key != "notes"):
        notes.append("no built-in popular-Windows audio deviations found")
    return report


def _popular_windows_audio_deviation_count(report: dict[str, list[str]]) -> int:
    return sum(len(rows) for key, rows in report.items() if key != "notes")


def print_popular_windows_audio_comparison(result: dict[str, Any], *, max_diffs: int) -> None:
    report = popular_windows_audio_deviation_report(result)
    deviation_count = _popular_windows_audio_deviation_count(report)
    print()
    print("Popular Windows Residential Audio Baseline")
    print(f"Reference: {POPULAR_WINDOWS_AUDIO_BASELINE_NAME}")
    print(f"Basis: {POPULAR_WINDOWS_AUDIO_BASELINE_BASIS}")
    print(f"Deviation count: {deviation_count}")
    print()
    _print_limited("Browser profile deviations:", report["profile"], max_rows=max_diffs)
    print()
    _print_limited("Audio API deviations:", report["apis"], max_rows=max_diffs)
    print()
    _print_limited("Audio context deviations:", report["context"], max_rows=max_diffs)
    print()
    _print_limited("Media-device deviations:", report["media_devices"], max_rows=max_diffs)
    print()
    _print_limited("Render-graph deviations:", report["render_graphs"], max_rows=max_diffs)
    if report["probe"]:
        print()
        _print_limited("Probe deviations:", report["probe"], max_rows=max_diffs)
    if report["notes"]:
        print()
        _print_limited("Notes:", report["notes"], max_rows=max_diffs)


def _baseline_payload(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "overdrive.browser.audio_fingerprint.baseline.v1",
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
    if isinstance(data.get("apis"), dict) and isinstance(data.get("profile"), dict):
        return data
    raise ValueError(f"{path} is not an audio_fingerprint baseline/probe JSON file")


def print_baseline_comparison(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    threshold: float,
    max_diffs: int,
) -> None:
    print()
    print("Windows Chrome Audio Baseline Diff")
    print(f"Measurement threshold: {threshold:g}")
    print()
    _print_limited(
        "API differences:",
        _nested_numeric_differences(baseline.get("apis") or {}, current.get("apis") or {}, threshold=threshold, path="apis"),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "Context differences:",
        _nested_numeric_differences(
            baseline.get("contextAttributes") or {},
            current.get("contextAttributes") or {},
            threshold=threshold,
            path="contextAttributes",
        ),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "Media-device differences:",
        _nested_numeric_differences(
            baseline.get("mediaDevices") or {},
            current.get("mediaDevices") or {},
            threshold=threshold,
            path="mediaDevices",
        ),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "Render-graph differences:",
        _nested_numeric_differences(
            baseline.get("graphs") or [],
            current.get("graphs") or [],
            threshold=threshold,
            path="graphs",
        ),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "Repeated stability differences:",
        _nested_numeric_differences(
            baseline.get("repeated") or {},
            current.get("repeated") or {},
            threshold=threshold,
            path="repeated",
        ),
        max_rows=max_diffs,
    )
    print()
    _print_limited(
        "Browser profile differences:",
        _nested_numeric_differences(
            baseline.get("profile") or {},
            current.get("profile") or {},
            threshold=threshold,
            path="profile",
        ),
        max_rows=max_diffs,
    )


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


def _start_driver_with_progress(timeout: int) -> tuple[Any | None, str | None]:
    deadline = time.monotonic() + max(1, timeout)
    result_queue: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            result_queue.put(("driver", build_driver_with_fallback()))
        except Exception as exc:
            result_queue.put(("error", exc))

    thread = threading.Thread(target=worker, name="audio-webdriver-start", daemon=True)
    thread.start()

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, f"Timed out after {timeout}s while starting Selenium WebDriver."
        try:
            kind, value = result_queue.get(timeout=min(PROGRESS_INTERVAL, max(0.1, remaining)))
        except queue.Empty:
            remaining = deadline - time.monotonic()
            print(
                f"[audio] Still starting Selenium WebDriver... {max(0, int(remaining))}s before timeout",
                flush=True,
            )
            continue
        if kind == "driver":
            print("[audio] Selenium WebDriver started.", flush=True)
            return value, None
        return None, f"Unable to start Selenium WebDriver: {type(value).__name__}: {value}"


def _run_selenium_audio_probe(timeout: int = AUDIO_PROBE_TIMEOUT) -> tuple[dict[str, Any] | None, str | None]:
    """Run the in-browser audio probe and return raw result data."""
    server = None
    driver = None
    startup_timeout = max(DRIVER_START_TIMEOUT, timeout)
    print(f"[audio] Starting Selenium WebDriver (timeout {startup_timeout}s)...", flush=True)
    driver, error = _start_driver_with_progress(startup_timeout)
    if driver is None:
        return None, error or "Unable to start Selenium WebDriver."

    try:
        print("[audio] Starting local audio probe server...", flush=True)
        server, url = start_audio_probe_server()
        print(f"[audio] Loading probe page: {url}", flush=True)
        driver.set_page_load_timeout(timeout)
        driver.set_script_timeout(timeout)
        driver.get(url)
        print("[audio] Running browser audio probe JavaScript...", flush=True)
        result = driver.execute_async_script(AUDIO_PROBE_JS)
        print("[audio] Browser audio probe returned data.", flush=True)
    except Exception as exc:
        try:
            close_driver(driver)
        except Exception:
            pass
        if server is not None:
            server.shutdown()
            server.server_close()
        return None, f"Selenium run failed: {type(exc).__name__}: {exc}"

    try:
        print("[audio] Closing WebDriver...", flush=True)
        close_driver(driver)
    except Exception:
        pass
    if server is not None:
        print("[audio] Stopping local audio probe server...", flush=True)
        server.shutdown()
        server.server_close()

    if not isinstance(result, dict):
        return None, "Audio fingerprint detection returned unexpected data."

    return result, None


def check_audio_fingerprint(timeout: int = AUDIO_PROBE_TIMEOUT) -> tuple[int, str]:
    """
    Check for audio context fingerprinting.
    Returns (score, description)
    """
    result, error = _run_selenium_audio_probe(timeout)
    if result is None:
        return 3, error or "Audio fingerprint detection failed."

    return _score_audio_result(result)


def main() -> None:
    parser = argparse.ArgumentParser(description="Detect and compare browser audio fingerprint behavior.")
    parser.add_argument("--timeout", type=int, default=AUDIO_PROBE_TIMEOUT, help="Seconds to wait for Selenium/browser work.")
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
        help="Ignore numeric graph-summary deltas at or below this threshold.",
    )
    parser.add_argument(
        "--max-diffs",
        type=int,
        default=80,
        help="Maximum rows to print per diff section; use 0 for all.",
    )
    args = parser.parse_args()

    print_browser_detection_header("Audio Context Fingerprint Detection")

    result, error = _run_selenium_audio_probe(args.timeout)
    if result is None:
        from detections.common.common_browser import print_browser_probe_error

        return print_browser_probe_error(error or "Audio fingerprint detection failed.")

    score, description = _score_audio_result(result)
    popular_report = popular_windows_audio_deviation_report(result)
    deviation_count = _popular_windows_audio_deviation_count(popular_report)
    description = f"{description} Popular Windows audio baseline deviations: {deviation_count}."

    print_browser_detection_score_footer(score, description)
    print(f"STATUS: {description}")

    if result is not None:
        print_popular_windows_audio_comparison(result, max_diffs=args.max_diffs)

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
