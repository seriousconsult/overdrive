#!/usr/bin/env python3
"""
Cookie Tracking Detection

Detects whether cookies and related client-side storage behave like a typical
Windows Chrome residential browser with default settings. A browser that blocks,
partitions, or fails to persist same-origin state is less likely to match that
baseline.

Measured attributes:
- navigator.cookieEnabled
- document.cookie write/read roundtrip
- server-set, HttpOnly, SameSite, overwrite, expiry, and deletion behavior
- localStorage, sessionStorage, IndexedDB, Cache API, and Cookie Store surface

Score: 1-5
1 = authentic residential browser cookie behavior
2 = mostly normal cookie/storage behavior with minor deviations
3 = inconclusive browser/javascript result
4 = unusual browser behavior for a typical home setup
5 = strongly non-home-like cookie/storage behavior
"""

from __future__ import annotations

import json
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
    print_browser_probe_error,
)
from detections.common.direct_chromium import run_async_script

COOKIE_PROBE_TIMEOUT = max(DEFAULT_TIMEOUT, 25)

COOKIE_PROBE_JS = r"""
const callback = arguments[arguments.length - 1];
function finish(value) {
  if (typeof callback === "function") {
    callback(value);
  }
}
const FETCH_TIMEOUT_MS = 12000;

async function fetchWithTimeout(url, options = {}) {
  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  let timer = null;
  if (controller) {
    timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
      return await fetch(url, { ...options, signal: controller.signal });
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  return fetch(url, options);
}

function cookieText() {
  return document.cookie || "";
}

function hasCookie(name, value = null) {
  const wanted = value === null ? `${name}=` : `${name}=${value}`;
  return cookieText().split(/;\s*/).some((item) => item === wanted || (value === null && item.startsWith(wanted)));
}

function setCookie(line) {
  document.cookie = line;
}

function deleteCookie(name) {
  document.cookie = `${name}=; path=/; Max-Age=0; SameSite=Lax`;
}

async function fetchJson(path) {
  const response = await fetchWithTimeout(path, { credentials: "include", cache: "no-store" });
  return response.json();
}

async function testStorage(name, storage) {
  if (!storage) {
    return { available: false, writeRead: false, remove: false, error: "storage object unavailable" };
  }
  try {
    const key = `overdrive_${name}_probe`;
    storage.setItem(key, "alpha");
    const writeRead = storage.getItem(key) === "alpha";
    storage.removeItem(key);
    const remove = storage.getItem(key) === null;
    return { available: true, writeRead, remove, error: null };
  } catch (e) {
    return { available: true, writeRead: false, remove: false, error: String(e && e.message ? e.message : e) };
  }
}

function getStorageObject(name) {
  try {
    return window[name];
  } catch (e) {
    return null;
  }
}

async function testIndexedDB() {
  if (!window.indexedDB) {
    return { available: false, open: false, writeRead: false, deleteDb: false, error: "indexedDB unavailable" };
  }
  const dbName = "overdrive_cookie_probe_db";
  return new Promise((resolve) => {
    const request = indexedDB.open(dbName, 1);
    let settled = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("kv")) {
        db.createObjectStore("kv");
      }
    };
    request.onerror = () => finish({
      available: true,
      open: false,
      writeRead: false,
      deleteDb: false,
      error: String(request.error && request.error.message ? request.error.message : request.error),
    });
    request.onsuccess = () => {
      const db = request.result;
      try {
        const tx = db.transaction("kv", "readwrite");
        const store = tx.objectStore("kv");
        store.put("alpha", "probe");
        tx.oncomplete = () => {
          const readTx = db.transaction("kv", "readonly");
          const getReq = readTx.objectStore("kv").get("probe");
          getReq.onsuccess = () => {
            const writeRead = getReq.result === "alpha";
            db.close();
            const delReq = indexedDB.deleteDatabase(dbName);
            delReq.onsuccess = () => finish({ available: true, open: true, writeRead, deleteDb: true, error: null });
            delReq.onerror = () => finish({ available: true, open: true, writeRead, deleteDb: false, error: "deleteDatabase failed" });
          };
          getReq.onerror = () => {
            db.close();
            finish({ available: true, open: true, writeRead: false, deleteDb: false, error: "read failed" });
          };
        };
        tx.onerror = () => {
          db.close();
          finish({ available: true, open: true, writeRead: false, deleteDb: false, error: "write transaction failed" });
        };
      } catch (e) {
        db.close();
        finish({ available: true, open: true, writeRead: false, deleteDb: false, error: String(e && e.message ? e.message : e) });
      }
    };
    setTimeout(() => finish({ available: true, open: false, writeRead: false, deleteDb: false, error: "indexedDB timeout" }), 3000);
  });
}

async function testCacheStorage() {
  if (!window.caches) {
    return { available: false, open: false, deleteCache: false, error: "Cache API unavailable" };
  }
  const cacheName = "overdrive-cookie-probe-cache";
  try {
    await caches.open(cacheName);
    const deleteCache = await caches.delete(cacheName);
    return { available: true, open: true, deleteCache, error: null };
  } catch (e) {
    return { available: true, open: false, deleteCache: false, error: String(e && e.message ? e.message : e) };
  }
}

(async () => {
  try {
    const checks = {
      navigatorCookieEnabled: Boolean(navigator.cookieEnabled),
      documentCookieAccessor: typeof document.cookie === "string",
      jsCookie: {},
      serverCookie: {},
      storage: {},
      cookieStoreApi: {
        available: Boolean(window.cookieStore),
      },
    };

    await fetch("/clear", { credentials: "include", cache: "no-store" });

    setCookie("overdrive_js_session=alpha; path=/; SameSite=Lax");
    checks.jsCookie.sessionWriteRead = hasCookie("overdrive_js_session", "alpha");

    setCookie("overdrive_js_session=beta; path=/; SameSite=Lax");
    checks.jsCookie.overwrite = hasCookie("overdrive_js_session", "beta") && !hasCookie("overdrive_js_session", "alpha");

    setCookie("overdrive_js_strict=strict; path=/; SameSite=Strict");
    checks.jsCookie.sameSiteStrict = hasCookie("overdrive_js_strict", "strict");

    setCookie("overdrive_js_maxage=maxage; path=/; Max-Age=60; SameSite=Lax");
    checks.jsCookie.maxAge = hasCookie("overdrive_js_maxage", "maxage");

    const future = new Date(Date.now() + 60000).toUTCString();
    setCookie(`overdrive_js_expires=expires; path=/; expires=${future}; SameSite=Lax`);
    checks.jsCookie.expires = hasCookie("overdrive_js_expires", "expires");

    setCookie("overdrive_js_multi_a=a; path=/; SameSite=Lax");
    setCookie("overdrive_js_multi_b=b; path=/; SameSite=Lax");
    checks.jsCookie.multipleCookies = hasCookie("overdrive_js_multi_a", "a") && hasCookie("overdrive_js_multi_b", "b");

    deleteCookie("overdrive_js_session");
    checks.jsCookie.delete = !hasCookie("overdrive_js_session");

    await fetch("/set-http-cookie", { credentials: "include", cache: "no-store" });
    const httpOnlyEcho = await fetchJson("/echo-cookie");
    checks.serverCookie.httpOnlySentToServer = String(httpOnlyEcho.cookieHeader || "").includes("overdrive_http_only=server");
    checks.serverCookie.httpOnlyHiddenFromDocument = !hasCookie("overdrive_http_only");

    await fetch("/set-readable-cookie", { credentials: "include", cache: "no-store" });
    const readableEcho = await fetchJson("/echo-cookie");
    checks.serverCookie.readableSentToServer = String(readableEcho.cookieHeader || "").includes("overdrive_server_readable=server");
    checks.serverCookie.readableVisibleToDocument = hasCookie("overdrive_server_readable", "server");

    checks.storage.localStorage = await testStorage("local_storage", getStorageObject("localStorage"));
    checks.storage.sessionStorage = await testStorage("session_storage", getStorageObject("sessionStorage"));
    checks.storage.indexedDB = await testIndexedDB();
    checks.storage.cacheStorage = await testCacheStorage();

    finish({
      ok: true,
      checks,
      cookieTextLength: cookieText().length,
      reason: "cookie/storage probe completed",
    });
  } catch (e) {
    finish({ ok: false, error: String(e && e.message ? e.message : e) });
  }
})();
"""

class CookieProbeHandler(BaseHTTPRequestHandler):
    server_version = "OverdriveCookieProbe/1.0"
    COOKIE_NAMES = (
        "overdrive_http_only",
        "overdrive_server_readable",
        "overdrive_js_session",
        "overdrive_js_strict",
        "overdrive_js_maxage",
        "overdrive_js_expires",
        "overdrive_js_multi_a",
        "overdrive_js_multi_b",
    )

    def log_message(self, _fmt: str, *_args) -> None:
        return

    def _send_bytes(
        self,
        body: bytes,
        *,
        content_type: str = "text/plain; charset=utf-8",
        set_cookies: list[str] | None = None,
    ) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        if set_cookies:
            for cookie in set_cookies:
                self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/clear":
            expired = [
                f"{name}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax"
                for name in self.COOKIE_NAMES
            ]
            self._send_bytes(b"{}", content_type="application/json", set_cookies=expired)
            return
        if path == "/set-http-cookie":
            self._send_bytes(
                b"{}",
                content_type="application/json",
                set_cookies=["overdrive_http_only=server; Path=/; SameSite=Lax; HttpOnly"],
            )
            return
        if path == "/set-readable-cookie":
            self._send_bytes(
                b"{}",
                content_type="application/json",
                set_cookies=["overdrive_server_readable=server; Path=/; SameSite=Lax"],
            )
            return
        if path == "/echo-cookie":
            body = json.dumps(
                {"cookieHeader": self.headers.get("Cookie", "")},
                sort_keys=True,
            ).encode("utf-8")
            self._send_bytes(body, content_type="application/json")
            return

        body = b"<!doctype html><meta charset='utf-8'><title>Cookie Probe</title>"
        self._send_bytes(body, content_type="text/html; charset=utf-8")


def start_cookie_probe_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), CookieProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="cookie-probe")
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}/"


POPULAR_WINDOWS_COOKIE_BASELINE = (
    "Windows 11 + Google Chrome default residential cookie/storage behavior"
)


def _bool_deviation(value: Any, label: str, expected: bool = True) -> str | None:
    if value is expected:
        return None
    return f"{label} is {value!r}, expected {expected!r}"


def popular_windows_cookie_deviation_report(result: dict[str, Any]) -> dict[str, list[str]]:
    if not result.get("ok"):
        return {
            "probe": [f"probe failed: {result.get('error', 'unknown error')}"],
            "cookie": [],
            "server_cookie": [],
            "storage": [],
            "notes": [],
        }

    checks = result.get("checks") or {}
    if not isinstance(checks, dict):
        return {
            "probe": ["checks table is missing or malformed"],
            "cookie": [],
            "server_cookie": [],
            "storage": [],
            "notes": [],
        }

    cookie_deviations: list[str] = []
    server_deviations: list[str] = []
    storage_deviations: list[str] = []
    notes: list[str] = []

    for key, label in (
        ("navigatorCookieEnabled", "navigator.cookieEnabled"),
        ("documentCookieAccessor", "document.cookie accessor"),
    ):
        deviation = _bool_deviation(checks.get(key), label)
        if deviation:
            cookie_deviations.append(deviation)

    js_cookie = checks.get("jsCookie") or {}
    if not isinstance(js_cookie, dict):
        cookie_deviations.append("JavaScript cookie results are missing or malformed")
    else:
        for key, label in (
            ("sessionWriteRead", "session cookie write/read"),
            ("overwrite", "cookie overwrite semantics"),
            ("sameSiteStrict", "SameSite=Strict cookie write/read"),
            ("maxAge", "Max-Age cookie write/read"),
            ("expires", "Expires cookie write/read"),
            ("multipleCookies", "multiple same-origin cookies"),
            ("delete", "cookie deletion"),
        ):
            deviation = _bool_deviation(js_cookie.get(key), label)
            if deviation:
                cookie_deviations.append(deviation)

    server_cookie = checks.get("serverCookie") or {}
    if not isinstance(server_cookie, dict):
        server_deviations.append("server-observed cookie results are missing or malformed")
    else:
        for key, label in (
            ("httpOnlySentToServer", "server-set HttpOnly cookie sent back to server"),
            ("httpOnlyHiddenFromDocument", "HttpOnly cookie hidden from document.cookie"),
            ("readableSentToServer", "server-set readable cookie sent back to server"),
            ("readableVisibleToDocument", "server-set readable cookie visible to document.cookie"),
        ):
            deviation = _bool_deviation(server_cookie.get(key), label)
            if deviation:
                server_deviations.append(deviation)

    storage = checks.get("storage") or {}
    if not isinstance(storage, dict):
        storage_deviations.append("storage results are missing or malformed")
    else:
        storage_expectations = {
            "localStorage": ("localStorage", ("available", "writeRead", "remove")),
            "sessionStorage": ("sessionStorage", ("available", "writeRead", "remove")),
            "indexedDB": ("IndexedDB", ("available", "open", "writeRead", "deleteDb")),
            "cacheStorage": ("Cache API", ("available", "open", "deleteCache")),
        }
        for key, (label, expected_keys) in storage_expectations.items():
            data = storage.get(key) or {}
            if not isinstance(data, dict):
                storage_deviations.append(f"{label} result is missing or malformed")
                continue
            for expected_key in expected_keys:
                deviation = _bool_deviation(data.get(expected_key), f"{label}.{expected_key}")
                if deviation:
                    storage_deviations.append(deviation)
            if data.get("error"):
                storage_deviations.append(f"{label} error: {data.get('error')}")

    cookie_store = checks.get("cookieStoreApi") or {}
    if isinstance(cookie_store, dict) and cookie_store.get("available") is not True:
        notes.append("Cookie Store API unavailable; not scored because availability varies by Chrome build/context")

    if not cookie_deviations and not server_deviations and not storage_deviations:
        notes.append("no built-in popular-Windows cookie/storage deviations found")

    return {
        "probe": [],
        "cookie": cookie_deviations,
        "server_cookie": server_deviations,
        "storage": storage_deviations,
        "notes": notes,
    }


def _deviation_count(report: dict[str, list[str]]) -> int:
    return sum(len(rows) for key, rows in report.items() if key != "notes")


def _print_rows(title: str, rows: list[str]) -> None:
    print(title)
    if not rows:
        print("  - none")
        return
    for row in rows:
        print(f"  - {row}")


def print_cookie_deviation_report(result: dict[str, Any]) -> None:
    report = popular_windows_cookie_deviation_report(result)
    print()
    print("Popular Windows Residential Cookie/Storage Baseline")
    print(f"Reference: {POPULAR_WINDOWS_COOKIE_BASELINE}")
    print(f"Deviation count: {_deviation_count(report)}")
    print()
    _print_rows("Cookie deviations:", report["cookie"])
    print()
    _print_rows("Server-observed cookie deviations:", report["server_cookie"])
    print()
    _print_rows("Storage deviations:", report["storage"])
    if report["probe"]:
        print()
        _print_rows("Probe deviations:", report["probe"])
    if report["notes"]:
        print()
        _print_rows("Notes:", report["notes"])


def _score_cookie_result(result: dict[str, Any]) -> tuple[int, str]:
    if not result.get("ok"):
        return 3, f"Inconclusive: cookie probe failed: {result.get('error', 'unknown error')}"

    report = popular_windows_cookie_deviation_report(result)
    cookie_count = len(report["cookie"])
    server_count = len(report["server_cookie"])
    storage_count = len(report["storage"])
    total = _deviation_count(report)
    reason = result.get("reason") or "cookie/storage probe completed"

    if cookie_count + server_count >= 4:
        score = 5
    elif cookie_count + server_count:
        score = 4
    elif storage_count >= 3:
        score = 3
    elif storage_count:
        score = 2
    else:
        score = 1

    return (
        score,
        f"{reason}. Popular Windows cookie/storage baseline deviations: {total}.",
    )


def _run_chromium_cookie_probe(timeout: int = COOKIE_PROBE_TIMEOUT) -> tuple[dict[str, Any] | None, str | None]:
    server = None
    try:
        server, url = start_cookie_probe_server()
        result, error = run_async_script(COOKIE_PROBE_JS, timeout=timeout, url=url)
        if error:
            return None, f"Chromium DevTools run failed: {error}"
    except Exception as exc:
        if server is not None:
            server.shutdown()
            server.server_close()
            server = None
        return None, f"Chromium DevTools run failed: {type(exc).__name__}: {exc}"

    if server is not None:
        server.shutdown()
        server.server_close()

    if not isinstance(result, dict):
        return None, "Cookie tracking detection returned unexpected data."

    return result, None


def check_cookie_tracking(timeout: int = COOKIE_PROBE_TIMEOUT) -> tuple[int, str]:
    result, error = _run_chromium_cookie_probe(timeout)
    if result is None:
        return 3, error or "Cookie tracking detection failed."

    return _score_cookie_result(result)


def main() -> int:
    print_browser_detection_header("Cookie Tracking Detection")
    result, error = _run_chromium_cookie_probe(COOKIE_PROBE_TIMEOUT)
    if result is None:
        return print_browser_probe_error(error or "Cookie tracking detection failed.")
    score, description = _score_cookie_result(result)
    print_browser_detection_score_footer(score, description)
    print(f"STATUS: {description}")
    print_cookie_deviation_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
