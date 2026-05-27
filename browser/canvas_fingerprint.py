#!/usr/bin/env python3
"""
Canvas Fingerprint Detection

Detects canvas fingerprinting - a common browser tracking method where
the browser is asked to draw a hidden image, and the resulting hash
is used as a unique identifier.

Score: 1-5
5 = Canvas fingerprinting detected (high tracking risk)
4 = Canvas fingerprinting not detected but APIs available (potential risk)
3 = Canvas fingerprinting not detected and APIs not available (unknown risk)
2 = Canvas fingerprinting not detected and APIs not available (reduced attack surface)
1 = No canvas fingerprinting detected

TODO: Implement actual canvas fingerprint detection
- Use Selenium to access a test page that performs canvas fingerprinting
- Check if canvas readback is possible
- Detect canvas fingerprinting scripts

"""

import sys
import time
import hashlib
import urllib.parse
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
from common.common_browser import (
    print_browser_detection_header,
    print_browser_detection_score_footer,
)


def _make_test_page() -> str:
    # Minimal ThumbmarkJS-like drawing that produces a repeatable dataURL
    html = """<!doctype html>
<html><head><meta charset='utf-8'></head><body>
<canvas id='c' width='300' height='150'></canvas>
<script>
function hex(buffer){const v=new Uint8Array(buffer);let s='';for(let i=0;i<v.length;i++){s+=('00'+v[i].toString(16)).slice(-2);}return s}
(async function(){
  try{
    const c=document.getElementById('c');
    const ctx=c.getContext('2d');
    ctx.fillStyle='#f2f2f2';ctx.fillRect(0,0,300,150);
    ctx.textBaseline='top';ctx.font='16px Arial';ctx.fillStyle='rgb(255,0,0)';
    ctx.fillText('ThumbmarkJS test — 測試',2,2);
    ctx.fillStyle='rgba(0,0,255,0.7)';ctx.fillRect(10,30,80,50);
    ctx.beginPath();ctx.arc(200,75,30,0,Math.PI*2);ctx.fillStyle='green';ctx.fill();
    const data=c.toDataURL();
    if(!data){ document.title='NO_DATA'; return; }
    if(window.crypto && crypto.subtle && crypto.subtle.digest){
      const enc=new TextEncoder();
      const hash=await crypto.subtle.digest('SHA-256', enc.encode(data));
      const hexh=hex(hash); document.title='FP:'+hexh; return;
    }
    document.title='HAS_DATA';
  }catch(e){ document.title='ERROR:'+String(e); }
})();
</script></body></html>"""
    return html


def _try_selenium_canvas_check(timeout: int = 15) -> tuple[int, str]:
    """Attempt to run a headless browser, draw the test canvas and read back a fingerprint.

    Returns (score, description).
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.chrome.options import Options as ChromeOptions
        from selenium.common.exceptions import WebDriverException
    except Exception:
        return 3, "Selenium not available; cannot perform dynamic canvas test."

    html = _make_test_page()
    data_uri = "data:text/html;charset=utf-8," + urllib.parse.quote(html)

    # Try Chrome/Chromium first
    options = ChromeOptions()
    # newer Chrome supports 'headless=new', but fall back gracefully
    try:
        options.add_argument("--headless=new")
    except Exception:
        options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver = None
    try:
        driver = webdriver.Chrome(options=options)
    except Exception:
        # Try Firefox fallback
        try:
            from selenium.webdriver.firefox.options import Options as FxOptions
            fx_opts = FxOptions()
            fx_opts.add_argument("-headless")
            driver = webdriver.Firefox(options=fx_opts)
        except Exception as e:
            return 3, f"No suitable webdriver found to run dynamic test: {e}"

    try:
        driver.set_page_load_timeout(timeout)
        driver.get(data_uri)

        # Wait up to `timeout` seconds for a title change indicating result
        waited = 0
        title = driver.title or ""
        while waited < timeout and not (title.startswith("FP:") or title.startswith("ERROR:") or title in ("HAS_DATA", "NO_DATA")):
            time.sleep(0.5)
            waited += 0.5
            title = driver.title or ""

        if title.startswith("FP:"):
            fp = title.split("FP:", 1)[1]
            return 5, f"Canvas readback allowed; fingerprint SHA256: {fp}"
        if title == "HAS_DATA":
            return 4, "Canvas readback produced image data (APIs available), but digest not computed in-page."
        if title == "NO_DATA":
            return 2, "Canvas produced no dataURL (readback failed or returned empty)."
        if title.startswith("ERROR:"):
            return 2, f"In-page error when drawing/reading canvas: {title[6:]}"

        # Timeout / unknown
        return 3, "Timed out waiting for in-page canvas result; API availability unknown."
    except Exception as e:
        return 3, f"Browser test failed: {e}"
    finally:
        try:
            if driver:
                driver.quit()
        except Exception:
            pass


def check_canvas_fingerprint() -> tuple[int, str]:
    """
    Check for canvas fingerprinting support/behavior.
    Preference: run a dynamic in-browser test via Selenium; otherwise return an informational score.
    """
    # Try dynamic Selenium-backed test first
    score, desc = _try_selenium_canvas_check()
    return score, desc


def main():
    print_browser_detection_header("Canvas Fingerprint Detection")
    score, description = check_canvas_fingerprint()
    print_browser_detection_score_footer(score, description)


if __name__ == "__main__":
    main()