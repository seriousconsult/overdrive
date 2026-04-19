#!/usr/bin/env python3

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

chrome_options = Options()
# chrome_options.add_argument("--headless") # Optional: run without a window

driver = webdriver.Chrome(options=chrome_options)

try:
    print("Loading BrowserLeaks WebRTC test...")
    driver.get("https://browserleaks.com/webrtc")

    # Wait up to 10 seconds for the IP to appear in the table
    wait = WebDriverWait(driver, 10)
    
    # We target the specific table cell where the IP is displayed
    # The ID 'rtc-ipv4' is often inside a span or generated via JS
    ip_element = wait.until(
        EC.presence_of_element_condition((By.ID, "rtc-ipv4"))
    )

    webrtc_ip = ip_element.text
    
    if not webrtc_ip or webrtc_ip == "n/a":
        print("WebRTC IP not detected (This is actually good for privacy!)")
    else:
        print(f"--- RESULT ---")
        print(f"WebRTC Detected IP: {webrtc_ip}")
        print(f"--------------")

except Exception as e:
    print(f"An error occurred: {e}")
    # Optional: Save a screenshot to see what the script saw
    driver.save_screenshot("error_check.png")

finally:
    driver.quit()