from playwright.sync_api import sync_playwright
import time

APP_ID = "weight-tracker-cuejwfmmgnhvt95dckslt5"
URL = "https://" + APP_ID + ".streamlit.app/"

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        print(f"Accessing {URL}...")
        page.goto(URL, timeout=60000)
        
        # ボタンが表示されるまで最大30秒待つ
        wake_button = page.locator("button:has-text('Yes, get this app back up!')")
        try:
            wake_button.wait_for(state="visible", timeout=30000)
            print("App is sleeping. Clicking wake-up button...")
            wake_button.click()
            # 起動処理が確実に始まるまで30秒待機
            time.sleep(30)
        except Exception:
            print("App is already awake or button not found.")
            
        browser.close()

if __name__ == "__main__":
    main()
