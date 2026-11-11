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
        
        time.sleep(10)
        
        wake_button = page.locator("button:has-text('Yes, get this app back up!')")
        if wake_button.is_visible():
            print("App is sleeping. Clicking wake-up button...")
            wake_button.click()
            time.sleep(20)
        else:
            print("App is already awake!")
            
        browser.close()

if __name__ == "__main__":
    main()
