import os
import re
import time
import json
import random
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from tqdm import tqdm

# Prepare save directory
output_dir = "complete_raw_html_files"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Read packetstorm_links.json file
# with open('packetstorm_links.json', 'r', encoding='utf-8') as f:
with open('complete_packetstormsecurity.com_links.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

links = []
for key, entry in data.items():
    for link in entry['Exploit Links']:
        links.append(link)
    for link in entry['Patch Links']:
        links.append(link)
print(f"Successfully read links file, total {len(links)} links")
print(links[:3])
print("-" * 30)

# Set multiple User-Agents and randomly select one
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
]
selected_user_agent = random.choice(USER_AGENTS)
print(f"Using User-Agent: {selected_user_agent}")

# Configure Chrome headless mode, set window size and User-Agent
options = Options()
options.add_argument("--headless")
options.add_argument("--disable-gpu")
options.add_argument("--window-size=1920,1080")
options.add_argument(f"user-agent={selected_user_agent}")

def get_id(url):
    """
    Extract file ID from URL, matching /files/number format
    """
    m = re.search(r'/files/(\d+)', url)
    if not m:
        print(f"Could not find file ID, skipping link: {url}")
        return None
    return m.group(1)

fail_links = []

# Initialize Chrome driver
driver = webdriver.Chrome(options=options)

completed_ids = os.listdir(output_dir)
completed_ids = [cve[:-5] for cve in completed_ids]

continued_ids = 0

for target_url in tqdm(links, desc="Processing links", unit="link"):
    # print(f"Processing link: {target_url}")
    driver.get(target_url)
    file_id = get_id(target_url)
    if file_id in completed_ids:
        continued_ids += 1
        continue
    if file_id is None:
        fail_links.append(target_url)
        continue

    wait = WebDriverWait(driver, 10)
    time.sleep(3)  # Wait for page to load

    # Scroll to bottom of page to ensure TOS and other content loads completely
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
    time.sleep(1)

    # Try to find and click ACCEPT button (if exists)
    try:
        accept_button = driver.find_element(By.XPATH, "//input[@value='ACCEPT']")
        if accept_button.is_displayed() and accept_button.is_enabled():
            driver.execute_script("arguments[0].scrollIntoView(true);", accept_button)
            time.sleep(1)
            try:
                accept_button.click()
                print("Clicked ACCEPT button using regular click.")
            except Exception as e:
                print("Regular click failed:", target_url)
                driver.execute_script("arguments[0].click();", accept_button)
                print("Clicked ACCEPT button using JavaScript.")
        else:
            print("ACCEPT button not visible or not enabled, skipping click.")
    except Exception:
        print("ACCEPT button not found on page, may have already been accepted.")
            
    time.sleep(3)  # Wait for page to update

    # Save final page content to file
    page_source = driver.page_source
    save_path = os.path.join(output_dir, f"{file_id}.html")
    with open(save_path, "w", encoding="utf-8") as f:
        f.write(page_source)
    # print(f"Final page content saved to {save_path}")
    time.sleep(5)

driver.quit()

# Save failed links to file
with open("complete_failed_links.json", "w", encoding="utf-8") as f:
    json.dump(fail_links, f, ensure_ascii=False, indent=4)
print(f"Number of failed scraping links: {len(fail_links)}")
print("Number of continued ids ", continued_ids)