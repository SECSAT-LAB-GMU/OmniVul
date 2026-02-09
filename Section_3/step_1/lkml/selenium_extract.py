import os
import json
import time
import random
from urllib.parse import urljoin, urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import WebDriverException, TimeoutException


# --- UTILS ---
def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS)
    }

def random_delay(min_sec=1.0, max_sec=5.0):
    time.sleep(random.uniform(min_sec, max_sec))

def safe_filename(url):
    parts = urlparse(url)
    path = parts.path.strip('/').replace('/', '_')
    return f"{path}.txt"

# --- SELENIUM SETUP ---
def get_driver():
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--disable-gpu')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument(f"--user-agent={random.choice(USER_AGENTS)}")
    driver = webdriver.Chrome(options=chrome_options)
    driver.set_page_load_timeout(20)
    return driver

# --- MAIN EXTRACTION LOGIC ---
def extract_message_from_loaded(driver):
    pre_tags = driver.find_elements(By.CSS_SELECTOR, "pre[itemprop='articleBody']")
    if pre_tags:
        return pre_tags[0].text
    else:
        return "Message content not found."

def extract_thread_links_from_loaded(driver):
    thread_links = []
    ul_lists = driver.find_elements(By.CSS_SELECTOR, "ul.threadlist")
    for ul in ul_lists:
        a_tags = ul.find_elements(By.TAG_NAME, "a")
        for a_tag in a_tags:
            href = a_tag.get_attribute('href')
            if href and '/lkml/' in href:
                thread_links.append(href)
    return thread_links
    

# Set multiple User-Agents and randomly select one
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
]
selected_user_agent = random.choice(USER_AGENTS)


options = Options()
options.add_argument("--headless")
options.add_argument("--disable-gpu")
options.add_argument("--window-size=1920,1080")
options.add_argument(f"user-agent={selected_user_agent}")


# --- MAIN SCRIPT ---
def main():
    completed_cves = set()
    if os.path.exists("completed_ids.txt"):
        with open("completed_ids.txt", 'r') as f:
            for line in f:
                completed_cves.add(line.strip())

    url_dict = {}
    with open("complete_lkml.org_links.json", 'r') as f:
        values = json.load(f)
        for data in values.values():
            cve_id = data.get("CVE ID", "")
            if cve_id in completed_cves:
                continue
            patch_links = data.get("Patch Links", [])
            exploit_links = data.get("Exploit Links", [])
            links = patch_links + exploit_links
            url_dict[cve_id] = links

    for key, urls in url_dict.items():
        print("Currently on CVE ID:", key)
        folder_path = os.path.join("CVE_Arrangements", key)
        os.makedirs(folder_path, exist_ok=True)

        for base_url in urls:
            driver = get_driver()
            try:
                driver.get(base_url)
                random_delay()
            except (WebDriverException, TimeoutException) as e:
                print(f"Error loading {base_url}: {e}")
                driver.quit()
                continue
            # Extract and save the main message
            main_message = extract_message_from_loaded(driver)
            main_filename = safe_filename(base_url)
            with open(os.path.join(folder_path, main_filename), 'w', encoding='utf-8') as f:
                f.write(main_message)
            print(f"[{key}] Saved main message to {main_filename}")

            # Fetch the thread links from the same loaded page
            thread_links = extract_thread_links_from_loaded(driver)
            visited = set()
            for thread_url in thread_links:
                if thread_url not in visited:
                    visited.add(thread_url)
                    thread_driver = get_driver()
                    thread_message = None
                    try:
                        thread_driver.get(thread_url)
                        random_delay()
                        thread_message = extract_message_from_loaded(thread_driver)
                    except (WebDriverException, TimeoutException) as e:
                        print(f"Error loading {thread_url}: {e}")
                        thread_message = "Error fetching message."
                    filename = safe_filename(thread_url)
                    with open(os.path.join(folder_path, filename), 'w', encoding='utf-8') as f:
                        f.write(thread_message)
                    print(f"[{key}] Saved thread message to {filename}")
                    thread_driver.quit()
            driver.quit()

        with open("completed_ids.txt", 'a') as f:
            f.write(f"{key}\n")

if __name__ == "__main__":
    main()
