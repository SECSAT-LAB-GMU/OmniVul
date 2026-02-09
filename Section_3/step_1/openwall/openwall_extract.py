import os
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import time
import random
from requests.exceptions import RequestException

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115 Safari/537.36"
}

def fetch_with_retry(url, retries=3, delay=2):
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=HEADERS, timeout=10)
            response.raise_for_status()
            return response
        except RequestException as e:
            print(f"Attempt {attempt+1} failed for {url}: {e}")
            time.sleep(delay)
    raise Exception(f"Failed to fetch {url} after {retries} attempts")


# Function to fetch and extract message content from Openwall oss-security
def extract_oss_security_message(url):
    response = fetch_with_retry(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    pre_tag = soup.find('pre')
    if pre_tag:
        message_content = pre_tag.get_text(strip=True, separator='\n')
    else:
        message_content = "Message content not found."

    return message_content

# Function to generate a safe filename from URL
def safe_filename(url):
    parts = urlparse(url)
    path = parts.path.strip('/').replace('/', '_')
    return f"{path}.txt"

url_dict = {}
with open("complete_www.openwall.com_links.json", 'r') as f:
    values = json.load(f)
    for data in values.values():
        cve_id = data.get("CVE ID", "")
        patch_links = data.get("Patch Links", [])
        exploit_links = data.get("Exploit Links", [])
        links = patch_links + exploit_links
        url_dict[cve_id] = links


for key, urls in url_dict.items():
    folder_path = os.path.join("CVE_Arrangements", key)
    os.makedirs(folder_path, exist_ok=True)

    for base_url in urls:
        # Extract and save the main message
        main_message = extract_oss_security_message(base_url)
        main_filename = safe_filename(base_url)
        with open(os.path.join(folder_path, main_filename), 'w', encoding='utf-8') as f:
            f.write(main_message)
        print(f"[{key}] Saved oss-security message to {main_filename}")
        time.sleep(random.uniform(1, 3))
