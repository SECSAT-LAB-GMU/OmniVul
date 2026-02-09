import requests
from bs4 import BeautifulSoup
import pandas as pd
import json
import time
import os
from tqdm import tqdm
import random
import argparse

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
]

# Step 1: Function to scrape a single article
def scrape_article(url, max_retries=3):
    """Scrapes detailed information from an LWN article"""
    headers = {
        "User-Agent": random.choice(USER_AGENTS)  # Randomly select a User-Agent for each request
    }

    backoff_time = 60  # Initial retry wait time
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 429:
                print(f"⏳ Status code 429: Too many requests, waiting {backoff_time} seconds before retrying... (Attempt {attempt})")
                time.sleep(backoff_time)
                backoff_time *= 2
                backoff_time = min(backoff_time, 600)  # Maximum wait time of 10 minutes
                continue

            if response.status_code != 200:
                print(f"❌ Unable to access article: {url}, Status code: {response.status_code}")
                return None

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract article title
            title = soup.find("h1").text.strip() if soup.find("h1") else "Title not found"

            # Extract metadata (From, To, Subject, Date, Message-ID)
            meta_info = {}
            for row in soup.find_all("tr"):
                columns = row.find_all("td")
                if len(columns) == 3:
                    key = columns[0].text.strip().replace(":", "")
                    value = columns[2].text.strip()
                    meta_info[key] = value

            # Extract security advisory link
            security_link = next((link["href"] for link in soup.find_all("a") if "errata.almalinux.org" in link.get("href", "")), "N/A")

            # Extract article content
            content_div = soup.find("div", class_="ArticleText")
            content = content_div.get_text(separator="\n").strip() if content_div else "Content Not Found"

            return {
                "URL": url,
                "Title": title,
                "From": meta_info.get("From", "N/A"),
                "To": meta_info.get("To", "N/A"),
                "Subject": meta_info.get("Subject", "N/A"),
                "Date": meta_info.get("Date", "N/A"),
                "Message-ID": meta_info.get("Message-ID", "N/A"),
                "Security Advisory Link": security_link,
                "Content": content
            }

        except Exception as e:
            print(f"⚠️ Network error {url}, Error: {e}, waiting {backoff_time} seconds before retrying... (Attempt {attempt})")
            time.sleep(backoff_time)
            backoff_time = min(backoff_time * 2, 600) 
    return url

# Step 2: Read URL list and batch scrape articles
def scrape_articles_from_csv(input_csv, output_json, num_articles=None, delay=(10, 15), batch_index=1):
    """Reads URLs from a CSV file and scrapes articles in batches with a progress bar"""
    
    # Ensure input file exists
    if not os.path.exists(input_csv):
        print(f"❌ Input file {input_csv} does not exist!")
        return

    # Read URL list
    urls_df = pd.read_csv(input_csv)
    if "URL" not in urls_df.columns:
        print(f"❌ CSV file missing 'URL' column")
        return
    
    if num_articles is None:
        num_articles = len(urls_df)
    
    batch_start = batch_index * 1000
    batch_end = batch_start + 1000
    print(f"🔍 Scraping batch {batch_index} from {batch_start} to {batch_end}")
    urls = urls_df["URL"][batch_start:batch_end].tolist()  # Limit the number of articles to scrape

    articles_content = []
    failed_urls = []
    for url in tqdm(urls, desc="🔍 Scraping Progress", unit="articles"):
        article = scrape_article(url)
        if article:
            articles_content.append(article)
        else:
            failed_urls.append(url)
        sleep_time = random.uniform(*delay)  # Randomized delay
        time.sleep(sleep_time)  # Prevent excessive requests

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_json), exist_ok=True)

    # Save scraped articles as JSON
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(articles_content, f, ensure_ascii=False, indent=4)

    print(f"✅ {len(articles_content)} articles saved to {output_json}")

    # Save failed URLs for later processing
    failed_file = output_json.replace(".json", "_failed.json")
    with open(failed_file, "w", encoding="utf-8") as f:
        json.dump(failed_urls, f, ensure_ascii=False, indent=4)
    print(f"🚨 {len(failed_urls)} failed URLs saved to {failed_file}")

# Step 3: Main function entry point
def main():
    parser = argparse.ArgumentParser(description="Scrape LWN security alerts content from CSV")
    parser.add_argument("--batch-index", "-b", type=int, default=1, help="Batch index to scrape")
    args = parser.parse_args()
    
    vendor = "Fedora"
    batch_index = args.batch_index
    input_csv = f"./article-url-list/lwn_{vendor}_alerts_list.csv"
    output_json = f"./content/{vendor}/{vendor}_alerts_content-{batch_index}.json"
    
    # Configure the number of articles to scrape and delay time
    num_articles = None
    delay = (20, 40)  # Default: 20-40 seconds delay, can be adjusted

    scrape_articles_from_csv(input_csv, output_json, num_articles, delay, batch_index)

# Run the script
if __name__ == "__main__":
    main()