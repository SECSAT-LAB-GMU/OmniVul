import requests
from bs4 import BeautifulSoup
import pandas as pd
import time
from tqdm import tqdm
import random


# Step 1: Scrape single page content
def scrape_alerts(base_url, n=100, offset=0):
    params = {"n": n, "offset": offset}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"
    }

    response = requests.get(base_url, params=params, headers=headers)
    if response.status_code != 200:
        print(f"Unable to access page, status code: {response.status_code}")
        return None

    soup = BeautifulSoup(response.text, "html.parser")
    return soup

# Step 2: Parse table data
def parse_alerts_table(soup):
    table_data = []
    # Find table rows
    for row in soup.find_all("tr")[1:]:  # Skip header row
        cells = row.find_all("td")
        if len(cells) >= 2:  # Ensure at least 2 columns of data
            alert_id_element = cells[0].find("a")  # Alert ID and hyperlink
            alert_id = alert_id_element.text.strip() if alert_id_element else "N/A"
            alert_url = f"https://lwn.net{alert_id_element['href']}" if alert_id_element else "N/A"
            package_name = cells[1].text.strip()  # Package Name
            date = cells[2].text.strip() if len(cells) > 2 else "N/A"  # Date
            table_data.append({
                "Alert ID": alert_id,
                "URL": alert_url,
                "Package Name": package_name,
                "Date": date
            })
    return table_data

# Step 3: Batch scrape all pages
def scrape_all_alerts(base_url, total_records=1000, n=100):
    all_data = []
    for offset in tqdm(range(0, total_records, n), desc="Scraping", total=(total_records//n + 1)):
        print(f"Scraping records from offset={offset} to offset+{n}...")
        soup = scrape_alerts(base_url= base_url, n=n, offset=offset)
        if soup:
            page_data = parse_alerts_table(soup)
            all_data.extend(page_data)
        time.sleep(10)  # Avoid too frequent requests

    return all_data

# Step 4: Run and save results
if __name__ == "__main__":
    vendor = "Fedora"
    base_url = f"https://lwn.net/Alerts/{vendor}/"
    total_records = 22395
    n = 100
    alerts_data = scrape_all_alerts(base_url, total_records=total_records, n=n)

    # Save to CSV file
    df = pd.DataFrame(alerts_data)
    df.to_csv(f"./lwn_{vendor}_alerts_list.csv", index=False)
    print(f"All scraped content saved to lwn_{vendor}_alerts_list.csv")

    # Print partial results
    print(df.head())