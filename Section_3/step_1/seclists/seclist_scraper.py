import sys
import requests
import re
from bs4 import BeautifulSoup
import json
import random

from const import USER_AGENTS

from utils import fetch_with_retry
from linux_keywords import *

BASE_URL = "https://seclists.org/oss-sec/"

def scrape_thread_detail(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    soup = BeautifulSoup(r.text, 'html.parser')
    title_tag = soup.find("h1", class_="m-title")

    title = title_tag.get_text(strip=True) if title_tag else "No Title"

    cve_match = re.search(r"CVE-\d{4}-\d{4,7}", title)

    cve_id = cve_match.group() if cve_match else "No CVE found"

    from_em = soup.find("em", string="From")

    from_field = from_em.find_next_sibling("br").previous_sibling.strip() if from_em and from_em.find_next_sibling("br") else ""
    
    date_em = soup.find("em", string="Date")
    
    date_field = date_em.find_next_sibling("br").previous_sibling.strip() if date_em and date_em.find_next_sibling("br") else ""
    pre_tag = soup.find("pre")
    message_body = pre_tag.get_text() if pre_tag else ""
    return {
        "CVE ID": cve_id,
        "Title": title,
        "Date": date_field,
        "Messages": [
            {
                "Author": from_field,
                "Date": date_field,
                "Text": message_body
            }
        ]
    }

def parse_li(li):
    a = li.find('a', href=True)
    if not a:
        return None
    node = {"id": a.get("name", ""), "href": a.get("href", ""), "title": a.get_text(strip=True)}
    em = li.find("em")
    node["author_date"] = em.get_text(strip=True) if em else ""
    nested = li.find("ul")
    node["children"] = [parse_li(child) for child in nested.find_all("li", recursive=False)] if nested else []
    return node

def parse_threads(html):
    soup = BeautifulSoup(html, 'html.parser')
    begin = soup.find('hr', id='begin')
    end = soup.find('hr', id='end')
    if not begin or not end:
        return []
    content = []
    for sibling in begin.next_siblings:
        if sibling == end:
            break
        content.append(str(sibling))
    snippet = "".join(content)
    snippet_soup = BeautifulSoup(snippet, 'html.parser')
    thread_ul = snippet_soup.find("ul", class_="thread")
    if not thread_ul:
        return []
    nodes = []
    for li in thread_ul.find_all("li", recursive=False):
        node = parse_li(li)
        if node:
            nodes.append(node)
    return nodes

def scrape_details_recursive(node):
    if node is None or "href" not in node:
        return
    url = f"{BASE_URL}/{node['href']}"
    detail = scrape_thread_detail(url)
    node["detail"] = detail
    for child in node.get("children", []):
        scrape_details_recursive(child)

def flatten_messages(node):
    if node is None:
        return []
    msgs = []
    if node.get("detail"):
        for m in node["detail"].get("Messages", []):
            msgs.append({"author": m.get("Author", ""), "date": m.get("Date", ""), "Text": m.get("Text", "")})
    for child in node.get("children", []):
        msgs.extend(flatten_messages(child))
    return msgs

def scraper_url(year, quarter):

    complete_url = f"{BASE_URL}/{year}/{quarter}"

    n_cve_linux_threads = 0

    session = requests.Session()
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    r = fetch_with_retry(session, complete_url, headers)

    if not r:
        print("DId not get a response")
        return None

    # r = requests.get(complete_url)
    if r.status_code != 200:
        print(f"Unexpected return code: {r.status_code}")
        return None

    threads = [t for t in parse_threads(r.text) if t is not None]
    print("Total number of threads: ",len(threads))
    for t in threads:
        title = t["title"].lower()
        matched_keywords = [kw for kw in linux_kernel_cve_keywords if kw.lower() in title]
        matched_patterns = [pat for pat in flexible_patterns if re.search(pat, title, re.IGNORECASE)]
        if len(matched_keywords) + len(matched_patterns) > 0:
            scrape_details_recursive(t)
            n_cve_linux_threads+=1
    final_output = []
    for t in threads:
        if not t.get("detail"):
            continue
        final_output.append({
            "year": "2023",
            "quarter": "Q2",
            "CVE ID": t["detail"].get("CVE ID", ""),
            "thread": {
                "title": t["detail"].get("Title", ""),
                "Date": t["detail"].get("Date", ""),
                "Message": flatten_messages(t)
            }
        })
    print(f"Number of linux vulnerability threads: {n_cve_linux_threads}")
    return final_output

def main():
    year = sys.argv[1]
    quarter = sys.argv[2]
    final_output = scraper_url(year, quarter)
    if final_output is None:
        return
    output_file = f"seclist_thread_detals/{year}_{quarter}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(final_output, f, indent=4)
    print("Scraping complete. Data saved to final_output.json.")

if __name__ == "__main__":
    main()
