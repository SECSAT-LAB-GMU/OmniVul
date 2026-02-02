import sys
import requests
import re
from bs4 import BeautifulSoup
import json
import random

from const import USER_AGENTS

from collections import defaultdict

from utils import fetch_with_retry
from linux_keywords import *

BASE_URL = "offline_pages"

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
    begin = html.find('hr', id='begin')
    end = html.find('hr', id='end')
    if not begin or not end:
        return []
    content = []
    for sibling in begin.next_siblings:
        if sibling == end:
            break
        content.append(str(sibling))
    snippet = "".join(content)
    snippet_soup = BeautifulSoup(snippet, 'html.parser')
    thread_ul = snippet_soup.find(class_="thread")
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
    matched = []
    titles = []
    results = defaultdict(dict)

    complete_url = f"{BASE_URL}/{year}_{quarter}.html"
    n_cve_linux_threads = 0

    with open(complete_url, "r", encoding="utf-8") as file:
        # Parse the file content with BeautifulSoup
        r = BeautifulSoup(file, "html.parser")

    threads = [t for t in parse_threads(r) if t is not None]

    print(f"{year}, {quarter}")
    print("Total number of threads: ",len(threads))

    for t in threads:
        title = t["title"].lower()
        id = int(int(t["id"]))
        matched_keywords = [kw for kw in linux_kernel_cve_keywords if kw.lower() in title]
        matched_patterns = [pat for pat in flexible_patterns if re.search(pat, title, re.IGNORECASE)]
        if len(matched_keywords) + len(matched_patterns) > 0:
            results[id]["title"] = title
            results[id]["keywords"] = matched_keywords
            results[id]["patterns"] = matched_patterns
            # scrape_details_recursive(t)
            n_cve_linux_threads+=1

    print(f"Number of linux vulnerability threads: {n_cve_linux_threads}")
    output_file = f"seclist_stats/{year}_{quarter}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

def main():
    year = sys.argv[1]
    quarter = sys.argv[2]
    scraper_url(year, quarter)

if __name__ == "__main__":
    main()
