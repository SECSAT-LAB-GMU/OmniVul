import requests
import os
from bs4 import BeautifulSoup
from pprint import pprint
import re, json, sys, random, time
from tqdm import tqdm

def parse_comments(soup):
    """
    Parse all comments on the page and identify the first discussion (bz_first_comment).
    Returns a list where each element is a dictionary containing the following fields:
      - comment_id      (e.g. "c0", "c13", ...)
      - comment_number  (e.g. "Description", "Comment 13", ...)
      - user            (comment author)
      - time            (comment time)
      - text            (comment body)
      - is_first        (whether it's the first discussion)
    """
    comment_list = []
    # Find all div elements with class="bz_comment" on the page
    divs = soup.find_all("div", class_="bz_comment")
    
    for div in divs:
        # Collect fields
        cinfo = {}

        # 1) comment_id
        cinfo["comment_id"] = div.get("id")  # e.g. "c0", "c13", "c15", ...
        
        # 2) comment_number
        number_span = div.find("span", class_="bz_comment_number")
        cinfo["comment_number"] = number_span.get_text(strip=True) if number_span else None
        
        # 3) user
        user_span = div.find("span", class_="bz_comment_user")
        if user_span:
            # Usually contains <span class="vcard ..."><span class="fn">USERNAME</span></span>
            cinfo["user"] = user_span.get_text(strip=True)
        else:
            cinfo["user"] = None
        
        # 4) time
        time_span = div.find("span", class_="bz_comment_time")
        cinfo["time"] = time_span.get_text(strip=True) if time_span else None
        
        # 5) text
        text_pre = div.find("pre", class_="bz_comment_text")
        comment_text = text_pre.get_text("\n", strip=True) if text_pre else None
        comment_text = " ".join(comment_text.split())
        cinfo["text"] = comment_text
        
        # 6) Whether it's the first discussion (bz_first_comment)
        #    Can also be determined by div.get("id") == "c0" or comment_number == "Description"
        classes = div.get("class", [])
        cinfo["is_first"] = ("bz_first_comment" in classes)
        
        comment_list.append(cinfo)
    # pprint(comment_list[:3])
    return comment_list

def get_bug_info(soup, bug_info):

    # 1) Bug Summary
    # Observed that summary is also in <div id="summary_input">, but simplest is to look at title:
    #   <title>1384344 – (CVE-2016-5195, DirtyCow) CVE-2016-5195 kernel: ...</title>
    # Can also find <span id="short_desc_nonedit_display">xxx</span> on the page
    title_span_1 = soup.find("span", id="alias_nonedit_display")
    title_span_2 = soup.find("span", id="short_desc_nonedit_display")
    bug_info["summary"] = ""
    if title_span_1:
        bug_info["summary"] += title_span_1.get_text(strip=True)
    if title_span_2:
        bug_info["summary"] += " " + title_span_2.get_text(strip=True)
    # 2) Bug Status
    status_span = soup.find("span", id="static_bug_status")
    if status_span:
        status_raw = status_span.get_text(strip=True)  # Split all whitespace (including newlines), then join with single space
        status_cleaned = " ".join(status_raw.split())
        bug_info["status"] = status_cleaned
    else:
        bug_info["status"] = None
    # 3) Alias (actually in the title)
    alias_span = soup.find("span", id="alias_nonedit_display")
    if alias_span:
        bug_info["alias"] = alias_span.get_text(strip=True)
    else:
        bug_info["alias"] = None
    # 4) Severity
    # Locate the Severity field row by finding <a> tag with href containing "fields.html#bug_severity"
    severity_link = soup.find("a", href=re.compile(r"fields\.html#bug_severity"))
    if severity_link:
        # Find its parent <th> tag, then get the next <td>
        th = severity_link.find_parent("th")
        if th:
            td = th.find_next_sibling("td")
            if td:
                # Also collapse all whitespace characters
                bug_info["severity"] = " ".join(td.get_text(strip=True).split())
            else:
                bug_info["severity"] = None
        else:
            bug_info["severity"] = None
    else:
        bug_info["severity"] = None
    # 5) Comments
    comments = parse_comments(soup)
    bug_info["comments"] = comments
    #pprint(bug_info)
    return bug_info

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
]

completed_ids = os.listdir("html_cache_complete")
completed_ids = [item[:-5] for item in completed_ids]

if __name__ == "__main__":
    failed_links = []
    # with open("/data2/lexi/redhat-cve-details/top500_redhat_cve_dict.json", "r", encoding="utf-8") as f:
    with open("../redhat-cve-details/complete_redhat_cve_dict.json", "r", encoding="utf-8") as f:
        redhat_cve_dict = json.load(f)
    links = []
    for cve_id, cve_info in redhat_cve_dict.items():
        if 'bugzilla_redhat_info' in cve_info and len(cve_info['bugzilla_redhat_info']) > 0:
            for bugzilla_id in cve_info['bugzilla_redhat_info']:
                links.append((cve_id, f"https://bugzilla.redhat.com/show_bug.cgi?id={bugzilla_id}"))
    all_bug_info = {}
    for (cve_id, url) in tqdm(links, desc="Processing links", unit="link"):
        if cve_id in completed_ids:
            continue
        # Target Bugzilla page URL
        #url = "https://bugzilla.redhat.com/show_bug.cgi?id=1384344"
        # Simulate browser request headers to prevent blocking
        headers = {
            "User-Agent": random.choice(USER_AGENTS)
        }
        # Make request
        response = requests.get(url, headers=headers)
        # Check if request was successful
        if response.status_code == 200:
            with open(f"html_cache_complete/{cve_id}.html", "w", encoding="utf-8") as f:
                f.write(response.text)
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            bug_info = {}
            bug_info['url'] = url
            bug_info = get_bug_info(soup, bug_info)
            info = all_bug_info.get(cve_id, [])
            all_bug_info[cve_id] = info + [bug_info]
        else:
            print(f"❌ Scraping failed, status code: {response.status_code}")
            failed_links.append(url)
        
        time.sleep(10) # Wait 10 seconds to prevent IP blocking
    
    # Save all bug information
    with open("complete_all_bug_info.json", "w", encoding="utf-8") as f:
        json.dump(all_bug_info, f, ensure_ascii=False, indent=4)
    
    # Save failed links
    if failed_links:
        print(f"Number of failed scraping links: {len(failed_links)}")
        pprint(failed_links[:3])
        with open("failed_links.json", "a", encoding="utf-8") as f:
            json.dump(failed_links, f, ensure_ascii=False, indent=4)
    else:
        print("All links scraped successfully")