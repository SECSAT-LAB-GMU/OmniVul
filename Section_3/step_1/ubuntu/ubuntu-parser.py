import os
import glob
import json
from bs4 import BeautifulSoup
from pprint import pprint
from tqdm import tqdm

def parse_ubuntu_cve_html(html_content):
    soup = BeautifulSoup(html_content, "html.parser")
    result = {}

    # 1. CVE-ID (页面 <h1>)
    h1 = soup.find("h1")
    result["cve_id"] = h1.get_text(strip=True) if h1 else None

    # 2. Ubuntu priority
    pri_label = soup.find(lambda tag: tag.name=="p" and "Ubuntu priority" in tag.get_text())
    if pri_label:
        strong = pri_label.find_next_sibling().find("strong")
        result["ubuntu_priority"] = strong.get_text(strip=True) if strong else None
    else:
        alt = soup.select_one(".p-heading-icon__title strong")
        result["ubuntu_priority"] = alt.get_text(strip=True) if alt else None

    # 3. Cvss 3 Severity Score
    cvss_block = soup.find(lambda tag: tag.name in ("h2","p") and "Cvss 3 Severity Score" in tag.get_text())
    if cvss_block:
        strong = cvss_block.find_next("strong")
        if strong:
            score_text = strong.get_text(strip=True)
            parts = [p.strip() for p in score_text.split("·")]
            result["cvss_score"]    = parts[0] if parts else score_text
            result["cvss_severity"] = parts[1] if len(parts)>1 else None
    else:
        result["cvss_score"] = result["cvss_severity"] = None

    # 4. CVE Description
    desc = soup.select_one("#description > p")
    result["description"] = desc.get_text(" ", strip=True) if desc else None

    # 5. From the Ubuntu Security Team notes
    notes = []
    for heading in soup.find_all(lambda tag: tag.name in ("h2","h3") and "From the Ubuntu Security Team" in tag.get_text()):
        for sib in heading.find_next_siblings():
            if sib.name and sib.name.startswith("h"):
                break
            if sib.name == "p":
                notes.append(sib.get_text(" ", strip=True))
        break
    result["ubuntu_team_notes"] = " ".join(notes) if notes else None

    return result

if __name__ == "__main__":
    # folder_path = "ubuntu_cve_html_cache"
    folder_path = "complete_ubuntu_cve_html_cache"

    # output_json_path = "sec500_ubuntu_cve_details.json"
    output_json_path = "complete_ubuntu_cve_details.json"

    html_files = glob.glob(os.path.join(folder_path, "*.html"))
    # start from small
    # html_files = ['ubuntu_cve_html_cache/CVE-2010-4165.html', 'ubuntu_cve_html_cache/CVE-2019-14835.html', 'ubuntu_cve_html_cache/CVE-2024-8412.html', 'ubuntu_cve_html_cache/CVE-2023-25825.html']
    parsed_list = []

    for fn in tqdm(html_files, desc="Parsing CVE details"):
        with open(fn, "r", encoding="utf-8") as fh:
            content = fh.read()
        parsed = parse_ubuntu_cve_html(content)

        # —— sanity check —— 
        # description 只有 “Read the notes from the security team” 时，丢弃
        if not parsed.get('description') or parsed.get('description') == "Read the notes from the security team":
            print(f"Skipping {parsed.get('cve_id')} (missing Description)")
            continue

        parsed_list.append(parsed)
        # pprint(parsed)

    # 写入 JSON
    with open(output_json_path, "w", encoding="utf-8") as jf:
        json.dump(parsed_list, jf, ensure_ascii=False, indent=2)

    print(f"\nSaved {len(parsed_list)} CVE entries to {output_json_path}")
