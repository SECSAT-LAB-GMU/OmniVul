#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
from bs4 import BeautifulSoup

def parse_packetstorm_html(html_content, file_id):
    """
    Extract from Packet Storm style HTML:
      - title: Vulnerability title
      - cves:  Related CVE list (array)
      - description: Vulnerability description
      - content: Exploit or patch content etc.
    """
    soup = BeautifulSoup(html_content, "html.parser")

    # -------------------------
    # 1) Extract title (Title)
    #    Usually appears in <div class="fretrot"> or <div class="fretromob">,
    #    and the actual text is in <table> -> <tr> -> <td> underneath.
    # -------------------------
    title = None
    title_div = soup.find("div", class_="fretrot")
    if not title_div:
        # If desktop version div not found, try mobile version
        title_div = soup.find("div", class_="fretromob")
    if title_div:
        td = title_div.find("td")
        if td:
            title = td.get_text(strip=True)

    # -------------------------
    # 2) Extract CVE(s)
    #    Usually in a table row, where the previous column text is "CVE(s):"
    # -------------------------
    cves = []
    for row in soup.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) >= 2:
            header_text = cells[0].get_text(strip=True).lower()
            if "cve" in header_text:
                # Found the row containing CVE(s)
                # The next column usually has several <a> links pointing to /files/cve/...
                for link in cells[1].find_all("a"):
                    cve_text = link.get_text(strip=True)
                    if cve_text.startswith("CVE-"):
                        cves.append(cve_text)
                break

    # -------------------------
    # 3) Extract Description
    #    Usually uses "Description" as a separator tag, then the next div contains the description.
    # -------------------------
    description = None
    # First find the div that says "Description"
    desc_header = soup.find(lambda tag: tag.name == "div" and "Description" in tag.get_text())
    if desc_header:
        # Then find the next sibling div with class_="rfmedium"
        desc_div = desc_header.find_next_sibling("div", class_="rfmedium")
        if desc_div:
            description = desc_div.get_text(strip=True)

    # -------------------------
    # 4) Extract Content
    #    Usually in <pre class="contentbox">
    # -------------------------
    content = None
    pre_box = soup.find("pre", class_="contentbox")
    if pre_box:
        # Don't remove line breaks, preserve original format
        content = pre_box.get_text("\n", strip=False)

    # Assemble result
    return {
        "fileid": file_id,
        "title": title if title else "",
        "cves": cves,
        "description": description if description else "",
        "content": content if content else ""
    }

def parse_directory(input_dir):
    """
    Traverse all .html files in the specified directory, parse each one and return results list.
    """
    count = 0
    results = []
    for filename in os.listdir(input_dir):
        if filename.lower().endswith(".html"):
            file_path = os.path.join(input_dir, filename)
            with open(file_path, "r", encoding="utf-8") as f:
                html_content = f.read()
            file_id = filename.split(".")[0]
            data = parse_packetstorm_html(html_content, file_id)
            count += 1
            results.append(data)
    print(f"Parsing completed! Parsed {count} files in total")
    return results

def main():
    """
    Script main entry point:
      python parser.py [html_directory] [output_json_filename]
    """
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} <input_html_dir> <output_json>")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_json = sys.argv[2]

    if not os.path.isdir(input_dir):
        print(f"Error: {input_dir} is not a valid directory!")
        sys.exit(1)

    results = parse_directory(input_dir)

    # Merge all results and write to a single JSON file
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"Parsing completed! Results saved to {output_json}")

if __name__ == "__main__":
    main()
