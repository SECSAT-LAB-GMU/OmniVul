"""Parse git.kernel.org cgit commit pages into a CVE-keyed structure.

Reads fetch_index.json + raw/* (produced by scraper.py) and emits
output.json:

{
  "CVE-...": [
    {
      "source": "git.kernel.org",
      "url": "...",
      "canonical_url": "...",
      "role": "patch",
      "sha": "...",
      "author": "...",
      "author_email": "...",
      "date": "...",
      "subject": "...",
      "message": "...",
      "changed_files": ["..."],
      "patch_text": "..."   # raw unified diff
    }
  ]
}
"""

import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup
from tqdm import tqdm

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scraper_common import load_json, save_json  # noqa: E402

RAW_DIR = os.path.join(HERE, "raw")
INDEX_FILE = os.path.join(HERE, "fetch_index.json")
OUTPUT_FILE = os.path.join(HERE, "output.json")


def _td_text(soup, label: str) -> Optional[str]:
    th = soup.find("th", string=re.compile(rf"^{label}", re.I))
    if not th:
        return None
    td = th.find_next_sibling("td")
    return td.get_text(strip=True) if td else None


def _parse_html(html: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    author = _td_text(soup, "author")
    committer = _td_text(soup, "committer")
    subject = None
    commit_msg = ""

    msg_div = soup.find("div", class_="commit-subject") or soup.find("div", class_="commit-msg")
    if msg_div:
        subject = msg_div.get_text(strip=True)
    body_div = soup.find("div", class_="commit-msg")
    if body_div:
        commit_msg = body_div.get_text("\n", strip=False)

    # Author "Name <email>  YYYY-MM-DD HH:MM:SS"
    email = None
    date = None
    if author:
        m = re.match(r"^(?P<name>.*?)\s*<(?P<email>[^>]+)>\s*(?P<date>.*)$", author)
        if m:
            author = m.group("name").strip()
            email = m.group("email").strip()
            date = m.group("date").strip()

    # diff file list
    changed_files: List[str] = []
    for a in soup.select("table.diffstat a"):
        path = a.get_text(strip=True)
        if path:
            changed_files.append(path)

    return {
        "author": author,
        "author_email": email,
        "date": date,
        "committer": committer,
        "subject": subject,
        "message": commit_msg,
        "changed_files": changed_files,
    }


def main() -> None:
    if not os.path.exists(INDEX_FILE):
        raise SystemExit(f"missing {INDEX_FILE}. Run scraper.py first.")
    index = load_json(INDEX_FILE)

    by_cve: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for url, meta in tqdm(index.items(), desc="git.kernel.org parse"):
        html_path = os.path.join(RAW_DIR, meta["html"])
        if not os.path.exists(html_path):
            continue
        with open(html_path, "r", encoding="utf-8") as f:
            parsed = _parse_html(f.read())

        patch_text = None
        if meta.get("patch"):
            patch_path = os.path.join(RAW_DIR, meta["patch"])
            if os.path.exists(patch_path):
                with open(patch_path, "r", encoding="utf-8") as f:
                    patch_text = f.read()

        item = {
            "source": "git.kernel.org",
            "url": url,
            "canonical_url": meta.get("canonical_url"),
            "role": meta.get("role"),
            "sha": meta.get("sha"),
            **parsed,
            "patch_text": patch_text,
        }
        by_cve[meta["cve"]].append(item)

    save_json(OUTPUT_FILE, by_cve)
    print(f"{sum(len(v) for v in by_cve.values())} items across {len(by_cve)} CVEs -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
