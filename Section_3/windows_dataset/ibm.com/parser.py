"""Parse IBM Security Bulletin HTML pages into a CVE-keyed structure.

Reads raw/*.html (one bulletin per file) and emits output.json:

{
  "CVE-...": [
    {
      "source": "ibm.com",
      "url": "...",
      "role": "patch",
      "node_id": "...",
      "title": "...",
      "summary": "...",
      "vulnerability_details": "...",
      "affected_products": "...",
      "remediation": "...",
      "references": ["..."],
      "related_cves": ["..."]
    }
  ]
}
"""

import json
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

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")

SECTION_LABELS = {
    "summary": ["Summary"],
    "vulnerability_details": ["Vulnerability Details", "Vulnerability details"],
    "affected_products": ["Affected Products and Versions", "Affected Products", "Affected products"],
    "remediation": ["Remediation/Fixes", "Remediation / Fixes", "Remediation", "Fixes"],
    "workarounds": ["Workarounds and Mitigations", "Workarounds"],
    "references": ["References"],
}


def _section_text(soup: BeautifulSoup, labels: List[str]) -> Optional[str]:
    """Find a heading matching one of `labels` and return text up to the next heading."""
    for label in labels:
        heading = soup.find(
            lambda tag: tag.name in {"h2", "h3", "h4", "strong", "b"}
            and label.lower() in tag.get_text(strip=True).lower()
        )
        if heading:
            chunks = []
            for sib in heading.next_siblings:
                if getattr(sib, "name", None) in {"h2", "h3", "h4"}:
                    break
                if hasattr(sib, "get_text"):
                    chunks.append(sib.get_text("\n", strip=True))
                else:
                    text = str(sib).strip()
                    if text:
                        chunks.append(text)
            text = "\n".join(c for c in chunks if c)
            if text:
                return text
    return None


def _references(soup: BeautifulSoup) -> List[str]:
    refs = []
    ref_text = _section_text(soup, SECTION_LABELS["references"])
    if ref_text:
        for line in ref_text.splitlines():
            url_match = re.search(r"https?://\S+", line)
            if url_match:
                refs.append(url_match.group(0))
    return refs


def _title(soup: BeautifulSoup) -> Optional[str]:
    h1 = soup.find("h1")
    if h1:
        return h1.get_text(strip=True)
    if soup.title:
        return soup.title.get_text(strip=True)
    return None


def _jsonld_fallback(soup: BeautifulSoup) -> Dict[str, Any]:
    """If the page is mostly JS-rendered, IBM often embeds a JSON-LD blob."""
    out: Dict[str, Any] = {}
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string or "{}")
        except Exception:  # noqa: BLE001
            continue
        if isinstance(data, dict):
            if "headline" in data and "title" not in out:
                out["title"] = data["headline"]
            if "description" in data and "summary" not in out:
                out["summary"] = data["description"]
    return out


def parse_bulletin(html: str) -> Dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    parsed: Dict[str, Any] = {"title": _title(soup)}
    for key, labels in SECTION_LABELS.items():
        if key == "references":
            continue
        parsed[key] = _section_text(soup, labels)
    parsed["references"] = _references(soup)
    parsed["related_cves"] = sorted(set(CVE_RE.findall(soup.get_text(" ", strip=True))))

    # fill in anything still missing from JSON-LD
    fallback = _jsonld_fallback(soup)
    for k, v in fallback.items():
        parsed.setdefault(k, v)
    return parsed


def main() -> None:
    if not os.path.exists(INDEX_FILE):
        raise SystemExit(f"missing {INDEX_FILE}. Run scraper.py first.")
    index = load_json(INDEX_FILE)

    by_cve: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for url, meta in tqdm(index.items(), desc="ibm.com parse"):
        html_path = os.path.join(RAW_DIR, meta["html"])
        if not os.path.exists(html_path):
            continue
        with open(html_path, "r", encoding="utf-8") as f:
            parsed = parse_bulletin(f.read())
        item = {
            "source": "ibm.com",
            "url": url,
            "role": meta.get("role"),
            "node_id": meta.get("node_id"),
            **parsed,
        }
        by_cve[meta["cve"]].append(item)

    save_json(OUTPUT_FILE, by_cve)
    print(f"{sum(len(v) for v in by_cve.values())} items across {len(by_cve)} CVEs -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
