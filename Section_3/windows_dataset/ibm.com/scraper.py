"""Scrape IBM Security Bulletins (ibm.com/support/pages/node/<id>).

These pages mostly arrive as static HTML with a sidebar of metadata
plus content sections (Summary, Vulnerability Details, Affected
Products, Remediation/Fixes, References). We fetch HTML directly,
respecting jittered delays and rotating User-Agents, and save one file
per node id under raw/<id>.html.

For pages that turn out to be JS-rendered (rare for /node/ URLs) the
file will still capture the inline JSON-LD that IBM ships in <script>
tags, which the parser falls back to.
"""

import os
import re
import sys
from urllib.parse import urlparse

from tqdm import tqdm

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scraper_common import (  # noqa: E402
    fetch_with_retries,
    load_json,
    make_session,
    random_delay,
    safe_filename,
    save_json,
)

LINKS_FILE = os.path.join(HERE, "links.json")
RAW_DIR = os.path.join(HERE, "raw")
FAILED_FILE = os.path.join(HERE, "failed.json")
INDEX_FILE = os.path.join(HERE, "fetch_index.json")

NODE_RE = re.compile(r"/node/(?P<id>\d+)")


def _node_id(url: str) -> str:
    m = NODE_RE.search(urlparse(url).path)
    return m.group("id") if m else safe_filename(url, 32)


def main() -> None:
    os.makedirs(RAW_DIR, exist_ok=True)
    by_cve = load_json(LINKS_FILE)
    session = make_session({
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Referer": "https://www.ibm.com/support/",
    })

    index = load_json(INDEX_FILE) if os.path.exists(INDEX_FILE) else {}
    failed = {}

    work = []
    for cve, buckets in by_cve.items():
        for role in ("patch_urls", "exploit_urls"):
            for url in buckets[role]:
                work.append((cve, role.removesuffix("_urls"), url))

    for cve, role, url in tqdm(work, desc="ibm.com"):
        if url in index:
            continue
        node = _node_id(url)
        out_path = os.path.join(RAW_DIR, f"{safe_filename(node)}.html")

        if not os.path.exists(out_path):
            resp = fetch_with_retries(
                session, url,
                min_delay=2.5, max_delay=6.0, accept_status=(200,),
                allow_redirects=True,
            )
            if resp is None or resp.status_code != 200:
                failed[url] = {"cve": cve, "status": getattr(resp, "status_code", None)}
                continue
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(resp.text)
            random_delay(2.0, 5.0)

        index[url] = {"cve": cve, "role": role, "node_id": node, "html": os.path.basename(out_path)}

    save_json(INDEX_FILE, index)
    save_json(FAILED_FILE, failed)
    print(f"done — {len(work) - len(failed)}/{len(work)} ok; failed -> {FAILED_FILE}")


if __name__ == "__main__":
    main()
