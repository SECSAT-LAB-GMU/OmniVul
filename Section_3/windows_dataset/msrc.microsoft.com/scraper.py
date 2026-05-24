"""Scrape MSRC vulnerability records for every CVE in links.json.

Strategy:
  * The msrc.microsoft.com/update-guide/vulnerability/<CVE> URL renders
    client-side via JS. We bypass the SPA by hitting the public
    Security Updates Guide JSON API used by that SPA:
        https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/<CVE>
  * One CVE -> one JSON document; persisted under raw/<CVE>.json.
  * Re-runs skip CVEs whose raw file already exists (resumable).
  * Random User-Agent + jittered delay per request (scraper_common).
"""

import json
import os
import sys

from tqdm import tqdm

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scraper_common import (  # noqa: E402
    fetch_with_retries,
    load_json,
    make_session,
    random_delay,
    save_json,
)

LINKS_FILE = os.path.join(HERE, "links.json")
RAW_DIR = os.path.join(HERE, "raw")
FAILED_FILE = os.path.join(HERE, "failed.json")

API_TEMPLATE = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{cve}"


def main() -> None:
    os.makedirs(RAW_DIR, exist_ok=True)
    by_cve = load_json(LINKS_FILE)
    cve_ids = sorted(by_cve.keys())

    session = make_session({
        "Accept": "application/json,text/plain,*/*",
        "Origin": "https://msrc.microsoft.com",
        "Referer": "https://msrc.microsoft.com/",
    })

    failed = {}
    for cve in tqdm(cve_ids, desc="msrc.microsoft.com"):
        out_path = os.path.join(RAW_DIR, f"{cve}.json")
        if os.path.exists(out_path):
            continue

        url = API_TEMPLATE.format(cve=cve)
        resp = fetch_with_retries(
            session,
            url,
            min_delay=2.0,
            max_delay=5.0,
            accept_status=(200,),
        )
        if resp is None or resp.status_code != 200:
            failed[cve] = {
                "url": url,
                "status": getattr(resp, "status_code", None),
            }
            continue

        try:
            payload = resp.json()
        except json.JSONDecodeError:
            failed[cve] = {"url": url, "status": resp.status_code, "reason": "non-JSON"}
            continue

        save_json(out_path, payload)
        # extra jitter so we don't tail-pattern even with intra-fetch delay
        random_delay(1.0, 3.0)

    save_json(FAILED_FILE, failed)
    print(f"done — {len(cve_ids) - len(failed)}/{len(cve_ids)} ok; failed -> {FAILED_FILE}")


if __name__ == "__main__":
    main()
