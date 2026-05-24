"""Scrape the legacy MSRC portal advisories for CVEs in links.json.

The legacy URL pattern
    https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/<CVE>
issues a 301/302 redirect to the modern msrc.microsoft.com SPA, which is
JS-rendered. The actual record lives in the public Security Updates
Guide JSON API. We capture:

  * raw/<CVE>.redirect.json — the original 30x response headers, so the
    legacy URL's behaviour is preserved as provenance.
  * raw/<CVE>.json — the JSON payload from the SUG API (same shape that
    msrc.microsoft.com/scraper.py uses).

This scraper is intentionally independent of the msrc.microsoft.com
scraper so each folder is self-contained; you can run either one alone.
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

LEGACY_TEMPLATE = (
    "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/{cve}"
)
API_TEMPLATE = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{cve}"


def _capture_redirect(session, url: str) -> dict:
    resp = fetch_with_retries(
        session,
        url,
        min_delay=1.5,
        max_delay=3.5,
        accept_status=(200, 301, 302, 303, 307, 308),
        allow_redirects=False,
    )
    if resp is None:
        return {"status": None, "headers": {}, "final_url": None}
    return {
        "status": resp.status_code,
        "headers": {k: v for k, v in resp.headers.items()},
        "final_url": resp.headers.get("Location") or resp.url,
    }


def main() -> None:
    os.makedirs(RAW_DIR, exist_ok=True)
    by_cve = load_json(LINKS_FILE)
    cve_ids = sorted(by_cve.keys())

    session = make_session({
        "Accept": "application/json,text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Referer": "https://portal.msrc.microsoft.com/",
    })

    failed = {}
    for cve in tqdm(cve_ids, desc="portal.msrc"):
        redirect_path = os.path.join(RAW_DIR, f"{cve}.redirect.json")
        api_path = os.path.join(RAW_DIR, f"{cve}.json")
        if os.path.exists(api_path) and os.path.exists(redirect_path):
            continue

        if not os.path.exists(redirect_path):
            info = _capture_redirect(session, LEGACY_TEMPLATE.format(cve=cve))
            save_json(redirect_path, info)
            random_delay(1.0, 2.5)

        if not os.path.exists(api_path):
            api_url = API_TEMPLATE.format(cve=cve)
            resp = fetch_with_retries(
                session, api_url, min_delay=2.0, max_delay=5.0, accept_status=(200,),
            )
            if resp is None or resp.status_code != 200:
                failed[cve] = {"url": api_url, "status": getattr(resp, "status_code", None)}
                continue
            try:
                payload = resp.json()
            except json.JSONDecodeError:
                failed[cve] = {"url": api_url, "status": resp.status_code, "reason": "non-JSON"}
                continue
            save_json(api_path, payload)
            random_delay(1.0, 3.0)

    save_json(FAILED_FILE, failed)
    print(f"done — {len(cve_ids) - len(failed)}/{len(cve_ids)} ok; failed -> {FAILED_FILE}")


if __name__ == "__main__":
    main()
