"""Scrape git.kernel.org cgit commit pages + raw patches.

Most URLs in this corpus are in the short-form
    https://git.kernel.org/<tree>/c/<sha>
which cgit 302-redirects to the canonical commit page, e.g.
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=<sha>

For each URL we save:
  raw/<cve>__<sha>.html  — HTML of the commit page (metadata + diff prose)
  raw/<cve>__<sha>.patch — raw unified diff via cgit's ?patch suffix

Random User-Agent + jittered delay per scraper_common.fetch_with_retries.
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

SHORT_RE = re.compile(r"^/(?P<tree>[^/]+)/c/(?P<sha>[0-9a-f]+)/?$")
COMMIT_RE = re.compile(r"/commit/?\?id=(?P<sha>[0-9a-f]+)")


def _extract_sha(url: str) -> str | None:
    parsed = urlparse(url)
    m = SHORT_RE.match(parsed.path)
    if m:
        return m.group("sha")
    m = COMMIT_RE.search(parsed.geturl())
    if m:
        return m.group("sha")
    return None


def _patch_url(commit_url: str) -> str:
    """Translate a cgit commit URL to its raw-patch sibling."""
    parsed = urlparse(commit_url)
    path = parsed.path
    if path.startswith("/") and "/c/" in path:
        # short form -> just append /commit/?... is wrong; cgit short form
        # also supports `/patch/?id=...` once resolved; we instead build
        # the full canonical patch URL from the redirected response below.
        return commit_url + ("&" if "?" in commit_url else "?") + "patch=1"
    if "/commit" in path:
        return commit_url.replace("/commit", "/patch")
    return commit_url


def main() -> None:
    os.makedirs(RAW_DIR, exist_ok=True)
    by_cve = load_json(LINKS_FILE)
    session = make_session({
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Referer": "https://git.kernel.org/",
    })

    failed = {}
    index = load_json(INDEX_FILE) if os.path.exists(INDEX_FILE) else {}

    work = []
    for cve, buckets in by_cve.items():
        for role in ("patch_urls", "exploit_urls"):
            for url in buckets[role]:
                work.append((cve, role.removesuffix("_urls"), url))

    for cve, role, url in tqdm(work, desc="git.kernel.org"):
        if url in index:
            continue

        sha = _extract_sha(url) or safe_filename(url, 32)
        html_name = f"{cve}__{safe_filename(sha)}.html"
        patch_name = f"{cve}__{safe_filename(sha)}.patch"

        # commit page (follow redirects so short form resolves)
        resp = fetch_with_retries(
            session, url,
            min_delay=2.0, max_delay=5.0, accept_status=(200,),
            allow_redirects=True,
        )
        if resp is None or resp.status_code != 200:
            failed[url] = {"cve": cve, "status": getattr(resp, "status_code", None)}
            continue

        with open(os.path.join(RAW_DIR, html_name), "w", encoding="utf-8") as f:
            f.write(resp.text)

        # raw patch (translate from the final, canonical commit URL)
        canonical = resp.url
        patch_url = canonical.replace("/commit/?", "/patch/?")
        presp = fetch_with_retries(
            session, patch_url,
            min_delay=2.0, max_delay=5.0, accept_status=(200,),
        )
        if presp is not None and presp.status_code == 200:
            with open(os.path.join(RAW_DIR, patch_name), "w", encoding="utf-8") as f:
                f.write(presp.text)

        index[url] = {
            "cve": cve,
            "role": role,
            "sha": sha,
            "canonical_url": canonical,
            "html": html_name,
            "patch": patch_name if presp and presp.status_code == 200 else None,
        }
        random_delay(2.0, 5.0)

    save_json(INDEX_FILE, index)
    save_json(FAILED_FILE, failed)
    print(f"done — {len(work) - len(failed)}/{len(work)} ok; failed -> {FAILED_FILE}")


if __name__ == "__main__":
    main()
