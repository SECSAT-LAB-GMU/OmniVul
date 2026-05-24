"""Scrape github.com references (commits, PRs, issues, advisories...) for each CVE.

For each URL in links.json we:

  1. Classify it (commit / pull / issue / advisory / release / blob / repo).
  2. Hit the matching api.github.com REST endpoint and store the JSON.
  3. For commits, additionally fetch the unified-diff `.patch` from the
     `https://github.com/<owner>/<repo>/commit/<sha>.patch` shortcut so we
     get the raw patch text without API quota churn.

Rate limit (unauthenticated REST): 60 requests/hour. Set
`GITHUB_TOKEN` in the environment to lift that to 5000/hour. The script
randomises the User-Agent and inserts jittered delays via
scraper_common.fetch_with_retries; with a token you can shorten them.

Raw files live in raw/<sha_or_id>__<kind>.json so multiple URLs per CVE
do not collide.
"""

import os
import re
import sys
from typing import Optional
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
INDEX_FILE = os.path.join(HERE, "fetch_index.json")  # url -> raw_filename

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")


def classify(url: str) -> Optional[dict]:
    """Return {kind, owner, repo, id} or None for unknown github URLs."""
    parsed = urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    repo = repo.removesuffix(".git")

    if len(parts) == 2:
        return {"kind": "repo", "owner": owner, "repo": repo, "id": None}

    section = parts[2]
    if section == "commit" and len(parts) >= 4:
        sha = parts[3].split("?")[0]
        return {"kind": "commit", "owner": owner, "repo": repo, "id": sha}
    if section == "pull" and len(parts) >= 4:
        return {"kind": "pull", "owner": owner, "repo": repo, "id": parts[3]}
    if section == "issues" and len(parts) >= 4:
        return {"kind": "issue", "owner": owner, "repo": repo, "id": parts[3]}
    if section == "security" and len(parts) >= 5 and parts[3] == "advisories":
        return {"kind": "advisory", "owner": owner, "repo": repo, "id": parts[4]}
    if section == "releases" and len(parts) >= 5 and parts[3] == "tag":
        return {"kind": "release", "owner": owner, "repo": repo, "id": "/".join(parts[4:])}
    if section == "blob" and len(parts) >= 5:
        return {"kind": "blob", "owner": owner, "repo": repo, "id": "/".join(parts[3:])}
    if section == "compare" and len(parts) >= 4:
        return {"kind": "compare", "owner": owner, "repo": repo, "id": "/".join(parts[3:])}
    return {"kind": "other", "owner": owner, "repo": repo, "id": "/".join(parts[2:])}


def _raw_key(cve: str, classified: dict) -> str:
    base = safe_filename(f"{classified['owner']}__{classified['repo']}__{classified['kind']}__{classified.get('id') or 'root'}")
    return f"{cve}__{base}.json"


def _api_url(c: dict) -> Optional[str]:
    o, r, i = c["owner"], c["repo"], c.get("id")
    if c["kind"] == "commit":
        return f"https://api.github.com/repos/{o}/{r}/commits/{i}"
    if c["kind"] == "pull":
        return f"https://api.github.com/repos/{o}/{r}/pulls/{i}"
    if c["kind"] == "issue":
        return f"https://api.github.com/repos/{o}/{r}/issues/{i}"
    if c["kind"] == "advisory":
        return f"https://api.github.com/repos/{o}/{r}/security-advisories/{i}"
    if c["kind"] == "release":
        return f"https://api.github.com/repos/{o}/{r}/releases/tags/{i}"
    if c["kind"] == "repo":
        return f"https://api.github.com/repos/{o}/{r}"
    if c["kind"] == "compare":
        return f"https://api.github.com/repos/{o}/{r}/compare/{i}"
    return None


def _patch_url(c: dict) -> Optional[str]:
    if c["kind"] != "commit":
        return None
    return f"https://github.com/{c['owner']}/{c['repo']}/commit/{c['id']}.patch"


def main() -> None:
    os.makedirs(RAW_DIR, exist_ok=True)
    by_cve = load_json(LINKS_FILE)

    auth_headers = {}
    if GITHUB_TOKEN:
        auth_headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        # With a token we can be a little less polite, but still jittered.
        delay = (0.5, 2.0)
    else:
        delay = (2.0, 5.5)

    json_session = make_session({
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        **auth_headers,
    })
    patch_session = make_session({"Accept": "application/vnd.github.v3.patch", **auth_headers})

    index = load_json(INDEX_FILE) if os.path.exists(INDEX_FILE) else {}
    failed = {}

    work = []
    for cve, buckets in by_cve.items():
        for role in ("patch_urls", "exploit_urls"):
            for url in buckets[role]:
                work.append((cve, role.removesuffix("_urls"), url))

    for cve, role, url in tqdm(work, desc="github.com"):
        if url in index and os.path.exists(os.path.join(RAW_DIR, index[url])):
            continue
        c = classify(url)
        if c is None:
            failed[url] = {"cve": cve, "reason": "unrecognised github URL"}
            continue

        raw_name = _raw_key(cve, c)
        raw_path = os.path.join(RAW_DIR, raw_name)

        api_url = _api_url(c)
        record: dict = {"cve": cve, "role": role, "url": url, "kind": c["kind"]}
        if api_url:
            resp = fetch_with_retries(
                json_session, api_url,
                min_delay=delay[0], max_delay=delay[1], accept_status=(200,),
            )
            if resp is None or resp.status_code != 200:
                failed[url] = {"cve": cve, "api": api_url, "status": getattr(resp, "status_code", None)}
                continue
            try:
                record["api_payload"] = resp.json()
            except Exception:  # noqa: BLE001
                failed[url] = {"cve": cve, "api": api_url, "reason": "non-JSON"}
                continue

        patch_url = _patch_url(c)
        if patch_url:
            presp = fetch_with_retries(
                patch_session, patch_url,
                min_delay=delay[0], max_delay=delay[1], accept_status=(200,),
            )
            if presp is not None and presp.status_code == 200:
                record["patch_text"] = presp.text

        save_json(raw_path, record)
        index[url] = raw_name
        random_delay(*delay)

    save_json(INDEX_FILE, index)
    save_json(FAILED_FILE, failed)
    total = len(work)
    print(f"done — {total - len(failed)}/{total} ok; index -> {INDEX_FILE}; failed -> {FAILED_FILE}")


if __name__ == "__main__":
    main()
