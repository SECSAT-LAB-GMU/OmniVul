"""Parse raw github.com records into a CVE-keyed list of structured items.

scraper.py wrote one JSON per URL into raw/. This parser collates them
into output.json with shape:

{
  "CVE-...": [
    {
      "source": "github.com",
      "url": "...",
      "role": "patch | exploit",
      "kind": "commit | pull | issue | advisory | release | repo | ...",
      "title": "...",
      "body": "...",            # PR/issue/advisory body
      "author": "...",
      "date": "...",
      "message": "...",          # commit message
      "files": [{"path": ..., "status": ..., "additions": ..., "deletions": ..., "patch": ...}],
      "patch_text": "...",       # unified diff (commits only)
      "state": "open|closed|merged",
      "labels": [...],
      "advisory": { ... },       # advisory-specific fields
      "references": [...]
    }
  ]
}
"""

import os
import sys
from collections import defaultdict
from typing import Any, Dict, List

from tqdm import tqdm

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scraper_common import load_json, save_json  # noqa: E402

RAW_DIR = os.path.join(HERE, "raw")
OUTPUT_FILE = os.path.join(HERE, "output.json")


def _commit(payload: Dict[str, Any]) -> Dict[str, Any]:
    commit = payload.get("commit", {}) or {}
    author = commit.get("author") or {}
    files = []
    for f in payload.get("files") or []:
        files.append({
            "path": f.get("filename"),
            "status": f.get("status"),
            "additions": f.get("additions"),
            "deletions": f.get("deletions"),
            "patch": f.get("patch"),
        })
    return {
        "sha": payload.get("sha"),
        "title": (commit.get("message") or "").splitlines()[0] if commit.get("message") else None,
        "message": commit.get("message"),
        "author": author.get("name"),
        "author_email": author.get("email"),
        "date": author.get("date"),
        "files": files,
    }


def _pull(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": payload.get("title"),
        "body": payload.get("body"),
        "state": "merged" if payload.get("merged") else payload.get("state"),
        "merged_at": payload.get("merged_at"),
        "author": (payload.get("user") or {}).get("login"),
        "labels": [l.get("name") for l in (payload.get("labels") or [])],
        "head": (payload.get("head") or {}).get("sha"),
        "base": (payload.get("base") or {}).get("sha"),
    }


def _issue(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": payload.get("title"),
        "body": payload.get("body"),
        "state": payload.get("state"),
        "author": (payload.get("user") or {}).get("login"),
        "labels": [l.get("name") for l in (payload.get("labels") or [])],
        "closed_at": payload.get("closed_at"),
    }


def _advisory(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ghsa_id": payload.get("ghsa_id"),
        "cve_id": payload.get("cve_id"),
        "title": payload.get("summary") or payload.get("title"),
        "body": payload.get("description"),
        "severity": payload.get("severity"),
        "cvss": payload.get("cvss"),
        "cwe_ids": payload.get("cwe_ids"),
        "vulnerabilities": payload.get("vulnerabilities"),
        "published_at": payload.get("published_at"),
        "updated_at": payload.get("updated_at"),
        "references": payload.get("references"),
    }


def _release(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "tag_name": payload.get("tag_name"),
        "name": payload.get("name"),
        "body": payload.get("body"),
        "published_at": payload.get("published_at"),
    }


def _repo(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": payload.get("full_name"),
        "description": payload.get("description"),
        "stars": payload.get("stargazers_count"),
        "language": payload.get("language"),
    }


PARSERS = {
    "commit": _commit,
    "pull": _pull,
    "issue": _issue,
    "advisory": _advisory,
    "release": _release,
    "repo": _repo,
}


def parse_one(record: Dict[str, Any]) -> Dict[str, Any]:
    kind = record.get("kind")
    payload = record.get("api_payload") or {}
    fn = PARSERS.get(kind, lambda p: {"raw": p})

    item = {
        "source": "github.com",
        "url": record.get("url"),
        "role": record.get("role"),
        "kind": kind,
    }
    item.update(fn(payload))
    if "patch_text" in record:
        item["patch_text"] = record["patch_text"]
    return item


def main() -> None:
    if not os.path.isdir(RAW_DIR):
        raise SystemExit(f"raw dir missing: {RAW_DIR}. Run scraper.py first.")

    by_cve: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    files = sorted(f for f in os.listdir(RAW_DIR) if f.endswith(".json"))
    for fname in tqdm(files, desc="github parse"):
        try:
            record = load_json(os.path.join(RAW_DIR, fname))
        except Exception as exc:  # noqa: BLE001
            print(f"skip {fname}: {exc}")
            continue
        cve = record.get("cve") or fname.split("__")[0]
        by_cve[cve].append(parse_one(record))

    save_json(OUTPUT_FILE, by_cve)
    print(f"{sum(len(v) for v in by_cve.values())} items across {len(by_cve)} CVEs -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
