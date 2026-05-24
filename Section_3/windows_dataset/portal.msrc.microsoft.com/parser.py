"""Parse raw MSRC portal payloads into a CVE-keyed summary.

For each CVE the scraper saved two files:
  raw/<CVE>.json           — SUG API JSON (canonical source of fields)
  raw/<CVE>.redirect.json  — legacy URL response metadata (provenance)

We emit one record per CVE in output.json, mirroring the schema of
msrc.microsoft.com/parser.py so the portfolio can stitch them together.
"""

import os
import sys
from typing import Any, Dict, List

from tqdm import tqdm

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scraper_common import load_json, save_json  # noqa: E402

RAW_DIR = os.path.join(HERE, "raw")
OUTPUT_FILE = os.path.join(HERE, "output.json")

LEGACY_URL = "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/{cve}"


def _pick(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return default


def _cvss_block(payload: Dict[str, Any]) -> Dict[str, Any]:
    nested = _pick(payload, "cvssScoreSets", "cvssV3", "cvss", default=None)
    if isinstance(nested, list) and nested:
        nested = nested[0]
    src = nested if isinstance(nested, dict) else payload
    return {
        "baseScore": _pick(src, "baseScore", "score", "value"),
        "vector": _pick(src, "vector", "vectorString"),
        "severity": _pick(src, "baseSeverity", "severity"),
        "temporalScore": _pick(src, "temporalScore"),
    }


def _products(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    products = _pick(payload, "affectedProducts", "products", default=[]) or []
    out = []
    for p in products:
        if isinstance(p, dict):
            out.append({
                "name": _pick(p, "name", "productName"),
                "platform": _pick(p, "platform", "productFamily"),
                "versions": _pick(p, "versions", "versionList", default=[]) or [],
            })
    return out


def _remediations(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    rems = _pick(payload, "remediations", "kbArticles", default=[]) or []
    out = []
    for r in rems:
        if isinstance(r, dict):
            out.append({
                "type": _pick(r, "type", "remediationType"),
                "kb": _pick(r, "kbArticle", "kb"),
                "url": _pick(r, "url", "downloadUrl"),
                "description": _pick(r, "description", "fixedBuildNumber"),
            })
    return out


def _references(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs = _pick(payload, "references", "externalReferences", default=[]) or []
    out = []
    for r in refs:
        if isinstance(r, str):
            out.append({"url": r})
        elif isinstance(r, dict):
            out.append({"url": _pick(r, "url", "href"), "label": _pick(r, "label", "title")})
    return out


def parse_one(cve: str, payload: Dict[str, Any], redirect: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": "portal.msrc.microsoft.com",
        "url": LEGACY_URL.format(cve=cve),
        "role": "patch",
        "legacy_redirect": {
            "status": redirect.get("status"),
            "location": redirect.get("final_url"),
        },
        "title": _pick(payload, "title", "name", "cveTitle"),
        "description": _pick(payload, "description", "executiveSummary", "summary", "tag"),
        "impact": _pick(payload, "impact"),
        "cvss": _cvss_block(payload),
        "cwe": (
            _pick(payload, "cweDetailsList", default=[])
            or _pick(payload, "cweList", "cwe", default=[])
            or []
        ),
        "affected_products": _products(payload),
        "remediations": _remediations(payload),
        "acknowledgements": _pick(payload, "acknowledgements", "credits", default=[]) or [],
        "references": _references(payload),
        "exploited": _pick(payload, "exploited", "publiclyDisclosed", default=False),
        "release_date": _pick(payload, "releaseDate", "releasedDate"),
        "last_modified": _pick(payload, "lastModifiedDate", "lastUpdated"),
    }


def main() -> None:
    if not os.path.isdir(RAW_DIR):
        raise SystemExit(f"raw dir missing: {RAW_DIR}. Run scraper.py first.")

    results: Dict[str, Dict[str, Any]] = {}
    cve_files = sorted(f for f in os.listdir(RAW_DIR) if f.endswith(".json") and not f.endswith(".redirect.json"))
    for fname in tqdm(cve_files, desc="portal.msrc parse"):
        cve = fname[: -len(".json")]
        try:
            payload = load_json(os.path.join(RAW_DIR, fname))
        except Exception as exc:  # noqa: BLE001
            print(f"skip {cve}: {exc}")
            continue
        redirect_path = os.path.join(RAW_DIR, f"{cve}.redirect.json")
        redirect = load_json(redirect_path) if os.path.exists(redirect_path) else {}
        results[cve] = parse_one(cve, payload, redirect)

    save_json(OUTPUT_FILE, results)
    print(f"{len(results)} CVEs parsed -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
