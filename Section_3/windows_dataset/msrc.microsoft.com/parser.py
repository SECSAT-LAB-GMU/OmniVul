"""Parse raw MSRC JSON dumps into a CVE-keyed summary.

Reads raw/<CVE>.json (produced by scraper.py) and emits output.json with
the fields downstream portfolio_construction.py expects to consume.

Output schema:
{
  "CVE-2022-XXXX": {
    "source": "msrc.microsoft.com",
    "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-...",
    "role": "patch",
    "title": "...",
    "description": "...",
    "cvss": {"baseScore": float, "vector": str, "severity": str},
    "cwe": ["CWE-..."],
    "affected_products": [{"name": ..., "platform": ..., "versions": [...]}],
    "remediations": [{"type": ..., "kb": ..., "url": ..., "description": ...}],
    "acknowledgements": [...],
    "references": [...],
    "exploited": bool,
    "exploitability_assessment": str,
    "release_date": str,
    "last_modified": str
  }
}
"""

import os
from typing import Any, Dict, List

from tqdm import tqdm

import sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from scraper_common import load_json, save_json  # noqa: E402

RAW_DIR = os.path.join(HERE, "raw")
OUTPUT_FILE = os.path.join(HERE, "output.json")

PUBLIC_URL = "https://msrc.microsoft.com/update-guide/vulnerability/{cve}"


def _pick(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return default


def _cvss_block(payload: Dict[str, Any]) -> Dict[str, Any]:
    # The SUG API now returns CVSS fields flat at top-level; older CVRF
    # payloads nest them under cvssScoreSets/cvssV3. Handle both.
    nested = _pick(payload, "cvssScoreSets", "cvssV3", "cvss", default=None)
    if isinstance(nested, list) and nested:
        nested = nested[0]
    src = nested if isinstance(nested, dict) else payload
    return {
        "baseScore": _pick(src, "baseScore", "score", "value"),
        "vector": _pick(src, "vector", "vectorString"),
        "severity": _pick(src, "baseSeverity", "severity"),
        "temporalScore": _pick(src, "temporalScore"),
        "vectorSource": _pick(src, "vectorStringSource"),
    }


def _normalise_products(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    products = _pick(payload, "affectedProducts", "products", default=[]) or []
    out: List[Dict[str, Any]] = []
    for p in products:
        if not isinstance(p, dict):
            continue
        out.append({
            "name": _pick(p, "name", "productName", "product"),
            "platform": _pick(p, "platform", "productFamily"),
            "versions": _pick(p, "versions", "versionList", default=[]) or [],
        })
    return out


def _normalise_remediations(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    rems = _pick(payload, "remediations", "kbArticles", default=[]) or []
    out: List[Dict[str, Any]] = []
    for r in rems:
        if not isinstance(r, dict):
            continue
        out.append({
            "type": _pick(r, "type", "remediationType"),
            "kb": _pick(r, "kbArticle", "kb", "id"),
            "url": _pick(r, "url", "downloadUrl"),
            "description": _pick(r, "description", "fixedBuildNumber"),
            "products": _pick(r, "products", "affectedProducts", default=[]),
        })
    return out


def _normalise_references(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs = _pick(payload, "references", "externalReferences", default=[]) or []
    out: List[Dict[str, Any]] = []
    for r in refs:
        if isinstance(r, str):
            out.append({"url": r})
        elif isinstance(r, dict):
            out.append({
                "url": _pick(r, "url", "href"),
                "label": _pick(r, "label", "description", "title"),
            })
    return out


def parse_one(cve: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": "msrc.microsoft.com",
        "url": PUBLIC_URL.format(cve=cve),
        "role": "patch",
        "title": _pick(payload, "title", "name", "cveTitle"),
        "description": _pick(
            payload, "description", "executiveSummary", "summary", "tag"
        ),
        "impact": _pick(payload, "impact"),
        "vuln_type": _pick(payload, "vulnType"),
        "cvss": _cvss_block(payload),
        "cwe": (
            _pick(payload, "cweDetailsList", default=[])
            or _pick(payload, "cweList", "cwe", default=[])
            or []
        ),
        "affected_products": _normalise_products(payload),
        "remediations": _normalise_remediations(payload),
        "acknowledgements": _pick(payload, "acknowledgements", "credits", default=[]) or [],
        "references": _normalise_references(payload),
        "articles": _pick(payload, "articles", default=[]) or [],
        "revisions": _pick(payload, "revisions", default=[]) or [],
        "exploited": _pick(payload, "exploited", "publiclyDisclosed", default=False),
        "exploitability_assessment": _pick(
            payload,
            "exploitabilityAssessment",
            "latestSoftwareRelease",
            "olderSoftwareRelease",
            default=None,
        ),
        "publicly_disclosed": _pick(payload, "publiclyDisclosed"),
        "mitre_url": _pick(payload, "mitreUrl"),
        "release_date": _pick(payload, "releaseDate", "releasedDate"),
        "last_modified": _pick(payload, "lastModifiedDate", "latestRevisionDate"),
    }


def main() -> None:
    if not os.path.isdir(RAW_DIR):
        raise SystemExit(f"raw dir missing: {RAW_DIR}. Run scraper.py first.")

    results: Dict[str, Dict[str, Any]] = {}
    files = sorted(f for f in os.listdir(RAW_DIR) if f.endswith(".json"))
    for fname in tqdm(files, desc="msrc parse"):
        cve = fname[: -len(".json")]
        try:
            payload = load_json(os.path.join(RAW_DIR, fname))
        except Exception as exc:  # noqa: BLE001
            print(f"skip {cve}: {exc}")
            continue
        results[cve] = parse_one(cve, payload)

    save_json(OUTPUT_FILE, results)
    print(f"{len(results)} CVEs parsed -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
