"""Build the portfolio JSON for the Windows dataset.

Per-CVE we collate:

  1. CVE_intrinsic_attributes
       description.{nvd}
       CWE
       developer_discussion (from github issues/PRs/advisories + msrc + ibm)
  2. CVE_impact
       CVSS.{nvd, msrc, github}
       CPE  (from NVD configurations)
  3. Exploit Set                       — references flagged "exploit" by source
  4. Patch Set                         — references flagged "patch" by source

Source inputs:
  * nvd/nvd_cve_detail/complete_nvd_cve_dict.json (NVD canonical record)
  * msrc.microsoft.com/output.json
  * portal.msrc.microsoft.com/output.json
  * github.com/output.json                (list per CVE)
  * git.kernel.org/output.json            (list per CVE)
  * ibm.com/output.json                   (list per CVE)

Each scraper sets a "role" on every item ("patch" or "exploit"); we
route it into Patch Set / Exploit Set accordingly. Items with rich
discussion (GH PR comments, MSRC ack lists) also surface in
developer_discussion.
"""

import json
import os
from typing import Any, Dict, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(HERE, "final_complete_cve_merged_result.json")

NVD_FILE = os.path.join(HERE, "nvd", "nvd_cve_detail", "complete_nvd_cve_dict.json")
SCRAPER_OUTPUTS = {
    "msrc.microsoft.com": os.path.join(HERE, "msrc.microsoft.com", "output.json"),
    "portal.msrc.microsoft.com": os.path.join(HERE, "portal.msrc.microsoft.com", "output.json"),
    "github.com": os.path.join(HERE, "github.com", "output.json"),
    "git.kernel.org": os.path.join(HERE, "git.kernel.org", "output.json"),
    "ibm.com": os.path.join(HERE, "ibm.com", "output.json"),
}

# Sources whose parser emits a single record (dict) per CVE
SINGLETON_SOURCES = {"msrc.microsoft.com", "portal.msrc.microsoft.com"}
# Sources whose parser emits a list of records per CVE
LIST_SOURCES = {"github.com", "git.kernel.org", "ibm.com"}


def _load_optional(path: str) -> Optional[Any]:
    if not os.path.exists(path):
        print(f"warn: {path} missing — run its scraper.py + parser.py to populate.")
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _init_cve(final: Dict[str, Any], cve_id: str) -> None:
    final[cve_id] = {
        "CVE_intrinsic_attributes": {
            "description": {},
            "CWE": [],
            "developer_discussion": {},
        },
        "CVE_impact": {"CVSS": {}, "CPE": {}},
        "Exploit Set": {},
        "Patch Set": {},
    }


def _add_nvd_basics(cve_id: str, record: Dict[str, Any], final: Dict[str, Any]) -> None:
    intrinsic = final[cve_id]["CVE_intrinsic_attributes"]
    descs = record.get("descriptions") or []
    if descs:
        intrinsic["description"]["nvd"] = descs[0].get("value")
    intrinsic["CWE"] = record.get("weaknesses") or []

    impact = final[cve_id]["CVE_impact"]
    impact["CVSS"]["nvd"] = record.get("metrics", {})

    cpe_res: Dict[str, Any] = {}
    for cfg in record.get("configurations", []) or []:
        nodes = cfg.get("nodes") or []
        if not nodes:
            continue
        for cpe in (nodes[0].get("cpeMatch") or []):
            cpe_id = cpe.get("criteria")
            if not cpe_id:
                continue
            parts = cpe_id.split(":")
            if len(parts) < 6:
                continue
            cpe_res[cpe_id] = {
                "cpe": cpe_id,
                "version": f"{parts[0]}{parts[1]}",
                "vendor": parts[3],
                "product": parts[4],
                "product_version": parts[5],
            }
    impact["CPE"] = cpe_res


def _add_msrc(source: str, payload: Dict[str, Any], final: Dict[str, Any]) -> None:
    for cve_id, item in payload.items():
        if cve_id not in final:
            continue
        intrinsic = final[cve_id]["CVE_intrinsic_attributes"]
        if item.get("description"):
            intrinsic["description"][source] = item["description"]

        cvss = item.get("cvss") or {}
        if cvss:
            final[cve_id]["CVE_impact"]["CVSS"][source] = cvss

        # Acknowledgements ≈ developer discussion
        ack = item.get("acknowledgements") or []
        if ack:
            intrinsic["developer_discussion"][source] = {
                "source": source,
                "type": "acknowledgements",
                "value": ack,
            }

        bucket = final[cve_id]["Patch Set" if item.get("role") == "patch" else "Exploit Set"]
        bucket.setdefault(source, {})[item["url"]] = {
            "source": source,
            "title": item.get("title"),
            "description": item.get("description"),
            "remediations": item.get("remediations"),
            "references": item.get("references"),
            "release_date": item.get("release_date"),
            "last_modified": item.get("last_modified"),
            "exploited": item.get("exploited"),
        }


def _add_list_source(source: str, payload: Dict[str, Any], final: Dict[str, Any]) -> None:
    for cve_id, items in payload.items():
        if cve_id not in final:
            continue
        intrinsic = final[cve_id]["CVE_intrinsic_attributes"]
        discussions = []

        for item in items:
            role = item.get("role") or "patch"
            url = item.get("url")
            bucket = final[cve_id]["Patch Set" if role == "patch" else "Exploit Set"]
            bucket.setdefault(source, {})[url] = item

            # github commits/PRs/issues + ibm bulletins make good discussion fodder
            if source == "github.com" and item.get("kind") in {"pull", "issue", "advisory"}:
                discussions.append({
                    "type": item.get("kind"),
                    "url": url,
                    "title": item.get("title"),
                    "body": item.get("body"),
                    "state": item.get("state"),
                })
            elif source == "ibm.com":
                # IBM bulletin summary doubles as a vendor-side discussion record
                if item.get("summary") or item.get("vulnerability_details"):
                    discussions.append({
                        "type": "bulletin",
                        "url": url,
                        "title": item.get("title"),
                        "summary": item.get("summary"),
                        "details": item.get("vulnerability_details"),
                    })

            if source == "github.com" and item.get("kind") == "advisory":
                ghsa = item.get("cvss") or {}
                if ghsa:
                    final[cve_id]["CVE_impact"]["CVSS"].setdefault(source, ghsa)

        if discussions:
            intrinsic["developer_discussion"][source] = {
                "source": source,
                "type": "scraped_records",
                "entries": discussions,
            }


def main() -> None:
    nvd = _load_optional(NVD_FILE)
    if nvd is None:
        raise SystemExit(f"NVD file required: {NVD_FILE}")

    final: Dict[str, Any] = {}
    for cve_id in nvd:
        _init_cve(final, cve_id)
        _add_nvd_basics(cve_id, nvd[cve_id], final)

    scraped = {name: _load_optional(path) for name, path in SCRAPER_OUTPUTS.items()}
    for name, payload in scraped.items():
        if not payload:
            continue
        if name in SINGLETON_SOURCES:
            _add_msrc(name, payload, final)
        else:
            _add_list_source(name, payload, final)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(final, f, indent=4, ensure_ascii=False)

    n_with_msrc = sum(1 for v in final.values() if "msrc.microsoft.com" in v["Patch Set"])
    n_with_gh = sum(1 for v in final.values() if "github.com" in v["Patch Set"] or "github.com" in v["Exploit Set"])
    print(f"Output saved to {OUTPUT_FILE}")
    print(f"  total CVEs        : {len(final)}")
    print(f"  with MSRC patch   : {n_with_msrc}")
    print(f"  with GitHub items : {n_with_gh}")


if __name__ == "__main__":
    main()
