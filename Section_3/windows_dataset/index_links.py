"""Build per-domain CVE -> {patch_urls, exploit_urls} indices.

Sources:
  * nvd/Windows_final_cves.json (CVE -> {Patch Links, Exploit Links})
  * exploit_links.txt / patch_links.txt (flat lists, used to verify a URL's role)

For each of the top-5 domains we create `<domain>/links.json` keyed by
CVE so the matching scraper can iterate without rediscovering URLs.

The flat exploit/patch text files lose the CVE association, so they are
used only to cross-check whether a URL counts as an exploit reference,
a patch reference, or both. The CVE->URL mapping always comes from
Windows_final_cves.json.
"""

import os
import sys
from collections import defaultdict
from typing import Any, Dict, Iterable, List

from scraper_common import domain_of, load_json, save_json

HERE = os.path.dirname(os.path.abspath(__file__))

TOP5_DOMAINS = [
    "msrc.microsoft.com",
    "portal.msrc.microsoft.com",
    "github.com",
    "git.kernel.org",
    "ibm.com",
]


def _flatten(items: Iterable[Any]) -> List[str]:
    """Windows_final_cves.json mixes raw strings and nested lists. Flatten."""
    out: List[str] = []
    for it in items:
        if isinstance(it, str):
            if it:
                out.append(it)
        elif isinstance(it, list):
            out.extend(_flatten(it))
    return out


def _read_text_lines(path: str) -> set:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def build_indices() -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    cves_path = os.path.join(HERE, "nvd", "Windows_final_cves.json")
    cve_entries = load_json(cves_path)

    exploit_set = _read_text_lines(os.path.join(HERE, "exploit_links.txt"))
    patch_set = _read_text_lines(os.path.join(HERE, "patch_links.txt"))

    # per_domain[domain][cve_id] = {"patch_urls": [...], "exploit_urls": [...]}
    per_domain: Dict[str, Dict[str, Dict[str, List[str]]]] = {
        d: defaultdict(lambda: {"patch_urls": [], "exploit_urls": []})
        for d in TOP5_DOMAINS
    }

    for entry in cve_entries:
        cve_id = entry.get("CVE ID")
        if not cve_id:
            continue
        patches = _flatten(entry.get("Patch Links", []))
        exploits = _flatten(entry.get("Exploit Links", []))

        for url in patches:
            d = domain_of(url)
            if d in per_domain and url not in per_domain[d][cve_id]["patch_urls"]:
                per_domain[d][cve_id]["patch_urls"].append(url)
        for url in exploits:
            d = domain_of(url)
            if d in per_domain and url not in per_domain[d][cve_id]["exploit_urls"]:
                per_domain[d][cve_id]["exploit_urls"].append(url)

    # Cross-check: if a URL we already attributed was also in the opposite
    # flat list, expose that under the alternate role so the scraper
    # records both roles.
    for d, by_cve in per_domain.items():
        for cve_id, buckets in by_cve.items():
            for url in list(buckets["patch_urls"]):
                if url in exploit_set and url not in buckets["exploit_urls"]:
                    buckets["exploit_urls"].append(url)
            for url in list(buckets["exploit_urls"]):
                if url in patch_set and url not in buckets["patch_urls"]:
                    buckets["patch_urls"].append(url)

    return {d: dict(per_domain[d]) for d in TOP5_DOMAINS}


def main() -> None:
    indices = build_indices()
    for domain, by_cve in indices.items():
        out_dir = os.path.join(HERE, domain)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "links.json")
        save_json(out_path, by_cve)
        n_urls = sum(
            len(b["patch_urls"]) + len(b["exploit_urls"])
            for b in by_cve.values()
        )
        print(f"[{domain}] {len(by_cve)} CVEs / {n_urls} URLs -> {out_path}")


if __name__ == "__main__":
    main()
