"""Helpers that turn a merged-portfolio CVE entry into RAG documents.

The portfolio schema produced by ../portfolio_construction.py looks like:

  {
    "CVE_intrinsic_attributes": {
        "description": {<source>: <text>, ...},
        "CWE": [ {"description": [{"value": "CWE-..."}], ...}, ... ],
        "developer_discussion": {<source>: {"type": ..., "entries"/"value": ...}}
    },
    "CVE_impact": {
        "CVSS": {<source>: {... nvd metric lists / msrc flat block ...}},
        "CPE":  {<cpe-id>: {...}}
    },
    "Patch Set":   {<source>: {<url>: <item>}},
    "Exploit Set": {<source>: {<url>: <item>}}
  }

`build_documents()` flattens that into a list of langchain Documents (the RAG
corpus) plus a `ground_truth` dict that carries the portfolio-side answers the
QA pipeline compares against.
"""

import json

from langchain_core.documents import Document

# Fields on a scraped patch/exploit item that contain prose worth indexing.
TEXT_FIELDS = (
    "title", "subject", "message", "description", "summary",
    "vulnerability_details", "remediation", "workarounds", "body",
    "name", "state",
)


def _flatten_refs(refs):
    if not refs:
        return ""
    if not isinstance(refs, list):
        return str(refs)
    out = []
    for r in refs:
        if isinstance(r, dict):
            out.append(r.get("url") or r.get("label") or json.dumps(r, ensure_ascii=False))
        else:
            out.append(str(r))
    return ", ".join(x for x in out if x)


def item_to_text(item):
    """Readable prose for an item (commit message, bulletin summary, etc.)."""
    if not isinstance(item, dict):
        return str(item)
    parts = []
    for fld in TEXT_FIELDS:
        val = item.get(fld)
        if val:
            parts.append(f"{fld}: {val}")
    refs = _flatten_refs(item.get("references"))
    if refs:
        parts.append(f"references: {refs}")
    return "\n".join(parts)


def _looks_like_html_challenge(text):
    head = text[:300].lower()
    return "<!doctype html" in head or "not a bot" in head or "<html" in head


def item_diff(item):
    """A unified diff for an item, if one is present and usable."""
    if not isinstance(item, dict):
        return ""
    patch_text = item.get("patch_text") or ""
    if patch_text and not _looks_like_html_challenge(patch_text):
        return patch_text
    files = item.get("files") or item.get("changed_files") or []
    chunks = []
    for f in files:
        if isinstance(f, dict) and f.get("patch"):
            chunks.append(f"--- {f.get('path', '')}\n{f['patch']}")
    return "\n\n".join(chunks)


def added_lines(diff):
    """The '+' lines of a unified diff == the patched/fixed code."""
    added = []
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    return "\n".join(added)


def cwe_values(intrinsic):
    """Join the NVD weakness descriptions into a ground-truth CWE string."""
    vals = []
    for w in intrinsic.get("CWE") or []:
        if isinstance(w, dict):
            for d in w.get("description") or []:
                if isinstance(d, dict) and d.get("value"):
                    vals.append(d["value"])
    out = list(dict.fromkeys(vals))
    return ", ".join(out) if out else "Not given"


def primary_metric(impact):
    """Pick the most recent NVD CVSS metric and expose the SCORES tags."""
    nvd = (impact.get("CVSS") or {}).get("nvd") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = nvd.get(key)
        if arr:
            m = arr[0] if isinstance(arr, list) else arr
            cd = m.get("cvssData", {}) if isinstance(m, dict) else {}
            return {
                "baseScore": cd.get("baseScore"),
                "baseSeverity": cd.get("baseSeverity") or m.get("baseSeverity"),
                "impactScore": m.get("impactScore"),
                "exploitabilityScore": m.get("exploitabilityScore"),
                "availabilityImpact": cd.get("availabilityImpact"),
            }
    return {}


def ret_documents(discussions):
    """Turn the developer_discussion mapping into Documents.

    Handles the two shapes our parsers emit:
      * {"type": "acknowledgements", "value": [...]}          (msrc/portal)
      * {"type": "scraped_records",  "entries": [ {...}, ]}   (github/ibm)
    plus a permissive fallback for raw strings/lists.
    """
    documents = []
    for source, disc in (discussions or {}).items():
        if isinstance(disc, dict):
            dtype = disc.get("type")
            if dtype == "acknowledgements":
                vals = disc.get("value") or []
                text = "Acknowledgements: " + ", ".join(str(v) for v in vals)
                documents.append(Document(text, metadata={"source": source}))
            elif dtype == "scraped_records":
                for entry in disc.get("entries") or []:
                    parts = []
                    for fld in ("title", "summary", "details", "body", "state", "url"):
                        val = entry.get(fld)
                        if val:
                            parts.append(f"{fld}: {val}")
                    if parts:
                        kind = entry.get("type", "record")
                        documents.append(
                            Document("\n".join(parts), metadata={"source": f"{source}:{kind}"})
                        )
            else:
                documents.append(
                    Document(json.dumps(disc, ensure_ascii=False), metadata={"source": source})
                )
        elif isinstance(disc, list):
            for txt in disc:
                if txt:
                    documents.append(Document(str(txt), metadata={"source": source}))
        elif disc:
            documents.append(Document(str(disc), metadata={"source": source}))
    return documents


def _link_documents(item, source, url, label):
    """One or two Documents for a single patch/exploit link."""
    docs = []
    text = item_to_text(item)
    header = f"[{label} from {source}] {url}"
    docs.append(
        Document(header + ("\n" + text if text else ""),
                 metadata={"source": f"{label.lower()}:{source}"})
    )
    diff = item_diff(item)
    if diff:
        tag = "patch diff" if label == "PATCH" else "exploit code"
        docs.append(Document(f"[{tag.upper()}]\n{diff}", metadata={"source": f"{tag}:{source}"}))
    return docs


def build_documents(portfolio):
    """Flatten a CVE portfolio entry into (documents, ground_truth)."""
    documents = []
    ground_truth = {"Patch": {}, "Exploit": {}, "CWE": None, "SCORES": {}}

    intrinsic = portfolio.get("CVE_intrinsic_attributes", {}) or {}
    impact = portfolio.get("CVE_impact", {}) or {}

    # 1. vulnerability descriptions
    for source, desc in (intrinsic.get("description") or {}).items():
        if desc:
            documents.append(Document(str(desc), metadata={"source": f"description:{source}"}))

    # 2. patch set -> docs + patch code / code diff ground truth
    patch_codes, code_diffs = [], []
    for source, urls in (portfolio.get("Patch Set") or {}).items():
        for url, item in (urls or {}).items():
            documents.extend(_link_documents(item, source, url, "PATCH"))
            diff = item_diff(item)
            if diff:
                code_diffs.append(diff)
                added = added_lines(diff)
                if added:
                    patch_codes.append(added)
    if patch_codes:
        ground_truth["Patch"]["Patch code"] = "\n\n".join(patch_codes)
    if code_diffs:
        ground_truth["Patch"]["Code diff"] = "\n\n".join(code_diffs)

    # 3. exploit set -> docs + exploit code ground truth
    exploit_codes = []
    for source, urls in (portfolio.get("Exploit Set") or {}).items():
        for url, item in (urls or {}).items():
            documents.extend(_link_documents(item, source, url, "EXPLOIT"))
            diff = item_diff(item)
            if diff:
                exploit_codes.append(diff)
    if exploit_codes:
        ground_truth["Exploit"]["Exploit Code"] = "\n\n".join(exploit_codes)

    # 4. impact: CVSS metrics + affected CPEs
    for source, metric in (impact.get("CVSS") or {}).items():
        documents.append(
            Document(f"CVSS ({source}): {json.dumps(metric, ensure_ascii=False)}",
                     metadata={"source": f"cvss:{source}"})
        )
    cpes = list((impact.get("CPE") or {}).keys())
    if cpes:
        documents.append(Document("Affected CPEs:\n" + "\n".join(cpes), metadata={"source": "cpe"}))

    # 5. developer discussions
    documents.extend(ret_documents(intrinsic.get("developer_discussion") or {}))

    # 6. ground truth for CWE + SCORES
    ground_truth["CWE"] = cwe_values(intrinsic)
    ground_truth["SCORES"] = primary_metric(impact)

    return documents, ground_truth
