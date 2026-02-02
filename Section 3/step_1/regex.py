#!/usr/bin/env python3
import json, re, pathlib, sys
from collections import defaultdict

FILE_RE = re.compile(
    r'''
    (?:
        \bfile\s+ | \bin\s+ | \bof\s+
    )?
    (
      [A-Za-z0-9_\-./]+? /? [A-Za-z0-9_\-]+ \.
      (?:c|h|s|S|cc|cpp|go|o)
    )
    (?=[\s,;:.)]|$)
    ''', re.VERBOSE | re.IGNORECASE)

UNDER_FUNC_RE = re.compile(
    r'''
    \b
    ([A-Za-z0-9]*_[A-Za-z0-9_]*[a-z][A-Za-z0-9_]*)
    \b
    (?!\s*\.(?:c|h|s|S|cc|cpp|go|o)\b)
    ''', re.VERBOSE)

FUNC_TOKEN = r'[A-Za-z0-9_]*[a-z][A-Za-z0-9_]*'
CONTEXT_FUNC_RE = re.compile(
    fr'''
    (?:
        \b({FUNC_TOKEN})\s*\(\) |
        \bfunction\s+({FUNC_TOKEN})\b |
        \b({FUNC_TOKEN})\s+function\b |
    )
    (?!\s*\.(?:c|h|s|S|cc|cpp|go|o)\b)
    ''', re.VERBOSE)

def extract_candidates(text: str):
    files = FILE_RE.findall(text)

    funcs = UNDER_FUNC_RE.findall(text)
    funcs += [m for tup in CONTEXT_FUNC_RE.findall(text) for m in tup if m]

    dedup = lambda lst: sorted(set(lst))

    STOP = {'in','of','fix','handle','add','remove','enable','disable',
        'return','error','leak','update','use','make','move','change'}

    def clean_funcs(funcs):
        out = []
        for f in funcs:
            if f.lower() not in STOP and len(f) > 2:
                out.append(f)
        return out
    funcs = clean_funcs( dedup(funcs) )

    return {
        "function": dedup(funcs),
        "file":     dedup(files),
    }

def run_on_json(json_path: str,
                out_path: str = "final_regex_candidates.json"):
    data = json.loads(pathlib.Path(json_path).read_text())
    for cve_id, srcs in data.items():
        descs = []
        for src in ("nvd", "redhat", "ubuntu"):
            if src in srcs and srcs[src].get("description") \
               and srcs[src]["description"] != "same as nvd":
                descs.append(srcs[src]["description"])
                if src == "redhat" and srcs[src].get("additional_info_bugzilla"):
                    descs.append(srcs[src]["additional_info_bugzilla"])
        text = "; ".join(descs)
        srcs["extract_by_regex"] = extract_candidates(text)

    pathlib.Path(out_path).write_text(json.dumps(data, indent=4))
    print(f"[✔] saved: {out_path}")

if __name__ == "__main__":
    run_on_json("../final_complete_nvd_redhat_ubuntu_cve_descriptions.json")
