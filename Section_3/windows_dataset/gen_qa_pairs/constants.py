import os

# Prefer an env var so the key never has to live in the repo; fall back to a
# literal here if you'd rather paste it in.
GPT_KEY = os.environ.get("OPENAI_API_KEY") or os.environ.get("GPT_KEY") or ''


# Top-level portfolio sections (match ../portfolio_construction.py output)
INTRINSIC_ATTRIBS = "CVE_intrinsic_attributes"
IMPACT = "CVE_impact"
PATCH_SET = "Patch Set"
EXPLOIT_SET = "Exploit Set"

# Keys inside CVE_intrinsic_attributes
DESCRIPTION = "description"
CWE = "CWE"
DISCUSSIONS = "developer_discussion"

# Keys inside CVE_impact
CVSS = "CVSS"
CPE = "CPE"
