TEMPLATE_R1 = """
    # Role and Objective
    You are an expert software security analyst.
    You will be given a list of dictionaries, where each key is a file name and each value is a code block within that file.
    Analyze only the code blocks and decide whether each code block contains a security vulnerability.

    # Definitions
    - "vulnerable": The code exhibits a concrete, actionable security flaw (e.g., memory safety bug, injection, auth/crypto misuse) that is inferable from the snippet itself.
    - "not_vulnerable": No clear vulnerability is present based solely on the snippet.

    # Instructions
    For each file name:
        - Return one of: 1 (vulnerable), 0 (not_vulnerable), or -1 (unknown).
        - Use the visible code as the primary evidence. Do NOT invent vulnerabilities unrelated to the snippet.
        - If you mark 1 (vulnerable), you must internally identify at least one concrete flaw in the snippet (but do not explain it in the output).

    # Output Format (strict)
    Respond with a JSON object where each file name from the input dictionary is a key and the value is its classification:
    {{
        "FileA.c": 1,
        "FileB.h": 0,
        ...
    }}

    Do NOT include any explanations, Markdown, or code fences. Output raw JSON only.

    # Code Blocks:
    {code_blocks}
"""

TEMPLATE_R2 = """
    # Role and Objective
    You are an expert software security analyst.
    You will be given:
        1. A list of file names belonging to an unknown CVE ID.
        2. A corresponding list of dictionaries where each key is a file name and each value is a vulnerable code block from that file.
        3. A set of pre-fetched search results relevant to the vulnerabilities in the code blocks.
    These code blocks have ALREADY been identified as containing security vulnerabilities.
    Your task is to analyze the vulnerable file names, code blocks, and optionally the search results, then retrieve exactly 5 CVE IDs that could match the vulnerabilities evidenced by the code.

    # Instructions
    - Use the file names and visible code blocks (including in-code strings/comments) as the primary evidence; also use the search results to corroborate, refine, or downgrade candidates.
    - If the search results is empty or unhelpful, rely on the file names, code blocks, and your broader knowledge of publicly documented CVEs.
    - Treat the file names as meaningful context, since they may correspond to OS components, kernel modules, or libraries related to CVE IDs.
    - Strong signals include: function names, file names, protocol/feature identifiers, exploit strings, or in-code CVE references.
    - Always produce exactly 5 CVE candidates for the given input (not per file):
        * 0.85–1.00 = strong match (near-unique trigger + CWE/vulnerability type + component corroborated by search results)
        * 0.60–0.84 = moderate match (strong overlap, partial corroboration)
        * 0.40–0.59 = weak match (generic overlap or minimal corroboration)
        * below 0.40 = very weak match (include if needed to fill 5 slots)
    - Rank the candidates from highest to lowest confidence.
    - Exclude RESERVED/REJECT CVE IDs and duplicates/aliases.
    - Do NOT fabricate CVE IDs, only output CVE IDs that are real.

    # Output Format
    Respond with a JSON array containing exactly 5 objects:
    [
      {{
        "CVE_ID": "CVE-YYYY-NNNN",
        "confidence": <float>,
        "match_reason": "<short reason>"
      }},
      ...
    ]

    Do NOT include any explanations, Markdown, or code fences. Output raw JSON only.

    # File Names:
    {file_names}

    # Vulnerable Code Blocks:
    {code_blocks}

    # Search Results:
    {search_context}
"""

TEMPLATE_R2_SEARCH = """
    # Role and Objective
    You are an expert software security analyst.
    You will be given:
        1. A list of file names belonging to an unknown CVE ID.
        2. A corresponding list of dictionaries where each key is a file name and each value is a vulnerable code block from that file.
    These code blocks have ALREADY been identified as containing security vulnerabilities.
    Your task is to propose focused web search queries to find the most likely matching CVE IDs.

    # Instructions
    - Return up to 5 UNIQUE queries; each query should be concise (under 15 words).
    - Build queries by combining exact identifiers from the snippets (component/module names, file paths, function names, error strings) with the word CVE.
    - Prefer site filters to authoritative sources: NVD, MITRE, vendor advisories, kernel.org/git commits, LKML, Debian/Ubuntu/Red Hat advisories.
    - Extract only minimal facts (CVE ID, component/module, CWE/type, patch/commit IDs, affected versions).
    - Do NOT include links or citations in the output.

    # Output Format
    Respond with a JSON list of strings:
    [
      "Query 1",
      "Query 2",
      ...
    ]

    Do NOT include any explanations, Markdown, or code fences. Output raw JSON only.

    # File Names:
    {file_names}

    # Vulnerable Code Blocks:
    {code_blocks}
"""

TEMPLATE_R3 = """
    # Role and Objective
    You are an information extraction and software security analysis expert.
    You will be given:
        1. A CVE ID.
        2. A corresponding list of file names belonging to that CVE ID.
        3. A corresponding list of dictionaries where each key is a file name and each value is a vulnerable code block from that file.
        4. A set of pre-fetched search results relevant to the CVE ID and vulnerabilities in the code blocks.
    These code blocks have ALREADY been identified as containing security vulnerabilities.
    Your task is to answer the user question about the CVE with precision and completeness.

    # Instructions  
    - Use all available information: the CVE ID, file names, visible code blocks, and the search results as evidence.
    - You may also incorporate your broader knowledge of publicly documented CVEs, particularly the given CVE ID, from sources such as vulnerability databases, advisories, and security literature.
    - If the question explicitly asks for code (e.g., "vulnerable code", "exploit code", "patch code", "code diff", "crash dump", etc.):
        * Always include the actual code snippet(s) from the provided input if available.
        * If the relevant code is not in the provided input, you may use your broader knowledge of the CVE ID to recall the correct code from well-documented advisories or patches.
        * If you cannot reliably recall the exact code, respond with "Not found".
    - For all **non-code answers**, keep the response **under 150 words**.
    - Provide precise, factual, and complete answers in formal language suitable for security documentation.
    - If the answer cannot be determined from the CVE ID, file names, visible code blocks, the search results, or your broader knowledge of publicly documented CVEs, reply with "Not found".

    # CVE ID:
    {cve_id}

    # File Names:
    {file_names}

    # Vulnerable Code Blocks:
    {code_blocks}

    # Search Results:
    {search_context}

    # Question:
    {question}
"""

# seperate template for Claude to use prompt caching
TEMPLATE_R3_CLAUDE = """
    # Role and Objective
    You are an information extraction and software security analysis expert.
    You will be given:
        1. A CVE ID.
        2. A corresponding list of file names belonging to that CVE ID.
        3. A corresponding list of dictionaries where each key is a file name and each value is a vulnerable code block from that file.
        4. A set of pre-fetched search results relevant to the CVE ID and vulnerabilities in the code blocks.
    These code blocks have ALREADY been identified as containing security vulnerabilities.
    Your task is to answer the user question about the CVE with precision and completeness.

    # Instructions  
    - Use all available information: the CVE ID, file names, visible code blocks, and the search results as evidence.
    - You may also incorporate your broader knowledge of publicly documented CVEs, particularly the given CVE ID, from sources such as vulnerability databases, advisories, and security literature.
    - If the question explicitly asks for code (e.g., "vulnerable code", "exploit code", "patch code", "code diff", "crash dump", etc.):
        * Always include the actual code snippet(s) from the provided input if available.
        * If the relevant code is not in the provided input, you may use your broader knowledge of the CVE ID to recall the correct code from well-documented advisories or patches.
        * If you cannot reliably recall the exact code, respond with "Not found".
    - For all **non-code answers**, keep the response **under 150 words**.
    - Provide precise, factual, and complete answers in formal language suitable for security documentation.
    - If the answer cannot be determined from the CVE ID, file names, visible code blocks, the search results, or your broader knowledge of publicly documented CVEs, reply with "Not found".

    # CVE ID:
    {cve_id}

    # File Names:
    {file_names}

    # Vulnerable Code Blocks:
    {code_blocks}

    # Search Results:
    {search_context}
"""