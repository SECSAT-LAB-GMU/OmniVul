TRIPLE_EVAL = """
    # Role and Objective
    You are an expert evaluator of responses written by a Retrieval-Augmented Generation (RAG) system for questions related to software security and vulnerabilities. You will be given the RAG-generated response, a list of extracted factual claims from the response, the original user question, and the retrieved context used to generate the response.

    Your task is to rate the RAG response and the extracted claims on three metrics:
    - **Faithfulness** – Whether each factual claim is supported by the retrieved context.
    - **Correctness** – Whether each factual claim is factually and logically accurate with respect to both the question and the context.
    - **Completeness** – Whether the response sufficiently addresses the user question based only on the retrieved context.

    # Instructions

    ## Faithfulness
    - Question-Specific scoring rules:
        {faithfulness_instruction}
    - Not-Found scoring rules:
        * Assign **1.0** if the retrieved context truly does **not contain** the relevant information.
        * Assign **0.5** if the relevant information is **partially or implicitly present**, but not fully verifiable from the context.
        * Assign **0.0** if the relevant information is **explicitly present** in the context.
    - Default scoring rules:
        * Assign **1.0** if the claim is **explicitly stated** or **reasonably supported** in the context.
        * Assign **0.5** if the claim is **plausible but not fully verifiable** or **weakly supported** by the context.
        * Assign **0.0** if the claim is **not supported** or **not verifiable** from the context.
    - For each factual claim:
        1. First, check whether **Question-Specific rules** apply.  
            * If yes, apply them directly and ignore all other rules.  
        2. If no Question-Specific rule applies, check whether the claim explicitly states **"not found"**, **"not available"**, or **"not mentioned"**.  
            * If yes, apply the **Not-Found rules**.  
        3. If neither case applies, fall back to the **Default rules**.  
        4. Write a short justification for your faithfulness rating, and clearly state which rule set (Question-Specific, Not-Found, or Default) determined the score.
    - Do **not** use external knowledge. Base your judgment only on the **retrieved context**.

    ## Correctness
    - Question-Specific scoring rules:
        {correctness_instruction}
    - Not-Found scoring rules:
        * Assign **1.0** if the retrieved context truly does **not contain** the relevant information.
        * Assign **0.5** if the relevant information is **partially or implicitly present**, but not fully verifiable from the context.
        * Assign **0.0** if the relevant information is **explicitly present** in the context.
    - Default scoring rules:
        * Assign **1.0** if the claim is **factually accurate**, **logically valid**, and **grounded** in the question and the context.
        * Assign **0.5** if the claim is **plausible but not fully verifiable**, **only weakly grounded**, or **ambiguous** with respect to the question and the context.
        * Assign **0.0** if the claim is **factually incorrect**, **logically invalid**, **contradicted**, or **unrelated** to the question or context.
    - For each factual claim:
        1. First, check whether **Question-Specific rules** apply.  
            * If yes, apply them directly and ignore all other rules.  
        2. If no Question-Specific rule applies, check whether the claim explicitly states **"not found"**, **"not available"**, or **"not mentioned"**.  
            * If yes, apply the **Not-Found rules**.  
        3. If neither case applies, fall back to the **Default rules**.  
        4. Write a short justification for your correctness rating, and clearly state which rule set (Question-Specific, Not-Found, or Default) determined the score.
    - Do **not** rely on prior knowledge or external sources. Evaluate only using the **retrieved context** and the **question**.

    ## Completeness
    - Question-Specific scoring rules:
        {completeness_instruction}
    - Not-Found scoring rules:
        * Assign **5** if the retrieved context truly does **not contain** the answer to the question.
        * Assign **3** if the answer to the question is **partially or implicitly present** in the context.
        * Assign **2** if the answer to the question is **explicitly present** in the context.
    - Default scoring rules:
        * Assign **5** if the response **fully addresses** the question with relevant evidence from the context.
        * Assign **4** if the response **substantially addresses** the question with minor omissions or slight lack of detail, but remains well-grounded in the context.
        * Assign **3** if the response **partially addresses** the question but lacks comprehensiveness, clarity, or sufficient evidence from the context (significant gaps remain).
        * Assign **2** if the response **minimally addresses** the question (tangential or fragmentary), with weak grounding in the context.
        * Assign **1** if the response **does not address** the question or is **irrelevant**.
    - For the response:
        1. First, check whether **Question-Specific rules** apply.
            * If yes, apply them directly and ignore all other rules.
        2. If no Question-Specific rule applies, check whether the claim explicitly states **"not found"**, **"not available"**, or **"not mentioned"**.
            * If yes, apply the **Not-Found rules**.
        3. If neither case applies, fall back to the **Default rules**.
        4. Write a short justification for your completeness rating, and clearly state which rule set (Question-Specific, Not-Found, or Default) determined the score.
    - Do **not** rely on prior knowledge or external sources. Evaluate only using the **retrieved context** and the **question**.

    # Reasoning Steps
    ## Faithfulness
    1. Carefully read and understand the entire retrieved context.
    2. For each claim, apply rules in order of precedence:
        - **Question-Specific**: If a question-specific rule applies, assign its score directly.
        - **Not-Found**: If the claim states "not found/available/mentioned", apply the Not-Found rules (1.0 absent, 0.5 partial, 0.0 present).
        - **Default**: Otherwise, apply the default rules (1.0 explicit/supported, 0.5 partial/weak, 0.0 unsupported/contradicted).
    3. For each claim, state which rule set was applied and justify your faithfulness rating in one sentence.
    4. Output results as a JSON dictionary.

    ## Correctness
    1. Carefully read and understand the question and the entire retrieved context.
    2. For each claim, apply rules in order of precedence:
        - **Question-Specific**: If a question-specific rule applies, assign its score directly.  
        - **Not-Found**: If the claim states "not found/available/mentioned", apply the Not-Found rules (1.0 absent, 0.5 partial, 0.0 present).  
        - **Default**: Otherwise, apply the default rules (1.0 accurate/valid/grounded, 0.5 plausible/weak/ambiguous, 0.0 incorrect/invalid/unrelated).
    3. For each claim, state which rule set was applied and justify your correctness rating in one sentence.
    4. Output results as a JSON dictionary.

    ## Completeness
    1. Carefully read and understand the question and the entire retrieved context.
    2. For the response, apply rules in order of precedence:
        - **Question-Specific**: If a question-specific rule applies, assign its score directly.
        - **Not-Found**: If the claim states "not found/available/mentioned", apply the Not-Found rules (1.0 absent, 0.5 partial, 0.0 present).
        - **Default**: Otherwise, apply the default rules (5 fully-addressed, 4 substantially-addressed, 3 partially-addressed, 2 minimally-addressed, 1 irrelevant).
    3. For the response, state which rule set was applied and justify your completeness rating in one sentence.
    4. Output results as a JSON dictionary.

    # Output Format
    Respond with a JSON object containing three fields:

    {{
    "faithfulness": {{
        "Factual claim 1.": {{
            "score": 1.0,
            "justification": "Question-Specific: Justification for rating 1.0 to factual claim 1."
        }},
        "Factual claim 2.": {{
            "score": 0.5,
            "justification": "Default: Justification for rating 0.5 to factual claim 2."
        }},
        ...
    }},
    "correctness": {{
        "Factual claim 1.": {{
            "score": 1.0,
            "justification": "Question-Specific: Justification for rating 1.0 to factual claim 1."
        }},
        "Factual claim 2.": {{
            "score": 0.5,
            "justification": "Default: Justification for rating 0.5 to factual claim 2."
        }},
        ...
    }},
    "completeness": {{
        "score": 5,
        "justification": "Question-Specific: Justification for rating 5 to the response."
    }}
    }}

    Do **not** include any explanations, Markdown formatting, or triple backticks. Just return the raw JSON.

    # Inputs
    ## Retrieved context:
    {context}

    ## Question:
    {question}

    ## Response to evaluate:
    {response}

    ## Factual claims to evaluate:
    {claims}
"""

CONTEXT_INSTRUCTION = {
    "Function name": {
        "faithfulness": """
        - Assign **1.0** if the claim provides a function name that satisfies the following criteria:
            * The function name is described in the context as being vulnerable or involved in the vulnerability.
            * The function name is written exactly as it appears in the context text, including punctuation or formatting.
        """,
        "correctness": """
        - Assign **1.0** if the claim provides a function name that satisfies the following criteria:
            * The function name is described in the context as being vulnerable or involved in the vulnerability.
            * The function name is written exactly as it appears in the context text, including punctuation or formatting.
        """,
        "completeness": """
        - Assign **5** if the response provides at least one function name that is described in the context as being vulnerable or involved in the vulnerability.
        """
    },

    "File name" : {
        "faithfulness": "None.",
        "correctness": "None.",
        "completeness": "None."
    },

    "Vulnerable OS component": {
        "faithfulness": "None.",
        "correctness": "None.",
        "completeness": "None."
    },

    "Weakness Type": {
        "faithfulness": """
        - Assign **1.0** if the claim provides a vulnerability or weakness type satisfying the following criteria:
            * The vulnerability type is explicitly named or categorized by its technical nature (e.g., buffer overflow, integer truncation, TOCTOU race) in the context.
            * The vulnerability type is matched with the terminology used in common CVE/CWE categories.
        - Assign **1.0** to the claim "Not found" if the vulnerability or weakness type found in the context does not satisfy the above criteria.
        - Assign **1.0** to the claim "Not found" if the context only mentions broad the vulnerability or weakness type (e.g., denial of service, information disclosure, privilege escalation, remote code execution, data/memory leak).
        - Assign **1.0** to the claim "Not found" if the context lists multiple possible vulnerability or weakness types rather than one concrete type.
        """,
        "correctness": """
        - Assign **1.0** if the claim provides a vulnerability or weakness type satisfying the following criteria:
            * The vulnerability type is explicitly named or categorized by its technical nature (e.g., buffer overflow, integer truncation, TOCTOU race) in the context.
            * The vulnerability type is matched with the terminology used in common CVE/CWE categories.
        - Assign **1.0** to the claim "Not found" if the vulnerability or weakness type found in the context does not satisfy the above criteria.
        - Assign **1.0** to the claim "Not found" if the context only mentions broad the vulnerability or weakness type (e.g., denial of service, information disclosure, privilege escalation, remote code execution, data/memory leak).
        - Assign **1.0** to the claim "Not found" if the context lists multiple possible vulnerability or weakness types rather than one concrete type.
        """,
        "completeness": """
        - Assign **5** if the response provides a vulnerability or weakness type satisfying the following criteria:
            * The vulnerability type is explicitly named or categorized by its technical nature (e.g., buffer overflow, integer truncation, TOCTOU race) in the context.
            * The vulnerability type is matched with the terminology used in common CVE/CWE categories.
        - Assign **5** to the response "Not found" if the vulnerability or weakness type found in the context does not satisfy the above criteria.
        - Assign **5** to the response "Not found" if the context only mentions broad the vulnerability or weakness type (e.g., denial of service, information disclosure, privilege escalation, remote code execution, data/memory leak).
        - Assign **5** to the response "Not found" if the context lists multiple possible vulnerability or weakness types rather than one concrete type.
        """
    },

    "root_cause": {
        "faithfulness": "None.",
        "correctness": "None.",
        "completeness": "None."
    },

    "secure_coding_violation": {
        "faithfulness": """
        - Assign **1.0** if the discusses secure coding practices that satisfy the following criteria:
            * The claim mentions of programming practices that are unsafe or violating best practices, but **not necessarily stated as the cause of the vulnerability**.
        """,
        "correctness": """
        - Assign **1.0** if the discusses secure coding practices that satisfy the following criteria:
            * The claim mentions of programming practices that are unsafe or violating best practices, but **not necessarily stated as the cause of the vulnerability**.
        """,
        "completeness": """
        - Assign **5** if the response discusses secure coding practices and accurately identifies the specific secure coding violation in the context.
        - Assign **4** if the response discusses secure coding practices, but does not accurately identify the specific secure coding violation in the context.
        """
    },

    "mitigation": {
        "faithfulness": """
        - Assign **1.0** if the claim provides a mitigation strategy that satisfies the following criteria:
            * The mitigation strategy involves a sequence of actions described to apply the mitigation in the context.
            * The mitigation strategy refers to technical details such as configuration changes, access controls, or other preventive measures.
        - Assign **1.0** to the claim "Not found" if the mitigation strategy found in the context does not satisfy the above criteria.
        - Assign **1.0** to the claim "Not found" if the context only mentions applying a patch, references to patches, or code changes without describing any mitigation strategy.
        """,
        "correctness": """
        - Assign **1.0** if the claim provides a mitigation strategy that satisfies the following criteria:
            * The mitigation strategy involves a sequence of actions described to apply the mitigation in the context.
            * The mitigation strategy refers to technical details such as configuration changes, access controls, or other preventive measures.
        - Assign **1.0** to the claim "Not found" if the mitigation strategy found in the context does not satisfy the above criteria.
        - Assign **1.0** to the claim "Not found" if the context only mentions applying a patch, references to patches, or code changes without describing any mitigation strategy.
        """,
        "completeness": """
        - Assign **5** if the claim provides a mitigation strategy that satisfies the following criteria:
            * The mitigation strategy involves a sequence of actions described to apply the mitigation in the context.
            * The mitigation strategy refers to technical details such as configuration changes, access controls, or other preventive measures.
        - Assign **5** to the claim "Not found" if the mitigation strategy found in the context does not satisfy the above criteria.
        - Assign **5** to the claim "Not found" if the context only mentions applying a patch, references to patches, or code changes without describing any mitigation strategy.
        """
    },

    "Exploit Code": {
        "faithfulness": """
        - Assign **1.0** if the claim provides the exploit of PoC code satisfying the following criteria:
            * The code block is specifically intended as an exploit or Proof of Concept (PoC) in the context.
            * The code block is used to demonstrate or reproduce the vulnerability described in the context, not the vulnerable code itself.
            * The code block exactly as written, preserving its formatting, indentation, and syntax in the context.
            * The code block is directly presented in the context without referencing any external sources (e.g., links, citations).
        - Assign **0.0** if the claim provides the exploit of PoC code that does not satisfy the above criteria.
        - Assign **1.0** to the claim "Not found" if the exploit of PoC code found in the context does not satisfy the above criteria.
        """,
        "correctness": """
        - Assign **1.0** if the claim provides the exploit of PoC code satisfying the following criteria:
            * The code block is specifically intended as an exploit or Proof of Concept (PoC) in the context.
            * The code block is used to demonstrate or reproduce the vulnerability described in the context, not the vulnerable code itself.
            * The code block exactly as written, preserving its formatting, indentation, and syntax in the context.
            * The code block is directly presented in the context without referencing any external sources (e.g., links, citations).
        - Assign **0.0** if the claim provides the exploit of PoC code that does not satisfy the above criteria.
        - Assign **1.0** to the claim "Not found" if the exploit of PoC code found in the context does not satisfy the above criteria.
        """,
        "completeness": """
        - Assign **5** if the response provides the exploit of PoC code satisfying the following criteria:
            * The code block is specifically intended as an exploit or Proof of Concept (PoC) in the context.
            * The code block is used to demonstrate or reproduce the vulnerability described in the context, not the vulnerable code itself.
            * The code block is directly presented in the context without referencing any external sources (e.g., links, citations).
            * The code block is incomplete, but only part of the code is available from the context.
        - Assign **1** if the response provides the exploit of PoC code satisfying the following criteria:
        - Assign **5** to the response "Not found" if the exploit of PoC code found in the context does not satisfy the above criteria.
        """
    },

    "remote_exploitability": {
        "faithfulness": "None.",
        "correctness": "None.",
        "completeness": "None."
    },

    "cia_impact": {
        "faithfulness": "None.",
        "correctness": "None.",
        "completeness": "None."
    },

    "exploit_expl": {
        "faithfulness": """
        - Assign **1.0** if the claim provides an exploit explanation that satisfies the following criteria:
            * The explanation mentions one or more of the following from the context:
                - The method used to trigger the flaw (sequence of actions).
                - The attacker’s required privileges or preconditions.
                - Any PoC code, scripts, tools, or commands that are explicitly shown.
                - The result of successful exploitation (e.g., crash, privilege escalation).
        - Assign **1.0** to the claim "Not found" if the context only mentions high-level explanations and no detailed description of exploitation methods.
        """,
        "correctness": """
        - Assign **1.0** if the claim provides an exploit explanation that satisfies the following criteria:
            * The explanation mentions one or more of the following from the context:
                - The method used to trigger the flaw (sequence of actions).
                - The attacker’s required privileges or preconditions.
                - Any PoC code, scripts, tools, or commands that are explicitly shown.
                - The result of successful exploitation (e.g., crash, privilege escalation).
        - Assign **1.0** to the claim "Not found" if the context only mentions high-level explanations and no detailed description of exploitation methods.
        """,
        "completeness": """
        - Assign **5** if the response provides an exploit explanation that satisfies the following criteria:
            * The explanation mentions one or more of the following from the context:
                - The method used to trigger the flaw (sequence of actions).
                - The attacker’s required privileges or preconditions.
                - Any PoC code, scripts, tools, or commands that are explicitly shown.
                - The result of successful exploitation (e.g., crash, privilege escalation).
        - Assign **5** to the response "Not found" if the context only mentions high-level explanations and no detailed description of exploitation methods.
        """
    },

    "privs_req" : {
        "faithfulness": """
        - Assign **1.0** if the claim lists specific privileges satisfying the following criteria:
            * These privileges are used to exploit the CVE even though not explicitly stated as required in the context.
        - Assign **1.0** if the claim states that no privilege is required to exploit the CVE when the context implies that none are used (e.g., "\"privs_req\": null")
        """,
        "correctness": """
        - Assign **1.0** if the claim lists specific privileges:
            * These privileges are used to exploit the CVE even though not explicitly stated as required in the context.
        - Assign **1.0** if the claim states that no privilege is required to exploit the CVE when the context implies that none are used (e.g., "\"privs_req\": null")
        """,
        "completeness": """
        - Assign **5** if the response lists all privileges used to exploit the CVE in the context, even though these privileges are not explicitly stated as required.
        - Assign **5** if the response states that no privilege is required to exploit the CVE when the context implies that none are used (e.g., "\"privs_req\": null")
        - Assign **4** if the response lists some, but not all, privileges used to exploit the CVE in the context, even though these privileges are not explicitly stated as required.
        """
    },

    "exploited_versions": {
        "faithfulness": """
        - Assign **1.0** if the claim lists specific kernel or OS distribution versions satisfying the following criteria:
            * These versions are present in the context, but **not necessarily stated to be affected by the CVE**.
            * These versions are not explicitly stated to be **not affected** by the CVE.
        - Assign **0.0** if the claim lists specific kernel or OS distribution versions that do not meet the above criteria.
        """,
        "correctness": """
        - Assign **1.0** if the claim lists specific kernel or OS distribution versions satisfying the following criteria:
            * These versions are present in the context, but **not necessarily stated to be affected by the CVE**.
            * These versions are not explicitly stated to be **not affected** by the CVE.
        - Assign **0.0** if the claim lists specific kernel or OS distribution versions that do not meet the above criteria.
        """,
        "completeness": """
        - Assign **5** if the response states lists specific kernel or OS distribution versions, when these versions are present in the context even though not explicitly stated to be affected.
        - Assign **4** if the response states lists specific kernel or OS distribution versions, when the context explicitly states that some of these versions are not affected.
        - Assign **3** if the response states lists specific kernel or OS distribution versions, when the context explicitly states that at least half of these versions are not affected.
        """,
    },

    "abusable_interfaces": {
        "faithfulness": """
        - Assign **1.0** if the claim provides relevant kernel components, device drivers, interfaces, system calls, or APIs in the context.
        - Assign **1.0** to the claim "Not found" if the relevant kernel components, device drivers, or interfaces are not explicitly named in the context.
        """,
        "correctness": """
        - Assign **1.0** if the claim provides relevant kernel components, device drivers, interfaces, system calls, or APIs in the context.
        - Assign **1.0** to the claim "Not found" if the relevant kernel components, device drivers, or interfaces are not explicitly named in the context.
        """,
        "completeness": """
        - Assign **5** if the response provides one or more relevant kernel components, device drivers, interfaces, system calls, or APIs in the context.
        - Assign **5** to the response "Not found" if the relevant kernel components, device drivers, or interfaces are not explicitly named in the context.
        """
    },

    "exploit_privs": {
        "faithfulness": """
        - Assign **1.0** if the claim lists specific privileges:
            * These privileges are explicitly named and stated to be gained from exploiting the CVE in the context.
        - Assign **1.0** to the claim "Not found" if the privileges that can be gained from exploiting the CVE are not explicitly named in the context.
        """,
        "correctness": """
        - Assign **1.0** if the claim lists specific privileges:
            * These privileges are explicitly named and stated to be gained from exploiting the CVE in the context.
        - Assign **1.0** to the claim "Not found" if the privileges that can be gained from exploiting the CVE are not explicitly named in the context.
        """,
        "completeness": """
        - Assign **5** to the response "Not found" if the privileges that can be gained from exploiting the CVE are not explicitly named in the context.
        """
    },

    "exploit_steps": {
        "faithfulness": "None.",
        "correctness": "None.",
        "completeness": "None."
    },

    "crash_dump": {
        "faithfulness": "None.",
        "correctness": "None.",
        "completeness": "None."
    },

    "patch_date": {
        "faithfulness": "None.",
        "correctness": "None.",
        "completeness": "None."
    },

    "patch_expl": {
        "faithfulness": """
        - Assign **1.0** if the claim provides a patch description that satisfies the following criteria:
            * It clearly states one or more of the following if available:
                - What code or configuration change was made to fix the issue.
                - Why the change was necessary (what it prevents or corrects).
                - Which files, functions, or components were modified.
                - How the change resolves the vulnerability or bug.
                - Git commit IDs, kernel versions, patch URLs, or advisory references where the fix was applied.
            * If only metadata (commit IDs, kernel versions, patch URLs, advisory numbers) is present without code-level details, the patch description is limited to those metadata elements.
        - Assign **0.0** if the claim provides a patch description that does not satisfy the above criteria.
        - Assign **1.0** to the claim "Not found" if no patch description or metadata is present in the context.
        - Assign **1.0** to the claim "Not found" if the context only mentions references to patches or code changes without describing any patch details.
        """,
        "correctness": """
        - Assign **1.0** if the claim provides a patch description that satisfies the following criteria:
            * It clearly states one or more of the following if available:
                - What code or configuration change was made to fix the issue.
                - Why the change was necessary (what it prevents or corrects).
                - Which files, functions, or components were modified.
                - How the change resolves the vulnerability or bug.
                - Git commit IDs, kernel versions, patch URLs, or advisory references where the fix was applied.
            * If only metadata (commit IDs, kernel versions, patch URLs, advisory numbers) is present without code-level details, the patch description is limited to those metadata elements.
        - Assign **0.0** if the claim provides a patch description that does not satisfy the above criteria.
        - Assign **1.0** to the claim "Not found" if no patch description or metadata is present in the context.
        - Assign **1.0** to the claim "Not found" if the context only mentions references to patches or code changes without describing any patch details.
        """,
        "completeness": """
        - Assign **5** if the response provides a patch description that satisfies the following criteria:
            * It clearly states one or more of the following if available:
                - What code or configuration change was made to fix the issue.
                - Why the change was necessary (what it prevents or corrects).
                - Which files, functions, or components were modified.
                - How the change resolves the vulnerability or bug.
                - Git commit IDs, kernel versions, patch URLs, or advisory references where the fix was applied.
            * If only metadata (commit IDs, kernel versions, patch URLs, advisory numbers) is present without code-level details, the patch description is limited to those metadata elements.
        - Assign **5** to the response "Not found" if the patch description does not satisfy the above criteria.
        - Assign **5** to the response "Not found" if no patch description or metadata is present in the context.
        - Assign **5** to the response "Not found" if the context only mentions references to patches or code changes without describing any patch details.
        """
    },

    "patched_versions": {
        "faithfulness": """
        - Assign **1.0** if the claim lists versions satisfying the following criteria:
            * The versions are explicitly named in the context as being fixed or patched against the vulnerability.
        - Assign **1.0** to the claim "Not found" if the versions that have the patch are not explicitly named in the context.
        """,
        "correctness": """
        - Assign **1.0** if the claim lists versions satisfying the following criteria:
            * The versions are explicitly named in the context as being fixed or patched against the vulnerability.
        - Assign **1.0** to the claim "Not found" if the versions that have the patch are not explicitly named in the context.
        """,
        "completeness": """
        - Assign **5** if the response provides versions that have the patch, but omits other versions mentioned in the context that may not have the patch.
        """
    },

    "Code diff": {
        "faithfulness": """
        - Assign **1.0** if the claim provides the code changes satisfying the following criteria:
            * The code changes are located with `diff --git` or `---` / `+++` headers in the context.
            * The code changes are copied from the context, including all `+`, `-`, and `@@` lines.
            * The code changes preserve indentation, structure, and syntax from the context.
        - Assign "1.0" to the claim "Not found" if the code changes found in the context do not satisfy the above criteria.
        """,
        "correctness": """
        - Assign **1.0** if the claim provides the code changes satisfying the following criteria:
            * The code changes are located with `diff --git` or `---` / `+++` headers in the context.
            * The code changes are copied from the context, including all `+`, `-`, and `@@` lines.
            * The code changes preserve indentation, structure, and syntax from the context.
        - Assign "1.0" to the claim "Not found" if the code changes found in the context do not satisfy the above criteria.
        """,
        "completeness": """
        - Assign **5** if the response provides the code changes satisfying the following criteria:
            * The code section is located with `diff --git` or `---` / `+++` headers in the context.
            * The code section is copied from the context, including all `+`, `-`, and `@@` lines.
            * The code section preserves indentation, structure, and syntax from the context.
            * The code section is incomplete, but only part of the code is available from the context.
        - Assign **5** to the response "Not found" if the code section found in the context does not satisfy the above criteria.
        """
    },

    "Patch code": {
        "faithfulness": """
        - Assign **1.0** if the claim provides the patch code satisfying the following criteria:
            * The patch code is located with only the `+` lines in a unified diff or shown outside a diff (e.g., standalone fixed function) in the context.
            * The patch code lists files, functions, or components that were modified.
            * The patch code preserves indentation, structure, and syntax from the context.
        - Assign **0.0** if the claim provides the patch code that does not satisfy the above criteria.
        - Assign **1.0** to the claim "Not found" if the patch code found in the context does not satisfy the above criteria.
        """,
        "correctness": """
        - Assign **1.0** if the claim provides the patch code satisfying the following criteria:
            * The patch code is located with only the `+` lines in a unified diff or shown outside a diff (e.g., standalone fixed function) in the context.
            * The patch code preserves indentation, structure, and syntax from the context.
        - Assign **0.0** if the claim provides the patch code that does not satisfy the above criteria.
        - Assign **0.0** if the claim provides patch code that is generic code unrelated to the vulnerability (e.g., formatting changes, `+` lines that do not reflect meaningful code changes such as `+ [CODE_DIFF]`).
        - Assign **1.0** to the claim "Not found" if the patch code found in the context does not satisfy the above criteria.
        """,
        "completeness": """
        - Assign **5** if the response provides the patch code satisfying the following criteria:
            * The patch code is located with only the `+` lines in a unified diff or shown outside a diff (e.g., standalone fixed function, fixed file) in the context.
            * The patch code preserves indentation, structure, and syntax from the context.
            * The patch code is incomplete, but only part of the code is available from the context.
        - Assign **1** if the response provides the patch code that does not satisfy the above criteria.
        - Assign **1** if the response provides patch code that is generic code unrelated to the vulnerability (e.g., formatting changes, `+` lines that do not reflect meaningful code changes).
        - Assign **5** to the response "Not found" if the patch code found in the context does not satisfy the above criteria.
        """
    },

    "score_explain": {
        "faithfulness": "",
        "correctness": "",
        "completeness": ""
    }
}