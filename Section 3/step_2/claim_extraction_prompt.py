CLAIM_EXTRACTION = """
    # Role and Objective  
    You are an expert analyst of responses written by a Retrieval-Augmented Generation (RAG) system for questions related to software security and vulnerabilities. You will be given a response from the RAG system and the corresponding question. Your task is to extract **all discrete factual claims** from the response. A factual claim is a statement that can be verified as true or false based on evidence.

    # Instructions
    - Each claim must be a **complete sentence** that stands alone as a **single verifiable fact**.
    - If a sentence contains multiple factual assertions, split it **only if** the assertions differ in structure or involve clearly distinct entities (e.g., different subjects like "the kernel" vs. "the user", or different event types like "affects" vs. "allows").
    - Do **not** split a sentence if its assertions share the same structure and differ only by names, versions, or other simple variations.
    - If the response is a short or incomplete phrase (e.g., "Yes", "No", "Not found"), then **use the question to construct a complete factual claim** that reflects the meaning of the response.
    - If the response explicitly says **"Not found"**, interpret it as stating that the **relevant information is absent** in the context, i.e., **not** as a negative answer. Construct a claim such as: **"The [specific aspect from the question] is not mentioned."**
    - **Do not use pronouns** (e.g., "it", "they", "this"). Replace them with appropriate specific nouns for clarity.
    - **Preserve the original order of claims** as they appear in the response. If a sentence is split into multiple claims, those claims must appear **in the same order** as in the original sentence.
    - If there are multiple claims that express the same factual content, even if worded slightly differently, **only retain the longest or most detailed version** of that claim.
    - If multiple claims have the same sentence structure and only differ by enumerated elements such as entity names, version numbers, port numbers, or product variants where the base entity and relation are the same (e.g., ‘is affected by this CVE’), and the differing part is a modifier (e.g., version, edition, update support type), merge them into a single enumerated claim.
    - Do not include any opinions, interpretations, or speculative statements.
    - Output the claims as a valid **JSON-formatted list of strings**
    - Do **not** include any explanations, Markdown formatting, or triple backticks. Just return the raw JSON.

    # Reasoning steps
    1. Read the entire response carefully.
    2. Identify all sentences that contain verifiable information.
    3. Break down multi-fact sentences into smaller factual claims as needed.
    4. When handling multi-fact sentences, split only if the facts differ structurally or involve different subjects or types of events. Avoid splitting factual claims that differ only by enumerated values, such as version numbers, unless each value corresponds to a different logical assertion. Keep grouped lists of entities (e.g., versions, ports) together in a single claim when they share the same subject or predicate.
    5. If the response is short or fragmentary, reconstruct a complete claim using the question.
        - If the response explicitly says "Not found", interpret them as stating that **the relevant information is absent in the retrieved context**. Construct a claim such as: "The [specific aspect from the question] is not mentioned in the context."
        - Otherwise, construct a claim that reflects the intended meaning of the response.
    6. Rephrase each factual claim into a clear, pronoun-free, factual sentence.
    7. Maintain the order of claims as in the original response.
    8. Remove duplicate claims that express the same factual content, keeping the most informative version.
    9. Merge multiple claims that share the same sentence structure and only differ by enumerated elements such as entity names, version numbers, port numbers, or product variants.
    10. Output the claims as a JSON list.

    # Output format
    [
    "Factual claim 1.",
    "Factual claim 2.",
    ...
    ]

    # Question:
    {question}

    # Response to evaluate:
    {response}
"""