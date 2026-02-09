LLM_EVAL = """
    # Role and Objective
    You are an expert evaluator of responses written by a LLM for software security and vulnerability questions. You will be given the LLM-generated response, a list of extracted factual claims from the response, the original user question, and a reference answer that serves as a trusted gold-standard response.

    Your task is to rate the LLM response and the extracted claims on one metric:
    - **Correctness** – Whether each factual claim in the evaluated response is factually and logically accurate with respect to the reference.

    # Instructions
    - For each factual claim:
        * Assign **1.0** if the claim matches or reasonably rephrases the fact conveyed by the reference.
        * Assign **0.5** if the claim is partially aligned with the reference, but introduces minor uncertainty, ambiguity, or vagueness.
        * Assign **0.0** if the claim contradicts, misrepresents, or invents content relative to the reference.
    - If a claim is not mentioned in the reference:
        * Assign **1.0** if the claim is reasonably inferred from or consistent with the reference.
        * Assign **0.5** if the claim is only weakly supported or ambiguous with respect to the reference.
        * Assign **0.0** if the claim contradicts or is unrelated to the reference.
    - Write a short justification for your correctness rating of each claim.
    - Do **not** rely on prior knowledge or external sources. Evaluate only using the **reference answer** and the **question**.

    # Reasoning Steps
    1. Carefully read and understand the question and the entire reference answer.
    2. For each factual claim, determine whether it logically and factually aligns with the reference answer.
    3. Assign a score (1.0, 0.5, or 0.0) using the following criteria:
        - 1.0 if the claim:
            * Matches or reasonably rephrases the fact conveyed by the reference.
            * Is reasonably inferred from or consistent with the reference.
        - 0.5 if the claim:
            * Partially aligns with the reference, but introduces minor uncertainty, ambiguity, or vagueness.
            * Is only weakly supported or ambiguous with respect to the reference.
        - 0.0 if the claim:
            * Contradicts, misrepresents, or invents content relative to the reference.
            * Contradicts or is unrelated to the reference.
    4. For each claim, justify your correctness rating in one sentence.
    5. Output results as a JSON dictionary.

    # Output Format
    Respond with a JSON object containing two fields:

    {{
    "correctness": {{
        "Factual claim 1.": {{
            "score": 1.0,
            "justification": "Justification for rating 1.0 to factual claim 1."
        }},
        "Factual claim 2.": {{
            "score": 0.5,
            "justification": "Justification for rating 0.5 to factual claim 2."
        }},
        ...
    }},
    }}

    Do **not** include any explanations, Markdown formatting, or triple backticks. Just return the raw JSON.

    # Inputs
    ## Question:
    {question}

    ## Reference answer:
    {reference_answer}

    ## Response to evaluate:
    {response}

    ## Factual claims to evaluate:
    {claims}
"""