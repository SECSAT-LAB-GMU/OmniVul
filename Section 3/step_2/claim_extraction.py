import os
import sys
import json
from collections import defaultdict
from openai import OpenAI
import random

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from questions import qa_questions as QA_QUESTIONS
from questions import rag_questions as RAG_QUESTIONS
from questions import coding_attribs
from constants import GPT_KEY
from claim_extraction_prompt import CLAIM_EXTRACTION

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", GPT_KEY))

CVE_TEST = None
# CVE_TEST = "CVE-2017-18509"

folder_id = "init100"

with open(f"{folder_id}_complete_QA_data.json", 'r') as file:
    cves_complete_data = json.load(file)

if CVE_TEST is not None:
    cves_data = {}
    cves_data[CVE_TEST] = cves_complete_data[CVE_TEST]
else:
    cves_data = cves_complete_data

# tuning_cves = [cve.strip() for cve in tuning_cves]
tuning_cves = cves_data.keys()

claims_file_dict = {}

for cve in tuning_cves:
    claims_dict = defaultdict(lambda: defaultdict(list))
    for attribute in RAG_QUESTIONS.keys():
        for key in RAG_QUESTIONS[attribute].keys():
            if attribute == "SCORES" and key != "score_explain":
                continue
            if key in coding_attribs:
                continue
            question = QA_QUESTIONS[attribute][key]
            response = cves_data[cve][attribute][key]['rag']

            print("***********************************")
            print("Question:", question)
            print("Response:", response)

            extraction_prompt = CLAIM_EXTRACTION.format(
                response=response,
                question=question
            )
            claim_extraction_response = client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": extraction_prompt}],
                temperature=0
            )

            claims_json = claim_extraction_response.choices[0].message.content

            try:
                claims = json.loads(claims_json)
            except json.JSONDecodeError:
                print("Failed to parse extracted claims as JSON.")
                claims = []

            print("\n Extracted Claims:\n", claims)
            claims_dict[attribute][key] = claims

    claims_file_dict[cve] = claims_dict

with open(f"{folder_id}_extracted_claims.json", 'w') as f:
    json.dump(claims_file_dict, f, indent=4)
