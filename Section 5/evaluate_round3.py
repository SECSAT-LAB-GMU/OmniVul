import os
import sys
import json
from collections import defaultdict
from openai import OpenAI
import random
from tqdm import tqdm

from questions import rag_questions as RAG_QUESTIONS
from questions import coding_attribs
from claim_extraction_prompt import CLAIM_EXTRACTION
from correctness_prompt import LLM_EVAL

GPT_KEY = "XXX"

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", GPT_KEY))

model_name = "gpt"
with open(f"{model_name}_complete_QA_data.json", 'r') as file:
    cves_data = json.load(file)

tuning_cves = list(cves_data.keys())

os.makedirs(f"{model_name}_scores", exist_ok=True)
os.makedirs(f"{model_name}_evaluate_tokens", exist_ok=True)

evaluated_cves = [cve_file.replace('.json', '') for cve_file in os.listdir(f"{model_name}_scores")]
tuning_cves = [cve for cve in tuning_cves if cve not in evaluated_cves]
print(f"{len(tuning_cves)} CVEs to evaluate.")

for cve in tqdm(tuning_cves):
    eval_dict = defaultdict(lambda: defaultdict(dict))
    token_usage_dict = defaultdict(lambda: defaultdict(dict))
    for attribute in RAG_QUESTIONS.keys():
        for key in RAG_QUESTIONS[attribute].keys():
            question = cves_data[cve][attribute][key]['question']
            response = cves_data[cve][attribute][key]['response']
            reference_answer = cves_data[cve][attribute][key]['rag']

            # Claim extraction
            if key not in coding_attribs:
                extraction_prompt = CLAIM_EXTRACTION.format(
                    response=response,
                    question=question
                )
                claim_extraction_response = client.chat.completions.create(
                    model="gpt-4.1",
                    messages=[{"role": "user", "content": extraction_prompt}],
                    temperature=0,
                    seed=111
                )
                claims_json = claim_extraction_response.choices[0].message.content
                try:
                    claims = json.loads(claims_json)
                except json.JSONDecodeError:
                    print("Failed to parse extracted claims as JSON.")
                    # claims = []
                    claims = [response]
                claim_extraction_usage = getattr(claim_extraction_response, 'usage', None)
            else:
                claims = [response]
                claim_extraction_usage = None

            # LLM evaluation
            llm_eval_prompt = LLM_EVAL.format(
                question=question,
                reference_answer=reference_answer,
                response=response,
                claims=json.dumps(claims, indent=2)
            )
            
            llm_eval_response = client.chat.completions.create(
                model="gpt-4.1",
                messages=[{"role": "user", "content": llm_eval_prompt}],
                temperature=0,
                seed=111
            )
            llm_eval_scores = llm_eval_response.choices[0].message.content
            try:
                llm_eval_dict = json.loads(llm_eval_scores)
            except json.JSONDecodeError:
                print("Failed to parse LLM evaluation output.")
                llm_eval_dict = {}
            llm_eval_usage = getattr(llm_eval_response, 'usage', None)

            # Save evaluation result
            evaluation_result = {
                "question": question,
                "response": response,
                "correctness": llm_eval_dict.get("correctness", {}),            }
            eval_dict[attribute][key] = evaluation_result

            # Save token usage
            token_usage_dict[attribute][key] = {
                "claim_extraction": {
                    k: getattr(claim_extraction_usage, k, None) if claim_extraction_usage else None
                    for k in ["completion_tokens", "total_tokens", "prompt_tokens"]
                },
                "llm_eval": {
                    k: getattr(llm_eval_usage, k, None) if llm_eval_usage else None
                    for k in ["completion_tokens", "total_tokens", "prompt_tokens"]
                }
            }

    # Write evaluation results
    with open(f"{model_name}_scores/{cve}.json", 'w') as f:
        json.dump(eval_dict, f, indent=2)

    # Write token usage summary
    with open(f"{model_name}_evaluate_tokens/{cve}.json", 'w') as f:
        json.dump(token_usage_dict, f, indent=2)
