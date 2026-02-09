import os
import sys
import json
from collections import defaultdict
from openai import OpenAI
import random
from tqdm import tqdm

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from questions import qa_questions as QA_QUESTIONS
from questions import rag_questions as RAG_QUESTIONS
from questions import coding_attribs
from claim_extraction_prompt import CLAIM_EXTRACTION
from all_metric_attribute_prompt import TRIPLE_EVAL as TRIPLE_EVAL_ATTRIBUTE
from all_metric_attribute_prompt import CONTEXT_INSTRUCTION

GPT_KEY = "XXX"

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", GPT_KEY))

# Calibration data
# with open("calibration_complete_QA_data.json", 'r') as file:
#     cves_data = json.load(file)
# with open("calibration_context_QA_data.json", 'r') as file:
#     cves_context = json.load(file)

# Test data
with open("final_sota_qa_pairs.json", 'r') as file:
    cves_data = json.load(file)
with open("final_sota_contexts.json", 'r') as file:
    cves_context = json.load(file)

run_cves = list(cves_data.keys())

os.makedirs("rag_results", exist_ok=True)
os.makedirs("rag_evaluate_tokens", exist_ok=True)

evaluated_cves = [cve_file.replace('.json', '') for cve_file in os.listdir("rag_results")]
run_cves = [cve for cve in run_cves if cve not in evaluated_cves]
print(f"{len(run_cves)} CVEs to evaluate.")

for cve in tqdm(run_cves):
    eval_dict = defaultdict(lambda: defaultdict(dict))
    token_usage_dict = defaultdict(lambda: defaultdict(dict))
    for attribute in RAG_QUESTIONS.keys():
        for key in RAG_QUESTIONS[attribute].keys():
            if attribute == "SCORES" and key != "score_explain":
                continue
            question = QA_QUESTIONS[attribute][key]
            context = cves_context[cve][attribute][key]
            response = cves_data[cve][attribute][key]['rag']
            context_instruction = CONTEXT_INSTRUCTION.get(key, "")

            # Claim extraction
            if key not in coding_attribs:
                extraction_prompt = CLAIM_EXTRACTION.format(
                    response=response,
                    question=question
                )
                claim_extraction_response = client.chat.completions.create(
                    model="gpt-4o",
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

            # Triple evaluation
            triple_eval_prompt = TRIPLE_EVAL_ATTRIBUTE.format(
                faithfulness_instruction=context_instruction['faithfulness'],
                correctness_instruction=context_instruction['correctness'],
                completeness_instruction=context_instruction['completeness'],
                context=context,
                question=question,
                response=" ".join(claims),
                claims=json.dumps(claims, indent=2),
            )
            
            triple_eval_response = client.chat.completions.create(
                model="gpt-4.1",
                messages=[{"role": "user", "content": triple_eval_prompt}],
                temperature=0,
                seed=111
            )
            triple_eval_scores = triple_eval_response.choices[0].message.content
            try:
                triple_eval_dict = json.loads(triple_eval_scores)
            except json.JSONDecodeError:
                print("Failed to parse triple evaluation output.")
                triple_eval_dict = {}
            triple_eval_usage = getattr(triple_eval_response, 'usage', None)

            # Save evaluation result
            evaluation_result = {
                "question": question,
                "response": response,
                "faithfulness": triple_eval_dict.get("faithfulness", {}),
                "correctness": triple_eval_dict.get("correctness", {}),
                "completeness": triple_eval_dict.get("completeness", {})
            }
            eval_dict[attribute][key] = evaluation_result

            # Save token usage
            token_usage_dict[attribute][key] = {
                "claim_extraction": {
                    k: getattr(claim_extraction_usage, k, None) if claim_extraction_usage else None
                    for k in ["completion_tokens", "total_tokens", "prompt_tokens"]
                },
                "triple_eval": {
                    k: getattr(triple_eval_usage, k, None) if triple_eval_usage else None
                    for k in ["completion_tokens", "total_tokens", "prompt_tokens"]
                }
            }

    # Write evaluation results
    with open(f"rag_results/{cve}.json", 'w') as f:
        json.dump(eval_dict, f, indent=2)

    # Write token usage summary
    with open(f"rag_evaluate_tokens/{cve}.json", 'w') as f:
        json.dump(token_usage_dict, f, indent=2)