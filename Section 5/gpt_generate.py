import os, sys, json
from itertools import islice
from collections import defaultdict
from openai import OpenAI
from prompts import TEMPLATE_R1, TEMPLATE_R2, TEMPLATE_R3, TEMPLATE_R2_SEARCH
from questions import qa_questions as QA_QUESTIONS, rag_questions as RAG_QUESTIONS
from tqdm import tqdm

GPT_KEY = ''

if GPT_KEY == '':
    print("GPT KEY required")

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", GPT_KEY))

def load_json(filename, default=None):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def _get(d, *path, default=None):
    cur = d
    for p in path:
        if cur is None:
            return default
        cur = getattr(cur, p, cur.get(p) if isinstance(cur, dict) else None)
    return cur if cur is not None else default

def get_usage(usage):
    prompt_tokens = _get(usage, "prompt_tokens", default=0)
    completion_tokens = _get(usage, "completion_tokens", default=0)
    total_tokens = _get(usage, "total_tokens", default=prompt_tokens + completion_tokens)
    cached_tokens = _get(usage, "prompt_tokens_details", "cached_tokens", default=0)
    uncached_prompt_tokens = (prompt_tokens or 0) - (cached_tokens or 0)
    cache_hit_rate = (cached_tokens / prompt_tokens) if prompt_tokens else 0.0
    return {
        "eval": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "prompt_tokens_details": {
                "cached_tokens": cached_tokens,
                "uncached_prompt_tokens": uncached_prompt_tokens,
                "cache_hit_rate": round(cache_hit_rate, 4),
            },
        }
    }

def get_response(prompt, model="gpt-4o", temperature=0, seed=111):
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature, 
        seed=seed
    )
    answer = resp.choices[0].message.content
    usage = getattr(resp, "usage", None)
    return answer, usage

def run_round1(cves_data, cves_evaluation):
    out_dir = "gpt_results_round1"
    token_dir = "gpt_evaluate_tokens"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(token_dir, exist_ok=True)

    run_cves = list(cves_evaluation.keys())
    evaluated_cves = [f.replace('.json','') for f in os.listdir(out_dir)]
    print(f"Already evaluated CVEs: {len(evaluated_cves)}")
    run_cves = [cve for cve in run_cves if cve not in evaluated_cves]

    for cve in tqdm(run_cves, desc="Identifying vulnerable CVEs"):
        code_blocks = _get(cves_data, cve, "CVE_intrinsic_attributes","Vulnerable Location","Vulnerable code block", default=[])
        eval_prompt = TEMPLATE_R1.format(code_blocks=json.dumps(code_blocks, indent=2))
        answer, usage = get_response(eval_prompt)

        try:
            if isinstance(answer, str):
                eval_dict = json.loads(answer)
            elif isinstance(answer, dict):
                eval_dict = answer
        except:
            print(f"Error parsing JSON for {cve}")
            eval_dict = {}

        token_usage_dict = get_usage(usage)

        save_json(f"{out_dir}/{cve}.json", eval_dict)
        save_json(f"{token_dir}/{cve}.json", token_usage_dict)

def run_round2(cves_data, cves_evaluation, web_search=False):
    out_dir = "gpt_results_round2"
    token_dir = "gpt_evaluate_tokens"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(token_dir, exist_ok=True)
    search_dict = load_json("cve_id_search_results.json", default={})

    run_cves = list(cves_evaluation.keys())
    evaluated_cves = [f.replace('.json','') for f in os.listdir(out_dir)]
    print(f"Already evaluated CVEs: {len(evaluated_cves)}")
    run_cves = [cve for cve in run_cves if cve not in evaluated_cves]

    for cve in tqdm(run_cves, desc="Retrieving CVE IDs"):
        code_blocks = cves_data[cve]["CVE_intrinsic_attributes"]["Vulnerable Location"]["Vulnerable code block"]
        file_names = cves_data[cve]["CVE_intrinsic_attributes"]["Vulnerable Location"]["File name"]

        if web_search:
            if cve not in search_dict:
                search_prompt = TEMPLATE_R2_SEARCH.format(
                    file_names=json.dumps(file_names, indent=2),
                    code_blocks=json.dumps(code_blocks, indent=2),
                )
                search_answer, _ = get_response(search_prompt, model="gpt-4o", temperature=0, seed=111)
                try:
                    queries = json.loads(search_answer)
                except:
                    print(f"Error parsing JSON for {cve}")
                    queries = []

                search_results = []
                for query in queries:
                    resp = client.responses.create(model="gpt-4o",
                                                   tools=[{"type": "web_search", "search_context_size": "low"}],
                                                   input=query,
                                                   temperature=0,
                                                   max_output_tokens=1024)
                    
                    search_results.append(resp.output_text)

                search_context = "\n".join(search_results)
            else:
                search_context = search_dict[cve]

        eval_prompt = TEMPLATE_R2.format(
            file_names=json.dumps(file_names, indent=2),
            code_blocks=json.dumps(code_blocks, indent=2),
            search_context=search_context
        )

        answer, usage = get_response(eval_prompt, model="gpt-4o", temperature=0, seed=111)
        
        try:
            if isinstance(answer, str):
                eval_dict = json.loads(answer)
            elif isinstance(answer, dict):
                eval_dict = answer
        except:
            print(f"Error parsing JSON for {cve}")
            eval_dict = {}
            
        token_usage_dict = get_usage(usage)
        search_dict[cve] = search_context

        save_json(f"{out_dir}/{cve}.json", eval_dict)
        save_json(f"{token_dir}/{cve}.json", token_usage_dict)
        save_json("cve_id_search_results.json", search_dict)

def run_round3(cves_data, cves_evaluation, web_search=False):
    out_dir = "gpt_results_round3"
    token_dir = "gpt_evaluate_tokens"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(token_dir, exist_ok=True)
    search_dict = load_json("cve_id_search_results.json", default={})

    run_cves = list(cves_evaluation.keys())
    evaluated_cves = [f.replace('.json','') for f in os.listdir(out_dir)]
    print(f"Already evaluated CVEs: {len(evaluated_cves)}")
    run_cves = [cve for cve in run_cves if cve not in evaluated_cves]

    for cve in tqdm(run_cves, desc="Generating QA answers"):
        eval_dict = defaultdict(lambda: defaultdict(dict))
        token_usage_dict = defaultdict(lambda: defaultdict(dict))
        code_blocks = cves_data[cve]["CVE_intrinsic_attributes"]["Vulnerable Location"]["Vulnerable code block"]
        file_names = cves_data[cve]["CVE_intrinsic_attributes"]["Vulnerable Location"]["File name"]

        if web_search:
            if cve in search_dict:
                search_context = search_dict[cve]
            else:
                search_context = "None."

        for attribute in RAG_QUESTIONS.keys():
            for key in RAG_QUESTIONS[attribute].keys():
                question = QA_QUESTIONS[attribute][key]
                if attribute == "SCORES" and key != "score_explain":
                    rag_answer = cves_evaluation[cve][attribute][key]['portfolio']
                else:
                    rag_answer = cves_evaluation[cve][attribute][key]['rag']
                eval_prompt = TEMPLATE_R3.format(
                    cve_id=cve,
                    code_blocks=json.dumps(code_blocks, indent=2),
                    file_names=json.dumps(file_names, indent=2),
                    search_context=search_context,
                    question=question,
                )

                eval_answer, usage = get_response(eval_prompt, model="gpt-4o", temperature=0, seed=111)
                
                eval_dict[attribute][key] = {
                    "question": question,
                    "response": eval_answer,
                    "rag": rag_answer,
                }
                token_usage_dict[attribute][key] = get_usage(usage)

        save_json(f"{out_dir}/{cve}.json", eval_dict)
        save_json(f"{token_dir}/{cve}.json", token_usage_dict)

if __name__ == "__main__":
    with open("portfolio_cves.json") as f: 
        cves_data = json.load(f)
    with open("extracted_patched_cves.json") as f: 
        cves_data = {**cves_data, **json.load(f)}

    with open("final_sota_qa_pairs.json") as f: 
        cves_evaluation = json.load(f)

    # vulnerability detection
    run_round1(cves_data, cves_evaluation)
    patch_evaluation = {f"P{cve}": data for cve, data in cves_evaluation.items() if f"P{cve}" in cves_data}
    run_round1(cves_data, patch_evaluation)
    
    # cve identification
    run_round2(cves_data, cves_evaluation, web_search=True)

    # QA generation
    identified_cves = open('gpt_top1_correct_cves.txt').read().splitlines()
    cves_evaluation = {k: v for k, v in cves_evaluation.items() if k in identified_cves}
    run_round3(cves_data, cves_evaluation, web_search=True)