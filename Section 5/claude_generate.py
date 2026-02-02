import os, sys, json
from collections import defaultdict
from prompts import TEMPLATE_R1, TEMPLATE_R2
from prompts import TEMPLATE_R3_CLAUDE as TEMPLATE_R3
from questions import qa_questions as QA_QUESTIONS, rag_questions as RAG_QUESTIONS
import time
from tqdm import tqdm
import anthropic
import tiktoken

# Claude API setup
CLAUDE_KEY = ''

if CLAUDE_KEY == '':
    print("Provide API key")
    exit()

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", CLAUDE_KEY))

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
    input_tokens = _get(usage, "input_tokens", default=0)
    output_tokens = _get(usage, "output_tokens", default=0) 
    total_tokens = (input_tokens or 0) + (output_tokens or 0)
    
    cache_creation_tokens = _get(usage, "cache_creation_input_tokens", default=0)
    cache_read_tokens = _get(usage, "cache_read_input_tokens", default=0)
    
    effective_input_tokens = (input_tokens or 0) - (cache_read_tokens or 0) + (cache_creation_tokens or 0) * 1.25
    cache_hit_rate = (cache_read_tokens / input_tokens) if input_tokens else 0.0
    
    return {
        "eval": {
            # Use OpenAI-compatible field names for consistency
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": total_tokens,
            "prompt_tokens_details": {
                "cached_tokens": cache_read_tokens,
                "cache_creation_tokens": cache_creation_tokens,
                "uncached_prompt_tokens": (input_tokens or 0) - (cache_read_tokens or 0),
                "cache_hit_rate": round(cache_hit_rate, 4),
                "effective_input_cost": effective_input_tokens,  # Adjusted for cache pricing
            },
            # Claude-specific fields
            "claude_usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_creation_input_tokens": cache_creation_tokens,
                "cache_read_input_tokens": cache_read_tokens,
            }
        }
    }

def truncate_to_fit(prompt, max_tokens: int = 128000, encoding=tiktoken.encoding_for_model("gpt-4o")):
    tokens = encoding.encode(prompt)
    if len(tokens) > max_tokens:
        tokens = tokens[:max_tokens]
    return encoding.decode(tokens)

def run_round1(cves_data, cves_evaluation):
    out_dir = "claude_results_round1"
    token_dir = "claude_evaluate_tokens"
    encoding = tiktoken.encoding_for_model("gpt-4o")
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(token_dir, exist_ok=True)
    run_cves = list(cves_evaluation.keys())
    evaluated_cves = [f.replace('.json','') for f in os.listdir(out_dir)]
    print(f"Already evaluated CVEs: {len(evaluated_cves)}")
    run_cves = [cve for cve in run_cves if cve not in evaluated_cves]
    
    for cve in tqdm(run_cves, desc="Identifying vulnerable CVEs"):
        code_blocks = _get(cves_data, cve, "CVE_intrinsic_attributes", "Vulnerable Location", "Vulnerable code block", default=[])
        eval_prompt = TEMPLATE_R1.format(code_blocks=json.dumps(code_blocks, indent=2))

        # if len(encoding.encode(eval_prompt)) > 100000:
        #     eval_prompt = truncate_to_fit(eval_prompt, max_tokens=100000, encoding=encoding)
        #     print(f"Truncated prompt for {cve} to fit within token limit.")
        
        # Updated for Claude Sonnet 4 API
        resp = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            temperature=0,
            messages=[{"role": "user", "content": eval_prompt}]
        )
        
        answer = resp.content[0].text
        usage = getattr(resp, "usage", None)
        
        try:
            eval_dict = json.loads(answer)
        except:
            eval_dict = {}
        
        token_usage_dict = get_usage(usage)
        
        with open(f"{out_dir}/{cve}.json", "w") as f: 
            json.dump(eval_dict, f, indent=2)
        with open(f"{token_dir}/{cve}.json", "w") as f: 
            json.dump(token_usage_dict, f, indent=2)

def run_round2(cves_data, cves_evaluation, web_search=False):
    out_dir = "claude_results_round2"
    token_dir = "claude_evaluate_tokens"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(token_dir, exist_ok=True)
    search_dict = load_json("cve_id_search_results.json", default={})

    run_cves = list(cves_evaluation.keys())
    evaluated_cves = [f.replace('.json','') for f in os.listdir(out_dir)]
    print(f"Already evaluated CVEs: {len(evaluated_cves)}")
    run_cves = [cve for cve in run_cves if cve not in evaluated_cves]

    for cve in tqdm(run_cves, desc="Retrieving CVE IDs"):
        # Use _get for safer access to nested data
        code_blocks = _get(cves_data, cve, "CVE_intrinsic_attributes", "Vulnerable Location", "Vulnerable code block", default=[])
        file_names = _get(cves_data, cve, "CVE_intrinsic_attributes", "Vulnerable Location", "File name", default=[])

        if web_search:
            if cve in search_dict:
                search_context = search_dict[cve]
            else:
                search_context = "None."
        
        eval_prompt = TEMPLATE_R2.format(
            file_names=json.dumps(file_names, indent=2),
            code_blocks=json.dumps(code_blocks, indent=2),
            search_context=search_context if web_search else "None.",
        )
        
        # Updated for Claude Sonnet 4 API
        resp = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            temperature=0,
            messages=[{"role": "user", "content": eval_prompt}]
        )
        
        answer = resp.content[0].text
        usage = getattr(resp, "usage", None)
        
        try:
            if isinstance(answer, str):
                eval_dict = json.loads(answer)
            elif isinstance(answer, dict):
                eval_dict = answer
        except:
            print(f"Error parsing JSON for {cve}")
            eval_dict = {}
            
        token_usage_dict = get_usage(usage)
        with open(f"{out_dir}/{cve}.json", "w") as f: 
            json.dump(eval_dict, f, indent=2)
        with open(f"{token_dir}/{cve}.json", "w") as f: 
            json.dump(token_usage_dict, f, indent=2)
        

def run_round3(cves_data, cves_evaluation, web_search=False):
    out_dir = "claude_results_round3"
    token_dir = "claude_evaluate_tokens"
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
        
        # Use _get for safer access to nested data
        code_blocks = _get(cves_data, cve, "CVE_intrinsic_attributes", "Vulnerable Location", "Vulnerable code block", default=[])
        file_names = _get(cves_data, cve, "CVE_intrinsic_attributes", "Vulnerable Location", "File name", default=[])

        if web_search:
            if cve in search_dict:
                search_context = search_dict[cve]
            else:
                search_context = "None."

        eval_prompt = TEMPLATE_R3.format(
                    cve_id=cve,
                    code_blocks=json.dumps(code_blocks, indent=2),
                    file_names=json.dumps(file_names, indent=2),
                    search_context=search_context,
                )

        for attribute in RAG_QUESTIONS.keys():
            for key in RAG_QUESTIONS[attribute].keys():
                question = QA_QUESTIONS[attribute][key]
                if attribute == "SCORES" and key != "score_explain":
                    rag_answer = _get(cves_evaluation, cve, attribute, key, 'portfolio', default="Not found")
                else:
                    rag_answer = _get(cves_evaluation, cve, attribute, key, 'rag', default="Not found")
                
                # Updated for Claude Sonnet 4 API
                resp = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=1024,
                    temperature=0,
                    system=[{"type": "text", 
                             "text": eval_prompt, 
                             "cache_control": {"type": "ephemeral"}}],
                    messages=[{"role": "user", 
                               "content": question}]
                )
                
                eval_answer = resp.content[0].text
                usage = getattr(resp, "usage", None)
                
                eval_dict[attribute][key] = {
                    "question": question,
                    "response": eval_answer,
                    "rag": rag_answer,
                }
                token_usage_dict[attribute][key] = get_usage(usage)

        with open(f"{out_dir}/{cve}.json","w") as f: 
            json.dump(eval_dict,f,indent=2)
        with open(f"{token_dir}/{cve}.json","w") as f: 
            json.dump(token_usage_dict,f,indent=2)

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
    identified_cves = open('claude_top1_correct_cves.txt').read().splitlines()
    cves_evaluation = {k: v for k, v in cves_evaluation.items() if k in identified_cves}
    run_round3(cves_data, cves_evaluation, web_search=True)