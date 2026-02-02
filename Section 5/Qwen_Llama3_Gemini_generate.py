'''
Serving with desired model with sgland or vllm
eg. python -m sglang.launch_server --model-path Qwen/Qwen3-8B
uv run -m vllm.entrypoints.openai.api_server --model Qwen/Qwen3-Coder-30B-A3B-Instruct --gpu_memory_utilization 0.9 --max-model-len 101000
uv run -m vllm.entrypoints.openai.api_server --model "RedHatAI/Llama-3.3-70B-Instruct-quantized.w4a16" --gpu-memory-utilization 0.9 --trust-remote-code --max-model-len 101000

For Qwen3-30B-A3B-Instruct-2507-FP8 (optimal config):
vLLM:
uv run -m vllm.entrypoints.openai.api_server --model "Qwen/Qwen3-30B-A3B-Instruct-2507-FP8" --max-model-len 101000 --gpu-memory-utilization 0.95

SGLang:
python3 -m sglang.launch_server --model-path "Qwen/Qwen3-30B-A3B-Instruct-2507-FP8" --context-length 262144 --mem-frac 0.75 --attention-backend dual_chunk_flash_attn --tp 4 --chunked-prefill-size 131072

Query the model with OpenAI API
'''

import os
import sys
import json
from collections import defaultdict
import random
import argparse
from tqdm import tqdm
from typing import Optional, Any
import torch
from openai import OpenAI # type: ignore
import google.generativeai as genai
from gpt_prompt import TEMPLATE_R1, TEMPLATE_R2, TEMPLATE_R3
import matplotlib.pyplot as plt
import seaborn as sns

import numpy as np
from sklearn.metrics import confusion_matrix

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'cve-llm-predict')))

from questions import qa_questions as QA_QUESTIONS
from questions import rag_questions as RAG_QUESTIONS

dummy_api_key = "EMPTY"
dummy_api_base = "http://localhost:8000/v1"

# # https://huggingface.co/meta-llama/CodeLlama-70b-hf
# codeLlamaModels = ["meta-llama/CodeLlama-70b-Instruct-hf", "meta-llama/CodeLlama-34b-Instruct-hf", "meta-llama/CodeLlama-13b-Instruct-hf", "meta-llama/CodeLlama-7b-Instruct-hf", "TheBloke/CodeLlama-70B-Instruct-AWQ"]
# # https://huggingface.co/collections/Qwen/qwen3-coder-687fc861e53c939e52d52d10
# qwen3coderModels = ["Qwen/Qwen3-Coder-30B-A3B-Instruct", "Qwen/Qwen3-Coder-30B-A3B-Instruct-FP8", "Qwen/Qwen3-4B"]




def macro_statistics(y_pred, y_true):
    cm = confusion_matrix(y_true, y_pred)
    FP = cm.sum(axis=0) - np.diag(cm)
    FN = cm.sum(axis=1) - np.diag(cm)
    TP = np.diag(cm)
    TN = cm.sum() - (FP + FN + TP)

    TPR = TP / (TP + FN)
    TNR = TN / (TN + FP)

    # statistics for each class
    precision = TP / (TP + FP + 1e-10)
    recall = TP / (TP + FN + 1e-10)
    f1 = 2 * (precision * recall) / (precision + recall + 1e-10)
    accuracy = (TP + TN) / (TP + TN + FP + FN)
    # print(accuracy.shape, precision.shape, recall.shape, f1.shape)

    # macro average
    macro_precision = np.mean(precision)
    macro_recall = np.mean(recall)
    macro_f1 = np.mean(f1)
    macro_accuracy = np.mean(accuracy)


    return cm, macro_precision, macro_recall, macro_f1, macro_accuracy


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

def get_usage(usage, args=None):
    if args and args.model == "Gemini":
        prompt_tokens = _get(usage, "prompt_token_count", default=0)
        candidate_tokens = _get(usage, "candidates_token_count", default=0)
        cached_content_tokens = _get(usage, "cached_content_token_count", default=0)
        total_tokens = _get(usage, "total_token_count", default=0)
        return{
            "eval": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": candidate_tokens,
                "total_tokens": total_tokens,
                "cached_tokens": cached_content_tokens,
            }
        }

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


def generate(model_name:str, eval_prompt:str):
    client = OpenAI(api_key=dummy_api_key, base_url=dummy_api_base)
    Config = {
        'Qwen/Qwen3-30B-A3B-Instruct-2507-FP8': {
            'temperature': 0.7,
            'max_tokens': 1024,
            'top_p': 0.8,
            'top_k': 20,
            'min_p': 0.0
        },
    }

    if model_name in Config:
        extra_params = {"top_k": Config[model_name]['top_k']}
        if 'repetition_penalty' in Config[model_name]:
            extra_params['repetition_penalty'] = Config[model_name]['repetition_penalty']
        if 'min_p' in Config[model_name]:
            extra_params['min_p'] = Config[model_name]['min_p']

        response = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": eval_prompt}],
            temperature=Config[model_name]['temperature'],
            max_tokens=Config[model_name]['max_tokens'],
            top_p=Config[model_name]['top_p'],
            extra_body=extra_params,
        )

    elif model_name == "gemini-2.5-pro":
        model = genai.GenerativeModel('gemini-2.5-pro')
        response = model.generate_content(eval_prompt)

    else:
        response = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": eval_prompt}],
            max_tokens=1024,
        )
    return response


def run_round1(args, cves_data, cves_evaluation):
    out_dir = f"{args.model_name}_updated_results_round1"
    token_dir = f"{args.model_name}_updated_evaluate_tokens"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(token_dir, exist_ok=True)

    run_cves = list(cves_evaluation.keys())
    evaluated_cves = [f.replace('.json','') for f in os.listdir(out_dir)]
    print(f"Already evaluated CVEs: {len(evaluated_cves)}")
    run_cves = [cve for cve in run_cves if cve not in evaluated_cves]

    for cve in tqdm(run_cves, desc="Identifying vulnerable CVEs"):
        try:
            code_blocks = _get(cves_data, cve, "CVE_intrinsic_attributes","Vulnerable Location","Vulnerable code block", default=[])
            eval_prompt = TEMPLATE_R1.format(code_blocks=json.dumps(code_blocks, indent=2))

            resp = generate(args.model_name, eval_prompt)
            if hasattr(resp, 'choices'):
                answer = resp.choices[0].message.content
            else:
                answer = resp.text
            if hasattr(resp, 'usage'):
                usage = getattr(resp,"usage",None)
            else:
                usage = getattr(resp, 'usage_metadata', None)
            try:
                # Extract JSON from markdown code blocks
                json_content = answer.strip()
                if json_content.startswith('```json'):
                    json_content = json_content[7:]  # Remove ```json
                if json_content.startswith('```'):
                    json_content = json_content[3:]   # Remove ```
                if json_content.endswith('```'):
                    json_content = json_content[:-3]  # Remove ending ```
                json_content = json_content.strip()

                eval_dict = json.loads(json_content)

            except Exception as e:
                print(f"Error parsing JSON for {cve}: {e}")
                print(f"Raw answer: {answer}")
                raise ValueError(f"JSON parsing error: {e}") from e           


            token_usage_dict = get_usage(usage, args)

            with open(f"{out_dir}/{cve}.json","w") as f: json.dump(eval_dict,f,indent=2)
            with open(f"{token_dir}/{cve}.json","w") as f: json.dump(token_usage_dict,f,indent=2)
        except Exception as e:
            print(f"Error generating with {args.model_name} for {cve}: {e} in round 1")
            continue

def cal_metrics_round1(args):
    predict = []
    groundTruth = []
    result_dir = f"{args.model_name}_updated_results_round1"
    
    for cve_file in os.listdir(result_dir):
        json_data = json.load(open(os.path.join(result_dir, cve_file), 'r'))
        total_files = len(json_data)
        pos_files = sum(1 for v in json_data.values() if v == 1)
        neg_files = sum(1 for v in json_data.values() if v == 0)
        unk_files = sum(1 for v in json_data.values() if v == -1)
        print(f"{cve_file}: Total={total_files}, Pos={pos_files}, Neg={neg_files}, Unk={unk_files}")
        if pos_files > 0:
            predict.append(1)
        else:
            predict.append(0)

        if cve_file.startswith('P'):
            groundTruth.append(0)
        else:
            groundTruth.append(1)

    cm, precision, recall, f1, accuracy = macro_statistics(np.array(predict), np.array(groundTruth))
    print(f"Round 1 - {cve_file}: Precision={precision}, Recall={recall}, MA-F1={f1}, Accuracy={accuracy}")

    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Pred Neg', 'Pred Pos'], yticklabels=['True Neg', 'True Pos'])
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.title(f'Confusion Matrix for {args.model.upper()} Model')
    plt.savefig(f'{args.model_name}_round1_confusion_matrix.png')


def run_round2(args, cves_data, cves_evaluation, use_web_search=False):
    out_dir = f"{args.model_name}_updated_results_round2"
    token_dir = f"{args.model_name}_updated_evaluate_tokens"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(token_dir, exist_ok=True)
    search_dict = load_json("cve_id_search_results.json", default={})

    run_cves = list(cves_evaluation.keys())
    evaluated_cves = [f.replace('.json','') for f in os.listdir(out_dir)]
    run_cves = [cve for cve in run_cves if cve not in evaluated_cves]

    for cve in tqdm(run_cves, desc="Retrieving CVE IDs"):
        try:
            if use_web_search:
                search_context = search_dict[cve]

            code_blocks = cves_data[cve]["CVE_intrinsic_attributes"]["Vulnerable Location"]["Vulnerable code block"]
            file_names = cves_data[cve]["CVE_intrinsic_attributes"]["Vulnerable Location"]["File name"]
            eval_prompt = TEMPLATE_R2.format(
                file_names=json.dumps(file_names, indent=2),
                code_blocks=json.dumps(code_blocks, indent=2),
                search_context=search_context
            )

            resp = generate(args.model_name, eval_prompt)
            if hasattr(resp, 'choices'):
                answer = resp.choices[0].message.content
                if not isinstance(answer, dict):
                    try:
                        eval_dict = json.loads(answer)
                    except:
                        eval_dict = {}
                else:
                    eval_dict = answer
            else:
                answer = resp.text
                # Extract JSON from markdown code blocks
                try:
                    json_content = answer.strip()
                    if json_content.startswith('```json'):
                        json_content = json_content[7:]  # Remove ```json
                    if json_content.startswith('```'):
                        json_content = json_content[3:]   # Remove ```
                    if json_content.endswith('```'):
                        json_content = json_content[:-3]  # Remove ending ```
                    json_content = json_content.strip()

                    eval_dict = json.loads(json_content)
                except Exception as e:
                    print(f"Error parsing JSON for {cve}: {e}")
                    print(f"Raw answer: {answer}")
                    raise ValueError(f"JSON parsing error: {e}") from e     

            if hasattr(resp, 'usage'):
                usage = getattr(resp,"usage",None)
            else:
                usage = getattr(resp, 'usage_metadata', None)

            token_usage_dict = get_usage(usage)

            with open(f"{out_dir}/{cve}.json","w") as f: 
                json.dump(eval_dict,f,indent=2)
            with open(f"{token_dir}/{cve}.json","w") as f: 
                json.dump(token_usage_dict,f,indent=2)
        except Exception as e:
            print(f"Error generating with {args.model_name} for {cve}: {e} in round 2")
            continue


def run_round3(args, cves_data, cves_evaluation, run_cves, use_web_search=False):
    out_dir = f"{args.model_name}_updated_results_round3"
    token_dir = f"{args.model_name}_updated_evaluate_tokens"
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(token_dir, exist_ok=True)
    search_dict = load_json("cve_id_search_results.json", default={})

    evaluated_cves = [f.replace('.json','') for f in os.listdir(out_dir)]
    run_cves = [cve for cve in run_cves if cve not in evaluated_cves]

    for cve in tqdm(run_cves, desc="Generating QA answers"):
        eval_dict = defaultdict(lambda: defaultdict(dict))
        token_usage_dict = defaultdict(lambda: defaultdict(dict))
        code_blocks = cves_data[cve]["CVE_intrinsic_attributes"]["Vulnerable Location"]["Vulnerable code block"]
        file_names = cves_data[cve]["CVE_intrinsic_attributes"]["Vulnerable Location"]["File name"]
        try:
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
                        question=question,
                        search_context=search_dict.get(cve,"None") if use_web_search else "None",
                    )

                    resp = generate(args.model_name, eval_prompt)

                    if hasattr(resp, 'choices'):
                        answer = resp.choices[0].message.content
                        if not isinstance(answer, dict):
                            try:
                                eval_dict = json.loads(answer)
                            except:
                                eval_dict = {}
                        else:
                            eval_dict = answer
                    else:
                        answer = resp.text
                        
                    if hasattr(resp, 'usage'):
                        usage = getattr(resp,"usage",None)
                    else:
                        usage = getattr(resp, 'usage_metadata', None)
                    eval_dict[attribute][key] = {
                        "question": question,
                        "response": answer,
                        "rag": rag_answer,
                    }
                    token_usage_dict[attribute][key] = get_usage(usage)
        except Exception as e:
            print(f"Error generating with {args.model_name} for {cve} attribute {attribute} key {key}: {e} in round 3")
            continue

        with open(f"{out_dir}/{cve}.json","w") as f: 
            json.dump(eval_dict,f,indent=2)
        with open(f"{token_dir}/{cve}.json","w") as f: 
            json.dump(token_usage_dict,f,indent=2)





if __name__ == "__main__":

    _MODEL_NAMES = {'LLama-3.3':"RedHatAI/Llama-3.3-70B-Instruct-quantized.w4a16",
                    "Qwen3":"Qwen/Qwen3-30B-A3B-Instruct-2507-FP8",
                    "Gemini":'gemini-2.5-pro'
                    }

    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=str, default="Gemini", 
    choices=["LLama-3.3", "Qwen3", "Gemini"])

    args = parser.parse_args()
    if args.model == "Gemini":
        genai.configure(api_key="xxxxxx")

    args.model_name = _MODEL_NAMES[args.model]
    print(f"Using model: {args.model}")
    FINAL_SOTA_QA_PAIRS = "./final_sota_qa_pairs.json"
    ALL_QA_PAIRS = "./restructure_500.json"

    with open(ALL_QA_PAIRS) as f: 
        cves_data = json.load(f)

    with open(FINAL_SOTA_QA_PAIRS) as f: 
        cves_evaluation = json.load(f)

    # For Round 1: Vulnerability detection
    print(f"=>Start round 1: Total CVEs in evaluation set: {len(cves_evaluation)}")
    run_round1(args, cves_data, cves_evaluation)

    # For Round 1: Non-vulnerability patch detection
    PATCHED_QA_PAIRS = "./extracted_patched_cves.json"
    with open(PATCHED_QA_PAIRS) as f: 
        patched_cves_data = json.load(f)
    patch_evaluation = {f"P{cve}": data for cve, data in cves_evaluation.items() if f"P{cve}" in patched_cves_data}
    run_round1(args, patched_cves_data, patch_evaluation)
    cal_metrics_round1(args)


    # For Round 2: CVE ID retrieval
    print(f"=>Start round 2: Total CVEs in evaluation set: {len(cves_evaluation)}")
    run_round2(args, cves_data, cves_evaluation, use_web_search=True)
    
    # For Round 3: QA Answering for attributes
    detected_vul_CVES_file =  f"{args.model_name}_identified_cves_in_round2.txt"
    with open(detected_vul_CVES_file, 'r') as f:
        detected_vul_CVES = [line.strip() for line in f.readlines()]
    print(f"=>Start round 3 with {len(detected_vul_CVES)} Vulnerable CVEs")
    run_round3(args, cves_data, cves_evaluation, detected_vul_CVES, use_web_search=True)



