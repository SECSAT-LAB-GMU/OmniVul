This folder contains the data, scripts and results for SOTA LLM Evaluation on 3 steps: (1) Vulnerability Detection, (2) CVE Identification, (3) CVE Attribute QA.

### Data
The 200 CVEs with RAG-generated ground truth are recorded in `final_sota_qa_pairs.json`.

The raw portfolio for these CVEs are available in `portfolio_cves.json`, and the 83 patched versions of these CVEs are in `extracted_patched_cves.json`.

### Scripts
To run the LLM judge for steps 1 and 2, first run `{model}_generate.py`, where model is one of "gpt", "claude", "llama", "qwen", or "claude". Note that you need to provide the OpenAI API key.

Then, running `evaluate_round1.py` will produce the weighted precision, recall, and F1 for Vulnerability Detection. 

`evaluate_round2.py` will calcluate the top-1/5 accuracy scores for CVE Identification, and also write the correctly identified CVE IDs to a `{model}_top1_correct_cves.txt` file.

For step 3, `{model}_generate.py` will load `{model}_top1_correct_cves.txt` and generate the QA attributes for these CVEs. To get Correctness scores, run `evaluate_round3.py`, then `gather_scores.py` to collect the scores for 200 CVEs, and calculate the average for 23 attributes.

### Results

All step 1 outputs from LLMs are recorded in `{model}_complete_detection_result.txt`.

All step 2 outputs from LLMs are recorded in `{model}_complete_cve_result.txt`.

All step 3 outputs from LLMs are recorded in `{model}_complete_QA_result.txt`.
