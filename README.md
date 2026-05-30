# OmniVul

This repository contains artifacts for KDD26 accepted paper.

Paper title: **OmniVul: A Holistic Multi-Stage Benchmark for LLM-Based Vulnerability Assessment**

We propose a benchmark dataset for evaluation and fine-tuning of vulnerability analysis using LLMs.

### Abstract:

With more than 20,000 Common Vulnerabilities and Exposures (CVEs) reported annually, software vulnerabilities represent a critical cybersecurity challenge. This volume has intensified the demand for automated detection and analysis, motivating the integration of large language models (LLMs) for such tasks. However, existing vulnerability benchmarks are not suitable for evaluating LLMs' capabilities in vulnerability assessment, as most of them 1) rely on narrow data sources, 2) lack deep context, and 3) focus on single-turn Q&A rather than realistic, multi-stage analyst workflows. To address this gap, we introduce OmniVul, a comprehensive multi-turn benchmark for LLM-based vulnerability assessment. OmniVul comprises 2,000 CVEs with question–answer pairs spanning 23 attributes, including detection, code localization, root cause analysis, and patch suggestion. We employ an automated workflow to aggregate multi-source data via Retrieval-Augmented Generation (RAG), ensuring quality through LLM-as-a-Judge filtering and conformal prediction calibrated by human expert annotations. An evaluation of five state-of-the-art LLMs on OmniVul reveals distinct performance gaps, with top-1 accuracy remaining below 50% on average for vulnerable code detection and CVE identification. Our evaluation also demonstrates that current models lack critical reasoning capabilities for reliable vulnerability assessment. These results highlight the importance of OmniVul for advancing research in evaluating and fine-tuning LLMs for vulnerability assessment.


Each section of the paper are presented as their respective folder name.

Section 3 consists of three key steps:
	step_1: Data Collection and Portfolio construction. This also contains code for a sample dataset with Windows CVEs. 
	step_2: This consists of QA pair curation
	step_3: This is the evaluation of RAG system and conformal prediction.

Section 4 consists the links for data we collected and the results we got

Section 5 contains the evaluation that we performed using SOTA LLMs.


To start the execution please install the required packages listed in `requirements.txt` file. 


You can cite this paper using

```
@inproceedings{
kandalam2026omnivul,
title={OmniVul: A Holistic, Multi-Turn Conversational Benchmark for {LLM}-Based Vulnerability Assessment},
author={Vishnu Teja Kandalam and Viet Quoc Duong and Xiaochang Li and Minghui Yin and Vamsi Shankar Simhadri and Hung Pham and Huajie Shao and Xiaokuan Zhang and Yue Xiao},
booktitle={KDD 2026 Datasets and Benchmarks Track (Cycle 2)},
year={2026},
url={https://openreview.net/forum?id=P8nzBpsqxE}
}
```
