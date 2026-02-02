This folder contains the data and code to perform conformal prediction with LLM-as-a-Judge architecture.

### Data
The human-assigned and LLM-assigned scores for the helld-out calibration set are recorded in `conformal/human_{metric}.csv` and `conformal/cves_{metric}.csv` respectively, where `metric` is faithfulness, correctness, or completeness.

### Scripts
To run the LLM judge for RAG-generated attributes, run `evaluate_rag.py`. Note that you need to provide the OpenAI API key.

Executing the comformal.py script will output `nonconformity_{metric}.csv` for absolute human-LLM score differences, and `threshold_{metric}.csv` for the calibrated thresholds (23 attributes)
