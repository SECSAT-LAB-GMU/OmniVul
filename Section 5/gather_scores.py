import json
import pandas as pd
import os
from questions import rag_questions as RAG_QUESTIONS

model_name = "gpt"

def get_5_scale(score):
    if score > 0.9:
        return 5.0
    if 0.7 <= score < 0.9:
        return 4.0
    if 0.3 <= score < 0.7:
        return 3.0
    if 0.1 <= score < 0.3:
        return 2.0
    if score < 0.1:
        return 1.0
    
cves_correctness = []

for cve in json.load(open("final_sota_qa_pairs.json", "r")):
    cve_file = f"{cve}.json"
    if os.path.exists(f"{model_name}_results/{cve_file}"):
        with open(f"{model_name}_results/{cve_file}", "r") as f:
            data = json.load(f)
        
        cve = cve_file.replace(".json", "")
        correctness_dict = {'CVE': cve}
        
        for attribute in RAG_QUESTIONS.keys():
            for key in RAG_QUESTIONS[attribute].keys():
                if attribute == "SCORES" and key != "score_explain":
                    continue

                correctness = data[attribute][key]['correctness']
                
                correctness = [value['score'] for value in correctness.values()]
                completeness = completeness['score']
                correctness = sum(correctness) / len(correctness)
                completeness = completeness / 1.0

                correctness = get_5_scale(correctness)
                if model_name == "rag":
                    faithfulness = [value['score'] for value in faithfulness.values()]
                    faithfulness = sum(faithfulness) / len(faithfulness)
                    faithfulness = get_5_scale(faithfulness)

                final_key = attribute.replace(" ", "_") + '_' + key.replace(" ", "_")
                correctness_dict[final_key] = correctness
        
        cves_correctness.append(correctness_dict)

cves_correctness_df = pd.DataFrame(cves_correctness)
mean_correctness = cves_correctness_df.drop(columns=['CVE']).mean().round(2)

mean_correctness.to_frame(name="Mean Correctness").to_csv(f"scores/{model_name}_mean_correctness.csv")
cves_correctness_df.to_csv(f"scores/{model_name}_correctness.csv", index=False)


