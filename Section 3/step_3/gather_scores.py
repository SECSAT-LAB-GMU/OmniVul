import json
import pandas as pd
import os
from questions import rag_questions as RAG_QUESTIONS

model_name = "rag"

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

cves_faithfulness = []
cves_correctness = []
cves_completeness = []

os.makedirs("scores", exist_ok=True)

for cve in json.load(open("final_sota_qa_pairs.json", "r")):
    cve_file = f"{cve}.json"
    if os.path.exists(f"{model_name}_results/{cve_file}"):
        with open(f"{model_name}_results/{cve_file}", "r") as f:
            data = json.load(f)
        
        cve = cve_file.replace(".json", "")
        correctness_dict = {'CVE': cve}
        completeness_dict = {'CVE': cve}
        faithfulness_dict = {'CVE': cve}
        
        for attribute in RAG_QUESTIONS.keys():
            for key in RAG_QUESTIONS[attribute].keys():
                if attribute == "SCORES" and key != "score_explain":
                    continue

                correctness = data[attribute][key]['correctness']
                completeness = data[attribute][key]['completeness']

                if model_name == "rag":
                    faithfulness = data[attribute][key]['faithfulness']

                if len(correctness) == 0 or len(completeness) == 0:
                    print(f"Missing scores for {cve} - {attribute} - {key}")
                
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
                completeness_dict[final_key] = completeness
                if model_name == "rag":
                    faithfulness_dict[final_key] = faithfulness
        
        cves_correctness.append(correctness_dict)
        cves_completeness.append(completeness_dict)
        cves_faithfulness.append(faithfulness_dict)

len(cves_correctness), len(cves_completeness)
cves_correctness_df = pd.DataFrame(cves_correctness)
cves_completeness_df = pd.DataFrame(cves_completeness)
cves_faithfulness_df = pd.DataFrame(cves_faithfulness)

mean_faithfulness = cves_faithfulness_df.drop(columns=['CVE']).mean().round(2)
mean_correctness = cves_correctness_df.drop(columns=['CVE']).mean().round(2)
mean_completeness = cves_completeness_df.drop(columns=['CVE']).mean().round(2)

mean_faithfulness.to_frame(name="Mean Faithfulness").to_csv(f"scores/{model_name}_mean_faithfulness.csv")
mean_correctness.to_frame(name="Mean Correctness").to_csv(f"scores/{model_name}_mean_correctness.csv")
mean_completeness.to_frame(name="Mean Completeness").to_csv(f"scores/{model_name}_mean_completeness.csv")
cves_correctness_df.to_csv(f"scores/{model_name}_correctness.csv", index=False)
cves_completeness_df.to_csv(f"scores/{model_name}_completeness.csv", index=False)
cves_faithfulness_df.to_csv(f"scores/{model_name}_faithfulness.csv", index=False)