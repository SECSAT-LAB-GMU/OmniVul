import sys
import json
import os

VAMSI_FOLDER = "final_subject_results/Vamsi"
HUNG_FOLDER = "final_subject_results/Hung"

# VAMSI_FOLDER = "local_cwe_folder/Vamsi"
# HUNG_FOLDER = "local_cwe_folder/Hung"

emb_key_dict = {
    'Localization': ['Function name', 'File name', 'Vulnerable OS component'],
    'CWE': ['Weakness Type'],
    'Reasoning': ['root_cause', 'secure_coding_violation', 'mitigation', 'cia_impact', 'exploit_expl'],
    'Exploit': ['Exploit Code', 'exploited_versions', 'abusable_interfaces', "remote_exploitability", 'exploit_steps', 'privs_req', 'exploit_privs', 'crash_dump'],
    'Patch': ['patch_expl', 'patch_date', 'patched_versions', 'Code diff', 'Patch code'],
    'SCORES': ['score_explain']
}

test_folder = sys.argv[1]

vamsi_results = []
hung_results = []

def ret_scores(folder):
    scores = []
    for file_name in os.listdir(folder):
        if not file_name.endswith(".json"):
            continue
        with open(os.path.join(folder, file_name), "r") as f:
            data = json.load(f)
            scores.append(data)
    scores_dict = {}
    for score in scores:
        cve_id = next(iter(score.keys()))
        scores_dict[cve_id] = score[cve_id]
    return scores_dict

vamsi_results = ret_scores(os.path.join(VAMSI_FOLDER, test_folder))
hung_results = ret_scores(os.path.join(HUNG_FOLDER, test_folder))

cves = list(vamsi_results.keys())

no_conflicts = 0
conflicts_dict = {}
conflict_cves = 0

for cve in cves:
    vamsi_score = vamsi_results[cve]
    hung_score = hung_results[cve]
    for key in emb_key_dict.keys():
        for attribute in emb_key_dict[key]:

            vamsi_faithfulness_value = vamsi_score[key][attribute]["avg_faithfulness"]
            vamsi_crrectness_value = vamsi_score[key][attribute]["avg_correctness"]
            vamsi_completeness = vamsi_score[key][attribute]["completeness"]

            hung_faithfulness_value = hung_score[key][attribute]["avg_faithfulness"]
            hung_crrectness_value = hung_score[key][attribute]["avg_correctness"]
            hung_completeness = hung_score[key][attribute]["completeness"]

            conflict_flag = False
            if vamsi_faithfulness_value != hung_faithfulness_value or \
               vamsi_crrectness_value != hung_crrectness_value or \
               vamsi_completeness != hung_completeness:
                no_conflicts += 1
                if cve not in conflicts_dict:
                    conflicts_dict[cve] = {}
                if key not in conflicts_dict[cve]:
                    conflicts_dict[cve][key] = {}
                conflicts_dict[cve][key][attribute] = {
                    'vamsi_faithfulness': vamsi_faithfulness_value,
                    'hung_faithfulness': hung_faithfulness_value,
                    'vamsi_correctness': vamsi_crrectness_value,
                    'hung_correctness': hung_crrectness_value,
                    'vamsi_completeness': vamsi_completeness,
                    'hung_completeness': hung_completeness,
                    'vamsi_extra_text': vamsi_score[key][attribute]["better_text"],
                    'hung_extra_text': hung_score[key][attribute]["better_text"]
                }
                print(f"Conflict found for {cve} - {key} - {attribute}")
                conflict_flag = True
                # print(f"Vamsi: Faithfulness={vamsi_faithfulness_value}, Correctness={vamsi_crrectness_value}, Completeness={vamsi_completeness}, Extra Text={vamsi_extra_text}")
                # print(f"Hung: Faithfulness={hung_faithfulness_value}, Correctness={hung_crrectness_value}, Completeness={hung_completeness}, Extra Text={hung_extra_text}")            
    if conflict_flag:
        conflict_cves+=1

# Write conflicts to a JSON file
with open(f"{test_folder}_conflicts.json", "w") as conflict_file:
# with open(f"loc_cwe_{test_folder}_conflicts.json", "w") as conflict_file:
    json.dump(conflicts_dict, conflict_file, indent=4)

print(f"Total CVEs processed: {conflict_cves}")
print(f"Total conflicts found: {no_conflicts}")
print("Done.")
