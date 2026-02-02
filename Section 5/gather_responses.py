import os
import json

model_name = "gpt"
step = 3
result_dir = f"{model_name}_results_round{step}"
cves_data = {}

for cve_file in os.listdir(result_dir):
    data = json.load(open(os.path.join(result_dir, cve_file), 'r'))
    cve_id = cve_file.replace('.json', '')
    cves_data[cve_id] = data

if step == 1:
    task = "detection_data"
elif step == 2:
    task = "cve_data"
elif step == 3:
    task = "QA_data"

with open(f"{model_name}_complete_{task}.json", "w") as f:
    json.dump(cves_data, f, indent=2)


