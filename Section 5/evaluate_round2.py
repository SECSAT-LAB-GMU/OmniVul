import json
import os

model_name = "gpt"
result_dir = f"{model_name}_results_round2"
top1_correct = []
top5_correct = []

for cve_file in os.listdir(result_dir):
    data = json.load(open(os.path.join(result_dir, cve_file), 'r'))
    cve_id = cve_file.replace('.json', '')

    try:
        extracted_ids = [d['CVE_ID'] for d in data]
    except:
        print(f"Error processing {cve_file}")
        continue

    if len(extracted_ids) == 0:
        print(f"No CVE IDs extracted for {cve_id}")
        continue

    if cve_id in extracted_ids:
        print(f"{cve_id} found, position {extracted_ids.index(cve_id)+1}")
        top5_correct.append(cve_id)

    if cve_id == extracted_ids[0]:
        top1_correct.append(cve_id)

total = len(os.listdir(result_dir))
print(len(top1_correct), len(top5_correct), total)
print(f"Top-1 accuracy: {len(top1_correct)}/{total} = {len(top1_correct)/total:.2%}")
print(f"Top-5 accuracy: {len(top5_correct)}/{total} = {len(top5_correct)/total:.2%}")

with open(f"{model_name}_top1_correct_cves.txt", 'w') as f:
    f.writelines(f"{cve_id}\n" for cve_id in top1_correct)


