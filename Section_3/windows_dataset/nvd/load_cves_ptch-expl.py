# program to load all data from the CSVs and JSON files collected so far

import json
import csv
from collections import defaultdict
import glob
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from CONFIG import PLATFORM


DATA_FOLDER = f"{PLATFORM}_year_cves"  # Folder containing CSV and JSON files
CVEs_dict = defaultdict(dict)

def load_json_files(folder):
    records = []
    for file in glob.glob(folder + "/*.json"):
        with open(file, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                records.extend(data)
            elif isinstance(data, dict):
                records.extend(list(data.values()))
    return records

def csv_cve_dict(csv_records):
    cve_dict = defaultdict(lambda: defaultdict(list))
    for rec in csv_records:
        # if not cve_dict[rec["CVE ID"]][rec["Type"]+" Links"]:
        #     cve_dict[rec["CVE ID"]][rec["Type"]+" Links"] = []
        cve_dict[rec["CVE ID"]][rec["Type"]+" Links"].append(rec["URL"])

    return cve_dict

def load_csv_files(folder):
    records = []
    for file in glob.glob(folder + "/*.csv"):
        with open(file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(row)
    return records

def load_all_data(folder):
    csv_data = load_csv_files(folder)
    cve_records = csv_cve_dict(csv_data)
    json_data = load_json_files(folder)
    for rec in json_data:
        cve_id = rec["CVE ID"]
        if cve_id in cve_records:
            rec["Patch Links"].append(cve_records[cve_id]["Patch Links"])
            rec["Exploit Links"].append(cve_records[cve_id]["Exploit Links"])
    return json_data


if __name__ == "__main__":

    all_data = load_all_data(DATA_FOLDER)
    print(len(all_data))
    
    with open(f"{PLATFORM}_final_cves.json", "w", encoding="utf-8") as outfile:
        json.dump(all_data, outfile, indent=2, ensure_ascii=False)
