import csv
import json
import os
import shutil

with open('../complete_ref_cves_list.txt', 'r') as f:
    cves = f.readlines()

cves = [cve.strip() for cve in cves]

complete_data = {}
for every_quarter in os.listdir("seclist_stats/"):
    if every_quarter.endswith(".json"):
        with open(f"seclist_stats/{every_quarter}", "r") as f:
            data = json.load(f)
            for data_value in data.values():
                if data_value.get("CVE_id") in cves:
                    complete_data[data_value["CVE_id"]] = data_value

for cve in complete_data.keys():
    print(f"Processing {cve}")
    os.makedirs(f"CVE_Arrangements/{cve}", exist_ok=True)
    data = complete_data[cve]
    file_path = data["File_path"]
    file_name = os.path.basename(file_path)
    sub_threads = data["subthreads"]
    shutil.copy(file_path, f"CVE_Arrangements/{cve}/seclists_{file_name}")
    print("\t\tCopying main file:", file_name)
    for sub_thread in sub_threads:
        sub_thread_file_path = sub_thread["File_path"]
        sub_thread_file_name = os.path.basename(sub_thread_file_path)
        shutil.copy(sub_thread_file_path, f"CVE_Arrangements/{cve}/seclists_{sub_thread_file_name}")
        if sub_thread["no_subthreads"] > 0:
            for chld_thread in sub_thread["subthreads"]:
                chld_thread_file_path = chld_thread["File_path"]
                chld_thread_file_name = os.path.basename(chld_thread_file_path)
                shutil.copy(chld_thread_file_path, f"CVE_Arrangements/{cve}/seclists_{chld_thread_file_name}")
    print("\t\tCopying sub threads:", len(sub_threads))


print(f"Total number of CVE information: {len(complete_data)}")