import os
import json
import csv


CSV_HEADER = ["year","quarter","CVE_id", "thread_title", "thread_id", "children_ids"]

stats_directory = "seclist_stats/seclist_stats"


def write_to_csv(results):
    is_exists = os.path.isfile("cve_details.csv")
    with open("cve_details.csv", 'a') as file:
        writer = csv.writer(file)
        if not is_exists:
            writer.writerow(CSV_HEADER)        
        writer.writerow(results)

def ret_CVEs(json_file:str):
    """
        This function takes in the JSON file path as input and returns all the CVEs in that JSON file.
    """
    with open(stats_directory+"/"+json_file, 'r') as file:
        data = json.load(file)

    year, quarter = json_file.split("_")
    # extension తీసేయాలి 
    quarter = quarter[:-5]

    for id, val in data.items():
        sub_ids = []
        for sub in val["subthreads"]:
            sub_ids.append(sub["id"])
        sub_ids = ", ".join(sub_ids) if len(sub_ids) > 0 else ""
        row = [year, quarter, val["CVE_id"], val["title"], id, sub_ids]
        write_to_csv(row)



# write code to take every json one after the other and write all of them to the same file. 

for file in os.listdir(stats_directory):
    if file[-4:] != "json":
        continue
    print(file)
    cves = ret_CVEs(file)







