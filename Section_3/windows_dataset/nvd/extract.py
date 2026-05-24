# Step 2.


import json
import pandas as pd
import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from CONFIG import PLATFORM, years

# Load the CVE JSON file
log_file = "complete_cve_patch_exploit_links.log"
# years = [2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025]




total_cves = 0
for year in years:
    # input_file = f"/data2/lexi/data/nvd-linux-00-25Feb/nvd_cve_detail/cve_data_{year}.json"  # Ensure the path is correct
    # input_file = f"patch_exploits/nvd_cve_detail/cve_data_{year}.json"  # Ensure the path is correct
    input_file = f"nvd_cve_detail/{PLATFORM}_years/cve_data_{year}.json"  # Ensure the path is correct


    os.makedirs(f"{PLATFORM}_year_cves", exist_ok = True)
    output_json = f"{PLATFORM}_year_cves/cve_patch_exploit_links_{year}.json"
    output_csv = f"{PLATFORM}_year_cves/cve_patch_exploit_links_{year}.csv"

    with open(input_file, "r", encoding="utf-8") as f:
        cve_data = json.load(f)

    # Extract relevant information
    filtered_cve_data = []
    csv_data = []  # Data for CSV storage
    unique_combinations = set()  # store unique (CVE ID, Type, URL)
    unique_cves = set()
    unique_patches = set()
    unique_exploits = set()

    for cve in cve_data:
        cve_id = cve.get("id", "Unknown CVE")
        references = cve.get("references", [])

        # Filter references that are related to patches or exploits
        patch_links = [ref["url"] for ref in references if "tags" in ref and "Patch" in ref["tags"]]
        exploit_links = [ref["url"] for ref in references if "tags" in ref and "Exploit" in ref["tags"]]

        if patch_links or exploit_links:  # Only store CVEs that have at least one relevant reference

            if cve_id not in unique_cves:
                unique_cves.add(cve_id)

            
            filtered_cve_data.append({
                "CVE ID": cve_id,
                "Patch Links": patch_links,
                "Exploit Links": exploit_links
            })

            # Flatten data for CSV storage with deduplication
            for patch in patch_links:
                combination = (cve_id, "Patch", patch)
                if combination not in unique_combinations:
                    unique_combinations.add(combination)
                    csv_data.append({"CVE ID": cve_id, "Type": "Patch", "URL": patch})
                if patch not in unique_patches:
                    unique_patches.add(patch)

            for exploit in exploit_links:
                combination = (cve_id, "Exploit", exploit)
                if combination not in unique_combinations:
                    unique_combinations.add(combination)
                    csv_data.append({"CVE ID": cve_id, "Type": "Exploit", "URL": exploit})
                if exploit not in unique_exploits:
                    unique_exploits.add(exploit)

    # Save to JSON
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(filtered_cve_data, f, ensure_ascii=False, indent=4)

    # Save to CSV
    df = pd.DataFrame(csv_data)
    df.to_csv(output_csv, index=False)

    # # Print summary statistics
    print(f"✅ Total unique CVEs with references: {len(unique_cves)}")
    print(f"✅ Total unique Patch links: {len(unique_exploits)}")
    print(f"✅ Total unique Exploit links: {len(unique_patches)}")
    print(f"✅ Extracted data saved to: {output_json} (JSON)")
    print(f"✅ Extracted data saved to: {output_csv} (CSV)")

    # statistics summary
    total_cves += len(unique_cves)
    log_content = (
        f"===================== ✅ {year} CVE Filter Finished ==================\n"
        f"✅ Total unique CVEs with references: {len(unique_cves)}\n"
        f"✅ Total unique Patch links: {len(unique_patches)}\n"
        f"✅ Total unique Exploit links: {len(unique_exploits)}\n"
        f"✅ Extracted data saved to: {output_json} (JSON)\n"
        f"✅ Extracted data saved to: {output_csv} (CSV)\n"
    )

    # write into log file
    with open(log_file, "a", encoding="utf-8") as log:
        log.write(log_content)

    # print to the console
    print(log_content)

print(total_cves)