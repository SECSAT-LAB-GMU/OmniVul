# Step 1.

import requests
import pandas as pd
import json
import time
import sys
from datetime import datetime, timedelta
import os
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from CONFIG import years, PLATFORM

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
Key =  "a42d3903-399a-4ce3-baf4-a2a802c0084d"   
NVD_API_KEY = os.getenv("NVD_API_KEY", Key)
HEADERS = {'apiKey': NVD_API_KEY}


def fetch_cve_by_id(cve_id):
    """Fetch CVE details by specific CVE ID"""
    try:
        response = requests.get(f"{NVD_API_URL}?cveId={cve_id}", headers=HEADERS)
        if response.status_code == 200:
            data = response.json()
            if "vulnerabilities" in data:
                return data["vulnerabilities"]
            else:
                print(f"No data found for CVE: {cve_id}")
                return None
        else:
            print(f"Error {response.status_code}: {response.text}")
            return None
    except Exception as e:
        print(f"Exception occurred: {e}")
        return None

def fetch_cve_by_year(year):
    """Fetch CVE details for an entire year using pagination and date ranges"""
    start_date = datetime(year, 1, 1)
    end_date = datetime(year, 12, 31)

    delta = timedelta(days=120)
    all_cve_data = []

    while start_date <= end_date:
        pub_start_date = start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        pub_end_date = (start_date + delta - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.999Z")
        if datetime.strptime(pub_end_date, "%Y-%m-%dT%H:%M:%S.999Z") > end_date:
            pub_end_date = end_date.strftime("%Y-%m-%dT%H:%M:%S.999Z")

        print(f"Fetching CVEs from {pub_start_date} to {pub_end_date}")
        start_index = 0
        results_per_page = 2000  # Maximum allowed by API
        max_attempts = 5  # Avoid infinite loop

        while True:
            params = {
                "pubStartDate": pub_start_date,
                "pubEndDate": pub_end_date,
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
                "keywordSearch": PLATFORM,
            }
            try:
                response = requests.get(NVD_API_URL, headers=HEADERS, params=params)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            # Skip rejected vulnerabilities
                            if vuln.get("cve", {}).get("vulnStatus", "") == "Rejected":
                                continue
                            # if not is_cpematch_linux_related(vuln):
                                # print("Skipping non-Linux CVE")
                                # continue
                            all_cve_data.append(vuln.get("cve", {}))
                    else:
                        print(f"No vulnerabilities returned for range starting {pub_start_date}")
                        break

                    # Check if more data to fetch
                    total_results = data.get("totalResults", 0)
                    if total_results == 0 or start_index >= total_results:
                        break

                    start_index += results_per_page
                else:
                    print(f"Error {response.status_code}: {response.text}")
                    break
            except Exception as e:
                print(f"Exception occurred: {e}")
                max_attempts -= 1
                if max_attempts == 0:
                    print("Max attempts reached, moving to next date range.")
                    break
                time.sleep(5)  # Wait before retry

            # Prevent triggering request rate limits
            time.sleep(3)

        start_date += delta

    print(f"Found {len(all_cve_data)} CVEs for year {year}")
    return all_cve_data

def is_cpematch_linux_related(vuln):
    """Check if Vulnerability is related to Linux Platform"""
    if "configurations" not in vuln.get('cve', {}) or not vuln.get('cve').get("configurations", {}):
        return False
        
    configurations = vuln.get('cve').get("configurations", {})[0]
    configurations = configurations.get("nodes", [])
    for node in configurations:
        for cpe_match in node.get("cpeMatch", []):
            cpe_uri = cpe_match.get("criteria", "")
            if PLATFORM in cpe_uri.lower():
                return True
    # print("No Linux Matched")
    # print(vuln)
    return False

# def save_all_cve_data(all_cve_data, output_path = "nvd_cve_detail/complete_nvd_cve_dict.json"):
def save_all_cve_data(all_cve_data, output_path = "nvd_cve_detail/complete_nvd_cve_dict.json"):
    """Save all collected CVE data to consolidated files"""
    if not all_cve_data:
        print("No CVE data to save.")
        return
    
    all_cve_data_dict = {}
    # make all cve data as dict (key = cve_id)

    # laod the comleted cves from downlaoded_nvd_cve_keys.txt
    try:
        with open("downlaoded_nvd_cve_keys.txt", 'r') as file:
            completed_cves = file.readlines()
        completed_cves = [cve.strip() for cve in completed_cves]
    except FileNotFoundError:
        print("First time donwloading...")


    for entry in all_cve_data:
        all_cve_data_dict[entry["id"]] = entry
        
    # Create directories if they don't exist
    os.makedirs("nvd_cve_detail", exist_ok=True)
    
    # Save all CVE data as JSON
    with open(output_path, 'w') as json_file:
        json.dump(all_cve_data_dict, json_file, indent=4)
    print(f"Saved {len(all_cve_data_dict)} CVE details to {output_path}")

if __name__ == "__main__":
    """Here we fetch all CVE details from NVD API by year"""
    all_cve_data = []
    
    for year in years:
        print(f"Fetching CVE IDs for year {year}...")
        os.makedirs(f"nvd_cve_detail/{PLATFORM}_years/", exist_ok= True)
        year_cve_data = fetch_cve_by_year(year)
        if year_cve_data:
            with open(f"nvd_cve_detail/{PLATFORM}_years/cve_data_{year}.json", 'w') as file:
                json.dump(year_cve_data, file, indent=4)
            all_cve_data.extend(year_cve_data)
            print(f"Total CVE IDs found for {year}: {len(year_cve_data)}")
    
    # Save all data to consolidated files
    print(f"Total CVE IDs found across all years: {len(all_cve_data)}")
    save_all_cve_data(all_cve_data)