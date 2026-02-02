import requests
from tqdm import tqdm
import os
import time
import sys

cve_ids = []
with open("linux_only_cves.txt", 'r', encoding='utf-8') as f:
    for line in f:
        cid = line.strip().upper()
        if cid:
            cve_ids.append(cid)

if not cve_ids:
    sys.exit(1)

cache_dir = "complete_ubuntu_cve_html_cache"
os.makedirs(cache_dir, exist_ok=True)

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/114.0.0.0 Safari/537.36"
})

completed_ids = os.listdir(cache_dir)
completed_ids = [cve[:-5] for cve in completed_ids]

with open("failed_cve_ids.txt", "r", encoding="utf-8") as f:
    failed_cve_ids = f.readlines()

failed_cve_ids = [cve_id.strip() for cve_id in set(failed_cve_ids)]

cve_ids_temp = [cve_id for cve_id in cve_ids if cve_id not in completed_ids]
cve_ids_temp += [cve_id for cve_id in failed_cve_ids if cve_id not in completed_ids]
cve_ids = list(set(cve_ids_temp))


for cve_id in tqdm(cve_ids, desc="Downloading Ubuntu CVE pages"):
    if cve_id in completed_ids or cve_id in failed_cve_ids:
        continue
    url = f"https://ubuntu.com/security/{cve_id}"
    try:
        resp = session.get(url, timeout=10)
        if resp.status_code == 200:
            with open(os.path.join(cache_dir, f"{cve_id}.html"),
                      "w", encoding="utf-8") as f:
                f.write(resp.text)
        else:
            print(f" {cve_id}{resp.status_code}")
            failed_cve_ids.append(cve_id)
    except Exception as e:
        print(f" {cve_id} {e}")
        failed_cve_ids.append(cve_id)

    time.sleep(10)

print( cache_dir)

with open("failed_cve_ids.txt", "a", encoding="utf-8") as f:
    for cve_id in failed_cve_ids:
        f.write(cve_id + "\n")
