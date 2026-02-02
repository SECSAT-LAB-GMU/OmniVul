import json

def extract_web_links(data, domain):
    filtered_data = {}
    
    count = 0
    for key, entry in enumerate(data):
        filtered_entry = {
            "CVE ID": entry.get("CVE ID", ""),
            "Patch Links": [],
            "Exploit Links": []
        }

        seen_patch = set()
        for link in entry.get("Patch Links", []):
            if isinstance(link, list):
                for l in link:
                    if l not in seen_patch and domain in l:
                        seen_patch.add(l)
                        filtered_entry["Patch Links"].append(link)
                        count += 1                        
            else:
                if domain in link and link not in seen_patch:
                    seen_patch.add(link)
                    filtered_entry["Patch Links"].append(link)
                    count += 1

        seen_exploit = set()
        for link in entry.get("Exploit Links", []):
            if isinstance(link, list):
                for l in link:
                    if l not in seen_patch and domain in l:
                        seen_patch.add(l)
                        filtered_entry["Exploit Links"].append(link)
                        count += 1                        
            if domain in link and link not in seen_exploit:
                seen_exploit.add(link)
                filtered_entry["Exploit Links"].append(link)
                count += 1

        if filtered_entry["Patch Links"] or filtered_entry["Exploit Links"]:
            filtered_data[key] = filtered_entry

    return filtered_data, count

if __name__ == "__main__":
    with open("nvd/final_cves.json", 'r') as f:
        data = json.load(f)
    # domain = "lkml.org"
    # domain = "www.openwall.com"
    domain = "github.com"
    # domain = "bugzilla.redhat.com"
    # domain = "packetstormsecurity.com"
    filtered_data, count = extract_web_links(data, domain)
    # print(json.dumps(filtered_data, indent=4))
    print("CVEs count in filtered data is ", len(filtered_data))
    with open(f'complete_{domain}_links.json', 'w') as f:
        json.dump(filtered_data, f, indent=4)
    print(f"Total count: {count}")