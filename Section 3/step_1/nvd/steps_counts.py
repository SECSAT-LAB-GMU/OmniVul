import json

with open("nvd_cve_detail/complete_nvd_cve_dict.json", 'r') as f:
    data = json.load(f)

print("Total NVD data downloaded off the NVD website", len(data))

with open('nvd_cve_detail/complete_linux_nvd_cve_dict.json', 'r') as f:
    data = json.load(f)

print("Total NVD data downloaded off the NVD website per year that belong to linux", len(data))

# load the cves in "linux_cves_with_links.txt" and present the count
with open('linux_cves_with_links.txt', 'r') as f:
    cves_with_links = f.readlines()
cves_with_links = [cve.strip() for cve in cves_with_links]
print("Total number of CVEs with exploit links: ", len(cves_with_links))


# writing the unique CVEs to a text file
linux_cve_dict_with_links = {cve: data[cve] for cve in cves_with_links if cve in data}
print("Total number of CVEs with exploit links that are also in the NVD data: ", len(linux_cve_dict_with_links))

# write linux_cve_dict_with_links to a json file
with open('nvd_cve_detail/linux_cve_dict_with_links.json', 'w') as f:
    json.dump(linux_cve_dict_with_links, f, indent=4)

