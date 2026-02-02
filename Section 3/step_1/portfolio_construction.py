import json
from pprint import pprint
import sys
import pandas as pd

final_cve_res = {}
output_file = 'final_complete_cve_merged_result.json'

# NVD
with open('nvd/nvd_cve_detail/complete_linux_nvd_cve_dict.json', 'r', encoding='utf-8') as f:
    nvd_cve_details = json.load(f)
    cve_500_ids = list(nvd_cve_details)
    # cve_500_ids = sorted(cve_500_ids)
    # cve_500_ids = cve_500_ids[:5]
    # initialize final cve res
    for cve_id in cve_500_ids:
        final_cve_res[cve_id] = {}


# Red Hat
with open('complete_redhat_cve_dict.json', 'r', encoding='utf-8') as f:
    redhat_cve_details = json.load(f)

with open('complete_nvd_redhat_ubuntu_cve_descriptions.json', 'r', encoding='utf-8') as f:
    all_cve_descriptions = json.load(f)

for cve_id in cve_500_ids:
    final_cve_res[cve_id]['CVE_intrinsic_attributes'] = {}
    final_cve_res[cve_id]['CVE_intrinsic_attributes']['description'] = {}
    final_cve_res[cve_id]['CVE_intrinsic_attributes']['description']['nvd'] = nvd_cve_details[cve_id]['descriptions'][0]['value']
    if cve_id in redhat_cve_details:
        final_cve_res[cve_id]['CVE_intrinsic_attributes']['description']['redhat'] = redhat_cve_details[cve_id]['description']
    if cve_id in all_cve_descriptions and 'ubuntu' in all_cve_descriptions[cve_id]:
        if all_cve_descriptions[cve_id]['ubuntu']['description'] != 'same as nvd':
          final_cve_res[cve_id]['CVE_intrinsic_attributes']['description']['ubuntu'] = all_cve_descriptions[cve_id]['ubuntu']['description']

    final_cve_res[cve_id]['Patch Set'] = all_cve_descriptions[cve_id].get("patch_commit_msg", {})


# 1.2 weakness
"""patc
weakness:
{
    "CVE_intrinsic_attributes": {
        "weakness": {
            "CWE-ID": "123",
            "CWE-Name": "natural language description",
            "CWE-Description": "natural language description",
            "CWE-Extended-Description": "natural language description",
        }
    }
}
"""
for cve_id in cve_500_ids:
    try:
        weaknesses = nvd_cve_details[cve_id]['weaknesses']
        for weakness in weaknesses:
            cwe_ids = weakness['description']
    except KeyError:
        weaknesses = []
    final_cve_res[cve_id]['CVE_intrinsic_attributes']["CWE"] = weaknesses

with open('ubuntu/complete_ubuntu_cve_details.json', 'r', encoding='utf-8') as f:
    ubuntu_cve_details = json.load(f)

for cve_id in cve_500_ids:
    final_cve_res[cve_id]['CVE_intrinsic_attributes']['developer_discussion'] = {}
    if cve_id in ubuntu_cve_details and 'ubuntu_team_notes' in ubuntu_cve_details[cve_id] and ubuntu_cve_details[cve_id]['ubuntu_team_notes']:
        final_cve_res[cve_id]['CVE_intrinsic_attributes']['developer_discussion']['ubuntu'] = {
            "source": "ubuntu",
            "type": "ubuntu_team_notes",
            "value": ubuntu_cve_details[cve_id]['ubuntu_team_notes']
        }

# 1.3.2 Bugzilla Redhat
with open('redhat/redhat-bugzilla/complete_all_bug_info.json', 'r', encoding='utf-8') as f:
    all_bugzilla_redhat_dict = json.load(f)

    for cve_id, bug_info_list in all_bugzilla_redhat_dict.items():
        # there are 10 CVEs that are in bugzill redhat but not from NVD data, so we need to skip them
        # as we do not have any primary information of the CVE
        if cve_id not in cve_500_ids:
            continue

        bugzilla_discussions = []
        for bug_info in bug_info_list:
            comments = bug_info['comments']
            comment_list = []
            for comment in comments:
                comment_list.append({
                    'comment_id': comment['comment_id'],
                    'comment_content': comment['text'],
                    'comment_author': comment['user'],
                    'comment_date': comment['time'],
                })
            bugzilla_discussions.append({
                'bug_id': bug_info.get('url', ''),  # 或者你有 bug_id 字段
                'source': 'redhat',
                'type': 'bugzilla',
                'comments': comment_list,
            })
        if 'developer_discussion' not in final_cve_res[cve_id]['CVE_intrinsic_attributes']:
            final_cve_res[cve_id]['CVE_intrinsic_attributes']['developer_discussion'] = {}
        final_cve_res[cve_id]['CVE_intrinsic_attributes']['developer_discussion']['redhat-bugzilla'] = bugzilla_discussions

# 2. CVE_impact_attributes
for cve_id in cve_500_ids:
    # initialize CVSS
    final_cve_res[cve_id]['CVE_impact'] = {}
    final_cve_res[cve_id]['CVE_impact']['CVSS'] = {}
    # nvd cvss
    final_cve_res[cve_id]['CVE_impact']['CVSS']['nvd'] = nvd_cve_details[cve_id]['metrics']
    # redhat cvss
    if cve_id in redhat_cve_details:
        final_cve_res[cve_id]['CVE_impact']['CVSS']['redhat'] = {
            'cvss_score': redhat_cve_details[cve_id]['cvss_score'],
            'cvss_severity': redhat_cve_details[cve_id]['impact'],
        }
    # ubuntu cvss
    if cve_id in ubuntu_cve_details:
        ubuntu_cvss = {
            'cvss_score': ubuntu_cve_details[cve_id]['cvss_score'],
            'cvss_severity': ubuntu_cve_details[cve_id]['cvss_severity'],
            'ubuntu_priority': ubuntu_cve_details[cve_id]['ubuntu_priority'],
        }
        final_cve_res[cve_id]['CVE_impact']['CVSS']['ubuntu'] = ubuntu_cvss

for cve_id in cve_500_ids:
    final_cve_res[cve_id]['CVE_impact']['CPE'] = {}
    try:
        cpe_config = nvd_cve_details[cve_id]['configurations']
    except KeyError:
        cpe_config = []
    cpe_res = {}
    for nodes in cpe_config:
        nodes = nodes['nodes'][0]
        cpeMatch = nodes['cpeMatch']
        for cpe in cpeMatch:
            cpe_id = cpe['criteria']
            parts = cpe_id.split(':')
            cpe_res[cpe_id] = {
                "cpe": cpe_id,
                'version': f"{parts[0]}{parts[1]}",
                'vendor': parts[3],
                'product': parts[4],
                'product_version': parts[5]
            }
    final_cve_res[cve_id]['CVE_impact']['CPE'] = cpe_res

# 3. Exploit Set
# 3.1 Packetstorm
with open('packetstorm/complete_output.json', 'r') as f:
    packetstorm_info = json.load(f)

map_cve_id_to_packetstorm_fileid = {}
packetstorm_info_dict = {}

for item in packetstorm_info:
    fileid = item['fileid']
    cves = item['cves']
    for cve_id in cves:
        if cve_id not in map_cve_id_to_packetstorm_fileid:
            map_cve_id_to_packetstorm_fileid[cve_id] = []
        if fileid not in map_cve_id_to_packetstorm_fileid[cve_id]:
            map_cve_id_to_packetstorm_fileid[cve_id].append(fileid)
    packetstorm_info_dict[fileid] = item

for cve_id, fileid_list in map_cve_id_to_packetstorm_fileid.items():
    if cve_id not in final_cve_res:
        continue
    final_cve_res[cve_id]['Exploit Set'] = {}
    final_cve_res[cve_id]['Exploit Set']['packetstorm'] = {}
    for fileid in fileid_list:
        packetstorm_info = packetstorm_info_dict[fileid]
        final_cve_res[cve_id]['Exploit Set']['packetstorm'][fileid] = {
            "source": "packetstorm.com",
            "title": packetstorm_info['title'],
            "content": packetstorm_info['content'],
        }

# 4. Patch Set
# 4.1 git kernel patch
# git kernel patch 
with open('git-kernel/complete_git_messages.json', 'r', encoding='utf-8') as f:
    cve_id_and_hash_mapping = json.load(f)

with open("git-kernel/complete_mainline_patches.json", 'r', encoding='utf-8') as f:
    all_mainline_patches = json.load(f)

for cve_id, hash_list in cve_id_and_hash_mapping.items():
    mainline_patch_set = {}
    for hashcode in hash_list:
        key = f"{cve_id}&&{hashcode}"
        if key in all_mainline_patches:
            patch = all_mainline_patches[key]
            commit_hash = patch['Commit Hash']
            mainline_patch_set[commit_hash] = patch
    final_cve_res[cve_id]['Patch Set'] = {}
    final_cve_res[cve_id]['Patch Set']['Details'] = cve_id_and_hash_mapping[cve_id]

# store the result
with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(final_cve_res, f, indent=4, ensure_ascii=False)
print(f"Output saved to {output_file}")

