import json, sys
from pprint import pprint

with open('nvd/nvd_cve_detail/complete_cve_dict_with_links.json', 'r', encoding='utf-8') as f:
    nvd_data = json.load(f)

results = {}

for item in nvd_data.values():
    nvd_description = ""
    cve_id = item.get('id', 'unknown')
    for desc in item.get('descriptions', []):
        if desc.get('lang') == 'en':
            nvd_description = desc.get('value', "")
            results[cve_id] = {
                'nvd': {
                    'description': nvd_description
                }
            }
            break

with open('redhat/redhat-cve-details/complete_redhat_cve_dict.json', 'r', encoding='utf-8') as f:
    redhat_data = json.load(f)

for item in redhat_data.values():
    cve_id = item.get('cve_id', 'unknown')
    description = item.get('description', '')
    prefix = "DescriptionThe CVE Program describes this issue as:"
    if description.startswith(prefix):
        description = description[len(prefix):].strip()
    if cve_id not in results:
        continue
    nvd_desc = results[cve_id]['nvd']['description']

    nvd_desc_no_space = ''.join(nvd_desc.split()) if nvd_desc else ''
    rh_desc_no_space = ''.join(description.split())

    if nvd_desc_no_space == rh_desc_no_space:
        description = "same as nvd"
    
    # --- Additional Info (Bugzilla) Processing ---
    bugzilla_info = None
    additional_info = item.get('additional_info', []) # Get additional_info, default to empty list
    # Ensure additional_info is treated as a list even if it's a string
    if isinstance(additional_info, str):
        additional_info = [additional_info]
    elif not isinstance(additional_info, list):
         additional_info = [] # If it's neither string nor list, ignore

    for info_line in additional_info:
        if isinstance(info_line, str) and info_line.strip().startswith("Bugzilla"):
            bugzilla_info = info_line.strip()
            break # Found the Bugzilla info, no need to check further lines

    # --- Store Results ---
    redhat_res = {
        'description': description
    }
    if bugzilla_info: # Add bugzilla info if found
        redhat_res['additional_info_bugzilla'] = bugzilla_info
    
    results[cve_id]['redhat'] = redhat_res

with open('ubuntu/complete_ubuntu_cve_details.json', 'r', encoding='utf-8') as f:
    ubuntu_data = json.load(f)

for item in ubuntu_data:
    cve_id = item.get('cve_id', 'unknown')
    description = item.get('description', '')
    # ubuntu_note = item.get('ubuntu_team_notes', '')
    if cve_id not in results:
        continue
    nvd_desc = results[cve_id]['nvd']['description']
    # Prepare for comparison: remove all whitespace
    nvd_desc_no_space = ''.join(nvd_desc.split()) if nvd_desc else ''
    ubuntu_desc_no_space = ''.join(description.split())

    if nvd_desc_no_space == ubuntu_desc_no_space:
        description = "same as nvd"
    ubuntu_res = {
        'description': description
    }
    # if ubuntu_note:
    #     ubuntu_res['ubuntu_team_notes'] = ubuntu_note
    results[cve_id]['ubuntu'] = ubuntu_res

import re

def clean_commit_message(message):
    """
    Cleans a git commit message by removing common metadata lines.
    """
    lines = message.splitlines()
    cleaned_lines = []
    # Common metadata prefixes to remove
    metadata_prefixes = (
        "Signed-off-by:",
        "Acked-by:",
        "Reviewed-by:",
        "Tested-by:",
        "Reported-by:",
        "Cc:",
        "Fixes:",
        "Link:",
        "Co-authored-by:",
        "Suggested-by:",
        "Relnotes:", # Sometimes used for release notes
        "Change-Id:", # Gerrit specific
        "cherry picked from commit" # Git specific
    )
    # Regex to match lines like "commit <hash>" or similar patterns often added by git commands
    git_ref_patterns = re.compile(r"^\s*commit\s+[0-9a-f]{40}\s*$", re.IGNORECASE)

    for line in lines:
        stripped_line = line.strip()
        # Check if the line starts with any known metadata prefix
        is_metadata = any(stripped_line.startswith(prefix) for prefix in metadata_prefixes)
        # Check if the line matches git reference patterns
        is_git_ref = git_ref_patterns.match(stripped_line)

        if not is_metadata and not is_git_ref:
            cleaned_lines.append(line) # Keep the original line with its leading/trailing whitespace if it's not metadata

    # Join the cleaned lines back, preserving original line breaks as much as possible
    # If all lines were removed (e.g., only metadata), return an empty string or a placeholder
    cleaned_message = "\n".join(cleaned_lines).strip() # Use strip() at the end to remove leading/trailing whitespace from the whole message
    return cleaned_message if cleaned_message else "[Message content removed as it only contained metadata]"


with open('git-kernel/complete_git_messages.json', 'r', encoding='utf-8') as f:
    git_commit_diffs_top500 = json.load(f)
    hash_to_commit_msg = {}
    for item in git_commit_diffs_top500.keys():
        # if item['CVE ID'] not in results:
        #     continue
        if item not in results:
            continue
        # cve_id = item['CVE ID']
        cve_id = item
        results[cve_id]['patch_commit_msg'] = {}
        commits = git_commit_diffs_top500[cve_id]
        commit_messages = []

        for item in commits.values():
            commit_hash = item["commit_info"]['Commit Hash']
            commit_msg = item["commit_info"]['Message']
            author = item["commit_info"]["Author"]
            cleaned_message = clean_commit_message(commit_msg) 
            url = item["url"]
            mod_file_names = item["commit_info"]["Changed Files Name"]
            mod_file = item["commit_info"]["Changed Files"]
            code_diff = item["commit_info"]["Code Diff"]
            files_before_fix = item["commit_info"].get("Files Before Fix", "")

            required_item = {
                'cve_id': cve_id,
                'url': url,
                "Author": author,
                "commit_hashes": list(commits.keys()),
                "mod_file_names": mod_file_names,
                'commit_msg': cleaned_message,
                "mod_files": mod_file,
                "code_diff" : code_diff,
                "Before fix": files_before_fix
            }
            # hash_to_commit_msg[item['Commit Hash']] = required_item
            results[cve_id]['patch_commit_msg'][commit_hash] = required_item


path_to_save = 'final_complete_nvd_redhat_ubuntu_cve_descriptions.json'
with open(path_to_save, 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=4, ensure_ascii=False)

