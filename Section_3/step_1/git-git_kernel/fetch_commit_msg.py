import subprocess
import json
from tqdm import tqdm
import sys
"""
Fetch commit message from repo (linux-stable-full)
This repo is downloaded from https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
"""

# Define Linux stable repo path (fully cloned repo)
LINUX_REPO_PATH = "linux-stable-full"

input_json = "complete_references/nvd-git-kernel-commit-hashes.json"
with open(input_json, "r", encoding="utf-8") as f:
    cve_commit_mapping = json.load(f)

references_json = "complete_references/nvd-git-kernel-references.json"
with open(references_json, "r", encoding="utf-8") as f:
    cve_url_mapping = json.load(f)

# Store results
commit_results = {}
failed_commits = {}

def get_commit_info(commit_hash):
    """Use multiple Git commands to get complete commit information"""
    try:
        # Get basic commit information
        cmd_log = ["git", "log", "-1", "--pretty=format:COMMIT_HASH:%H%nAUTHOR:%an <%ae>%nDATE:%ad%nMESSAGE:%B", commit_hash]
        result_log = subprocess.run(cmd_log, cwd=LINUX_REPO_PATH, capture_output=True, text=True)

        # Get list of modified files and their status
        cmd_files = ["git", "show", "--name-status", "--pretty=format:", commit_hash]
        result_files = subprocess.run(cmd_files, cwd=LINUX_REPO_PATH, capture_output=True, text=True)

        # Get code changes diff
        cmd_diff = ["git", "diff", f"{commit_hash}^!", "--unified=5"]
        result_diff = subprocess.run(cmd_diff, cwd=LINUX_REPO_PATH, capture_output=True, text=True)

        if result_log.returncode != 0:
            print(f"❌ Failed to process commit {commit_hash}")
            return None

        commit_data = parse_commit_info(result_log.stdout, result_files.stdout, result_diff.stdout)
        return commit_data

    except Exception as e:
        print(f"❌ Failed to process commit {commit_hash}: {e}")
        return None

def get_file_content_after_fix(commit_hash, filename):
    """Get complete code content after the commit"""
    try:
        cmd = ["git", "show", f"{commit_hash}:{filename}"]
        result = subprocess.run(cmd, cwd=LINUX_REPO_PATH, capture_output=True, text=True)

        if result.returncode == 0:
            return result.stdout
        else:
            return "⚠️ Unable to retrieve file, it may have been deleted."
    except Exception as e:
        return f"❌ File retrieval failed: {e}"

def get_file_content_before_fix(commit_hash, filename):
    """Get code content before the commit (parent commit version)"""
    try:
        # Use commit_hash^ to represent parent commit
        cmd = ["git", "show", f"{commit_hash}^:{filename}"]
        result = subprocess.run(cmd, cwd=LINUX_REPO_PATH, capture_output=True, text=True)

        if result.returncode == 0:
            return result.stdout
        else:
            return "⚠️ Unable to retrieve file before fix, it may not have existed."
    except Exception as e:
        return f"❌ File retrieval failed: {e}"

def parse_commit_info(commit_log, file_changes, commit_diff):
    """Parse Git commit information and store it in structured format"""
    lines = commit_log.split("\n")
    commit_data = {
        "Commit Hash": None,
        "Author": None,
        "Date": None,
        "Message": "",
        "Changed Files Name": [],
        "Changed Files": {},
        "Files Before Fix": {},
        "Code Diff": commit_diff
    }

    # Parse commit metadata
    for line in lines:
        if line.startswith("COMMIT_HASH:"):
            commit_data["Commit Hash"] = line.replace("COMMIT_HASH:", "").strip()
        elif line.startswith("AUTHOR:"):
            commit_data["Author"] = line.replace("AUTHOR:", "").strip()
        elif line.startswith("DATE:"):
            commit_data["Date"] = line.replace("DATE:", "").strip()
        elif line.strip() and not line.startswith("MESSAGE:"):
            commit_data["Message"] += line.strip() + "\n"

    # Parse modified files
    changed_files = file_changes.strip().split("\n")
    for file_line in changed_files:
        if file_line.strip():
            status, file_name = file_line.split("\t")
            print(file_name)
            commit_data["Changed Files Name"].append(file_name)
            commit_data['Files Before Fix'][file_name] = get_file_content_before_fix(commit_data["Commit Hash"], file_name)
            commit_data["Changed Files"][file_name] = get_file_content_after_fix(commit_data["Commit Hash"], file_name)

    return commit_data

for cve_id, commit_hashes in tqdm(cve_commit_mapping.items(), total=len(cve_commit_mapping), desc="Processing Commits"):
    for commit_hash in commit_hashes:
        commit_info = get_commit_info(commit_hash)
        if commit_info:
            # construct url
            url = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=" + commit_hash
            if cve_id not in commit_results:
                commit_results[cve_id] = {}
            commit_results[cve_id][commit_hash] = {
                'cve_id': cve_id,
                'url': url,
                'commit_info': commit_info
            }
        else:
            if cve_id not in failed_commits:
                failed_commits[cve_id] = []
            failed_commits[cve_id].append(commit_hash)

# Save successful commit code changes to JSON
output_json = "complete_git_messages.json"
print("Length of commit results:", len(commit_results))


with open(output_json, "w", encoding="utf-8") as f:
    json.dump(commit_results, f, ensure_ascii=False, indent=4)

# Save failed commits
failed_json = "complete_failed_git_kernel_hashes.json"
with open(failed_json, "w", encoding="utf-8") as f:
    json.dump(failed_commits, f, ensure_ascii=False, indent=4)

# Print statistics
print(f"✅ Successfully extracted {len(commit_results)} commit records. Saved to: {output_json}")
print(f"⚠️ Failed to extract {len(failed_commits)} commit records. Saved to: {failed_json}")
