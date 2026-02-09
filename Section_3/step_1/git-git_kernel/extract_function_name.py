import json
import re
from typing import Dict, Set, Optional, List


def extract_function_name_from_hunk_context_line(context_line: str) -> Optional[str]:
    """
    Attempt to extract C function name from the context part of hunk header.
    Example: "@@ -10,7 +10,7 @@ static void my_function(int arg) {" -> "my_function"
    """
    context_line = context_line.strip()

    # If there's a {, the function signature is usually before {
    if '{' in context_line:
        context_line = context_line.split('{', 1)[0].strip()

    # Simple regex to try matching function name (a word followed by '(')
    # It tries to handle possible types, static, pointers, etc. before
    # (?:[\w\s\*]+\s+)?  -> Match optional return type and modifiers (like "static void * ")
    # ([a-zA-Z_][\w]*)   -> Capture function name (starts with letter or underscore, followed by letters, digits, underscores)
    # \s*\(              -> Match optional spaces and left parenthesis
    match = re.search(r"(?:[\w\s\*]+\s+)?([a-zA-Z_][\w]*)\s*\((?:[^)]*\))?", context_line)
    if match:
        function_name = match.group(1)
        # Avoid some common C keywords being incorrectly identified as function names
        c_keywords_not_funcs = {"if", "for", "while", "switch", "sizeof", "return", "case", 
                               "else", "do", "break", "continue", "goto", "typedef", "struct", 
                               "union", "enum", "const", "static", "extern", "inline", "volatile"}
        if function_name and function_name not in c_keywords_not_funcs:
            return function_name
    return None

def extract_c_function_name_from_hunk_context(context_line: str) -> Optional[str]:
    """
    Attempt to extract C function name from the context part of hunk header,
    capable of handling patterns like do_##name.
    """
    context_line = context_line.strip()

    # Remove line comments /* ... */ or // ... (simplified handling)
    context_line = re.sub(r'/\*.*?\*/', '', context_line)
    context_line = re.sub(r'//.*', '', context_line)
    context_line = context_line.strip()

    # If there's a {, the function signature is usually before {
    if '{' in context_line:
        context_line = context_line.split('{', 1)[0].strip()
    
    # Avoid matching #define macro definition lines (even if they might look like functions)
    if context_line.startswith("#define"):
        return None

    # Simple regex to try matching function name (a word followed by '(')
    # It tries to handle possible types, static, pointers, etc. before
    # (?:[\w\s\*]+\s+)?  -> Match optional return type and modifiers (like "static void * ")
    # ([a-zA-Z_][\w]*)   -> Capture function name (starts with letter or underscore, followed by letters, digits, underscores)
    # \s*\(              -> Match optional spaces and left parenthesis
    # match = re.search(r"(?:[\w\s\*]+\s+)?([a-zA-Z_][\w]*)\s*\((?:[^)]*\))?", context_line)
    match = re.search(
        r"(?:[\w\s\*&]+\s+)?([a-zA-Z_][\w]*(?:##[a-zA-Z_][\w]*)?)\s*\(", 
        context_line
    )
    if match:
        function_name = match.group(1)
        # Avoid some common C keywords being incorrectly identified as function names
        c_keywords_not_funcs = {"if", "for", "while", "switch", "sizeof", "return", "case", 
                               "else", "do", "break", "continue", "goto", "typedef", "struct", 
                               "union", "enum", "const", "static", "extern", "inline", "volatile"}
        is_potentially_macro_name = "##" in function_name
        if function_name and function_name not in c_keywords_not_funcs and (not function_name.isupper() or is_potentially_macro_name):
            return function_name
    return None

def parse_diff_for_impacted_functions(code_diff_str: str) -> Dict[str, List[str]]:
    """
    Parse 'Code Diff' string (unified diff format) and extract file names
    and potential C function names from hunk headers.

    Returns a dictionary where key is file name and value is a sorted list of affected C function names in that file.
    """
    impacted_locations: Dict[str, Set[str]] = {}
    current_file_path: Optional[str] = None
    lines = code_diff_str.splitlines()

    for line in lines:
        if line.startswith("diff --git a/"):
            path_parts = line.split(" ")
            if len(path_parts) >= 4:
                file_path_b = path_parts[3]
                current_file_path = file_path_b[2:] if file_path_b.startswith("b/") else file_path_b
                if current_file_path not in impacted_locations:
                    impacted_locations[current_file_path] = set()

                if current_file_path.endswith(".h") or current_file_path.endswith(".S"):
                    # file_basename = current_file_path.split("/")[-1]
                    impacted_locations[current_file_path].add(current_file_path)
            else:
                current_file_path = None # Reset

        elif line.startswith("@@ ") and current_file_path and \
             current_file_path.endswith(".c"): # Only process C files
            try:
                hunk_header_content_start_index = line.find("@@", line.find("@@") + 2) + 2
                if hunk_header_content_start_index > 1:
                    context_text = line[hunk_header_content_start_index:].strip()
                    function_name = extract_c_function_name_from_hunk_context(context_text)
                    if function_name:
                        impacted_locations[current_file_path].add(function_name)
            except Exception:
                pass # Ignore errors in parsing hunk header

    cleaned_locations: Dict[str, List[str]] = {}
    for file_path, functions_set in impacted_locations.items():
        if functions_set:
            cleaned_locations[file_path] = sorted(list(functions_set))
            
    return cleaned_locations

def main_step1_extract_function_names_from_diffs(cve_data_full: Dict, output_json_path: str):
    """
    Main function: Process loaded complete CVE data, extract affected files and C function names from diff in each commit,
    and save to specified JSON file.
    """
    all_vulnerable_locations: Dict[str, Dict[str, Dict[str, List[str]]]] = {}

    print("Starting to extract affected files and function names from Code Diff...")
    for cve_id, commits_data in cve_data_full.items():
        if not isinstance(commits_data, dict):
            # print(f"Info: CVE {cve_id} commits_data format is incorrect, skipped.")
            continue
        
        cve_specific_locations: Dict[str, Dict[str, List[str]]] = {}
        for commit_hash, commit_details in commits_data.items():
            if not isinstance(commit_details, dict):
                # print(f"Info: CVE {cve_id}, Commit {commit_hash} commit_details format is incorrect, skipped.")
                continue

            print(f"Processing: CVE {cve_id}, Commit {commit_hash}")
            commit_info = commit_details.get("commit_info")
            code_diff_str = commit_info.get("Code Diff")
            
            if code_diff_str:
                impacted_functions_by_file = parse_diff_for_impacted_functions(code_diff_str)
                if impacted_functions_by_file:
                    cve_specific_locations[commit_hash] = impacted_functions_by_file
                else:
                    # Even if no functions, record that this commit was processed (if needed)
                    # cve_specific_locations[commit_hash] = {} 
                    print(f"  -> No C function names identified from hunk headers in {commit_hash} diff.")
            else:
                print(f"  -> 'Code Diff' information not found: CVE {cve_id}, Commit {commit_hash}")
        
        if cve_specific_locations:
            all_vulnerable_locations[cve_id] = cve_specific_locations

    try:
        with open(output_json_path, "w", encoding="utf-8") as out_f:
            json.dump(all_vulnerable_locations, out_f, indent=4, ensure_ascii=False)
        print(f"\nExtracted affected function locations successfully saved to: {output_json_path}")
    except IOError as e:
        print(f"\nError: Unable to write to output file {output_json_path}. Error message: {e}")
    except Exception as e:
        print(f"\nUnknown error occurred while saving output: {e}")

    return all_vulnerable_locations


if __name__ == "__main__":
    input_json_file = "complete_git_messages.json"

    output_json_file_step1 = "complete_step1_impacted_functions_from_diff.json"

    print(f"Input file: {input_json_file}")
    print(f"Step 1 output file: {output_json_file_step1}")

    # Ensure file exists
    with open(input_json_file, "r", encoding="utf-8") as f:
        cve_data = json.load(f)
    print(f"\nSuccessfully loaded file: {input_json_file}")

    # Execute step 1: Extract function names from diff
    main_step1_extract_function_names_from_diffs(cve_data, output_json_file_step1)