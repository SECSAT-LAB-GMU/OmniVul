import json
import os
import subprocess
import tempfile
import re
from typing import Dict, List, Optional, Any

# --- Configuration ---
TARGET_FUNCTIONS_JSON_PATH = "complete_step1_impacted_functions_from_diff.json"

FULL_CVE_DATA_JSON_PATH = "complete_git_messages.json"

OUTPUT_FUNCTION_BODIES_JSON_PATH = "complete_step2_vulnerable_function_bodies.json"


# Command for Universal Ctags. 
CTAGS_COMMAND = "ctags"

def run_ctags(file_content: str, temp_file_suffix: str = ".c") -> Optional[str]:
    """
    Runs Universal Ctags on the given file content saved to a temporary file.
    Returns the ctags output string if successful, None otherwise.
    """
    try:
        with tempfile.NamedTemporaryFile(mode="w+", suffix=temp_file_suffix, delete=False, encoding='utf-8') as tmp_f:
            tmp_f.write(file_content)
            temp_file_path = tmp_f.name
        

        cmd = [
            CTAGS_COMMAND,
            "--fields=+neKSE", 
            "--languages=C",
            "--kinds-C=f", 
            "-o", "-",  # Output to stdout
            temp_file_path
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, encoding='utf-8')
        
        if result.returncode != 0:
            # ctags might return non-zero if no tags are found, which isn't always an "error" for us
            # but good to log if there's actual stderr output
            if result.stderr:
                print(f"  [CTAGS Warning/Error for {os.path.basename(temp_file_path)}]: {result.stderr.strip()}")
        return result.stdout # Return stdout even if returncode is non-zero, as it might contain some tags

    except FileNotFoundError:
        print(f"  [Error] ctags command '{CTAGS_COMMAND}' not found. Please ensure Universal Ctags is installed and in PATH.")
        return None
    except Exception as e:
        print(f"  [Error] Exception while running ctags on a temporary file: {e}")
        return None
    finally:
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            os.remove(temp_file_path)

def parse_ctags_output_for_function(ctags_output: str, target_function_name: str, original_file_path_for_tag: str) -> Optional[Dict[str, int]]:
    """
    Parses ctags output to find the start and end line for a specific function.
    original_file_path_for_tag is the basename that ctags will use in its output.
    Returns a dict {'start': line_num, 'end': line_num} or None.
    Line numbers are 1-based.
    """
    for line in ctags_output.splitlines():
        parts = line.split('\t')
        if not parts:
            continue
        
        name_from_tag = parts[0]
        # file_from_tag = parts[1] # ctags output uses the temp file name here

        if name_from_tag == target_function_name:
            start_line, end_line = -1, -1
            for field in parts:
                if field.startswith("line:"):
                    try:
                        start_line = int(field.split(":")[1])
                    except ValueError:
                        pass
                elif field.startswith("end:"):
                    try:
                        end_line = int(field.split(":")[1])
                    except ValueError:
                        pass
            
            if start_line != -1 and end_line != -1:
                return {"start": start_line, "end": end_line}
            elif start_line != -1: # Only start line found (maybe not Universal Ctags or not a function with end)
                 print(f"  [Warning] Found function '{target_function_name}' but missing end line in ctags output. Start: {start_line}")
                 # Optionally, you could fall back to brace counting from here
                 return {"start": start_line, "end": -1} # Mark end as unknown
    return None


def extract_function_body(file_content_lines: List[str], start_line: int, end_line: int) -> Optional[str]:
    """
    Extracts function body from file_content_lines (0-based list) 
    using 1-based start_line and end_line from ctags.
    """
    if not (0 < start_line <= end_line <= len(file_content_lines)):
        if start_line > 0 and end_line == -1 and start_line <= len(file_content_lines): # Only start line is known
            # Fallback: Try to find end by brace counting from start_line
            # This is a simplified brace counter and might not be robust for all C code
            print(f"    Attempting brace counting from line {start_line}...")
            body_lines = []
            brace_level = 0
            first_brace_found = False
            for i in range(start_line - 1, len(file_content_lines)):
                line_text = file_content_lines[i]
                body_lines.append(line_text)
                
                # Very basic handling of comments and strings to avoid counting braces inside them
                line_to_check_braces = re.sub(r"//.*", "", line_text) # Remove // comments
                line_to_check_braces = re.sub(r"/\*.*?\*/", "", line_to_check_braces) # Remove /* ... */ comments
                line_to_check_braces = re.sub(r'".*?"', '', line_to_check_braces) # Remove string literals
                line_to_check_braces = re.sub(r"'.*?'", '', line_to_check_braces) # Remove char literals

                open_braces = line_to_check_braces.count('{')
                close_braces = line_to_check_braces.count('}')
                
                if open_braces > 0:
                    first_brace_found = True
                
                brace_level += open_braces
                brace_level -= close_braces
                
                if first_brace_found and brace_level == 0:
                    return "\n".join(body_lines)
            return None # Brace counting failed to find a balanced end

        print(f"  [Error] Invalid line numbers for extraction: start={start_line}, end={end_line}, total_lines={len(file_content_lines)}")
        return None
    
    # Extract lines (0-based index for list, 1-based for ctags lines)
    return "\n".join(file_content_lines[start_line-1 : end_line])


def process_files_to_extract_bodies(
    target_functions_data: Dict, 
    full_cve_data: Dict
) -> Dict:
    """
    Main processing function.
    Iterates through target functions and extracts their bodies from "Files Before Fix".
    """
    extracted_function_bodies: Dict[str, Any] = {}

    for cve_id, commits in target_functions_data.items():
        if cve_id not in full_cve_data:
            print(f"  [Skipping] CVE ID {cve_id} not found in full_cve_data.")
            continue
        
        extracted_function_bodies.setdefault(cve_id, {})
        
        for commit_hash, files_and_funcs in commits.items():
            if commit_hash not in full_cve_data[cve_id]:
                print(f"  [Skipping] Commit {commit_hash} for CVE {cve_id} not found in full_cve_data.")
                continue
            
            commit_data_full = full_cve_data[cve_id][commit_hash]['commit_info']
            files_before_fix_map = commit_data_full.get("Files Before Fix", {})
            
            if not files_before_fix_map:
                print(f"  [Skipping] No 'Files Before Fix' data for CVE {cve_id}, Commit {commit_hash}.")
                continue

            extracted_function_bodies[cve_id].setdefault(commit_hash, {})

            for file_path, function_names in files_and_funcs.items():
                print(f"Processing File: {file_path} for CVE {cve_id}, Commit {commit_hash}")
                
                file_content_before_fix = files_before_fix_map.get(file_path)
                
                if not file_path.endswith(".c"):
                    print(f"  [Info] Non-.c file: {file_path} - using entire file content")
                    extracted_function_bodies[cve_id][commit_hash][file_path] = {
                        func_name: file_content_before_fix for func_name in function_names
                    }
                    continue
            
                if not file_content_before_fix:
                    print(f"  [Warning] No 'File Before Fix' content for {file_path} in CVE {cve_id}, Commit {commit_hash}.")
                    extracted_function_bodies[cve_id][commit_hash][file_path] = {
                        func_name: "File content before fix not found." for func_name in function_names
                    }
                    continue

                extracted_function_bodies[cve_id][commit_hash].setdefault(file_path, {})
                
                # It's more efficient to run ctags once per file content
                ctags_raw_output = run_ctags(file_content_before_fix, os.path.splitext(file_path)[1])
                
                if ctags_raw_output is None:
                    print(f"  [Error] Ctags execution failed for content of {file_path}.")
                    for func_name in function_names:
                         extracted_function_bodies[cve_id][commit_hash][file_path][func_name] = "Ctags execution failed."
                    continue

                file_content_lines = file_content_before_fix.splitlines()

                for target_func_name in function_names:
                    print(f"  Attempting to extract: {target_func_name}")
                    
                    # Note: ctags uses the temporary filename in its output, not original_file_path.
                    # For simplicity in parsing, we just look for target_func_name.
                    # A more robust parser would confirm the file field in ctags output if parsing a whole project's tags file.
                    # Here, we run ctags on a single temp file, so the file field is less critical for disambiguation.
                    func_location = parse_ctags_output_for_function(ctags_raw_output, target_func_name, os.path.basename(file_path))
                    
                    if func_location:
                        body = extract_function_body(file_content_lines, func_location["start"], func_location["end"])
                        if body:
                            extracted_function_bodies[cve_id][commit_hash][file_path][target_func_name] = body
                            print(f"    Successfully extracted '{target_func_name}' ({len(body.splitlines())} lines)")
                        else:
                            extracted_function_bodies[cve_id][commit_hash][file_path][target_func_name] = f"Failed to extract body for '{target_func_name}' after ctags locate."
                            print(f"    Failed to extract body for '{target_func_name}' after ctags locate (start:{func_location['start']}, end:{func_location['end']}).")
                    else:
                        # This case will be hit for names like "do_##name" as ctags won't find them literally.
                        # It will also be hit if the function name from diff hunk was not a real, parsable function.
                        # extracted_function_bodies[cve_id][commit_hash][file_path][target_func_name] = f"Function '{target_func_name}' not found by ctags or end line missing."
                        print(f"    Function '{target_func_name}' not found by ctags or end line missing.")
                        extracted_function_bodies[cve_id][commit_hash][file_path][target_func_name] = file_content_before_fix
                        
    return extracted_function_bodies

if __name__ == "__main__":
    print(f"Loading target functions from: {TARGET_FUNCTIONS_JSON_PATH}")
    try:
        with open(TARGET_FUNCTIONS_JSON_PATH, "r", encoding="utf-8") as f:
            targets = json.load(f)
    except FileNotFoundError:
        print(f"Error: Target functions file not found at '{TARGET_FUNCTIONS_JSON_PATH}'")
        exit(1)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from '{TARGET_FUNCTIONS_JSON_PATH}': {e}")
        exit(1)

    print(f"Loading full CVE data from: {FULL_CVE_DATA_JSON_PATH}")
    try:
        with open(FULL_CVE_DATA_JSON_PATH, "r", encoding="utf-8") as f:
            cve_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: Full CVE data file not found at '{FULL_CVE_DATA_JSON_PATH}'")
        exit(1)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from '{FULL_CVE_DATA_JSON_PATH}': {e}")
        exit(1)
    
    print("\nStarting function body extraction process...")
    results = process_files_to_extract_bodies(targets, cve_data)

    print(f"\nSaving extracted function bodies to: {OUTPUT_FUNCTION_BODIES_JSON_PATH}")
    try:
        with open(OUTPUT_FUNCTION_BODIES_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print("Extraction complete. Results saved.")
    except Exception as e:
        print(f"Error saving results to JSON: {e}")