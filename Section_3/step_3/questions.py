# ఈ file లో మనకి RAG కి వాడాలిసిన INSTRUCTIONs మరియు వాటి query prompts ఉన్నాయి 
# వాటితో పాటు మనం చివరిలో రాయవలసిన QA జెంటాల ప్రశ్న స్మాహారమును కూడా ఇక్కడ నిక్షిప్తం చేయటం అయినది 

INSTRUCTIONS_DICT = {
    "Function name": """
        Steps to extract the vulnerable function name:
        1. Scan the context for any function definitions, names, or mentions.
        2. Identify functions that are directly described as being vulnerable or involved in the vulnerability.
        3. If multiple functions are mentioned, select the one most clearly labeled as vulnerable.
        4. Use the function name exactly as it appears in the text, including punctuation or formatting.
        - If no function is mentioned, respond with "Not found".

        Do Not:
        - Do not make any assumptions or guesses.
        - Do not infer based on naming conventions or surrounding text.
        - Only respond if the function name is explicitly mentioned in the context.
        - If multiple functions are listed, identify only the one clearly associated with the vulnerability.
    """,
    "File name" : """
        Steps to identify the vulnerable file name:
        1. Read the entire context for file paths or filenames with standard extensions such as .c, .cpp, .py, .java, .h, etc.
        2. Determine whether the file is explicitly identified as containing the vulnerable code, such as being mentioned in a call stack, warning, backtrace, or security note.
        3. Extract the complete path of the vulnerable file(s) exactly as written in the context.
        - If no such file is mentioned, respond with: "Not Found".

        Do not:
        - Do not make any assumptions or guesses about the file name.
        - Do not mistake exploit, PoC, demo, or test code file names with the vulnerable file names.
        - Do not infer based on similar naming, project structure, or typical file organization.
        - If multiple source files are clearly identified as containing vulnerable logic, return all of them.
    """,

    "Vulnerable OS component": """
        Steps to extract the vulnerable operating system component:
        1. Read through the context and Look for explicit statements identifying a kernel subsystem, component names (e.g., memory manager, syscall handler, networking stack, netfilter), file names or file paths.
        2. Identify any such component that is explicitly associated with the vulnerability.
        3. Extract any folder paths or file names that are representative of the vulnerable OS component
        4. If the context uses vague terms like "kernel bug" or "low-level behavior" without naming a component, ignore them.
        - If no such component is mentioned, respond with: "Not Found".

        Do not:
        - Do not make any assumptions about the OS component based on the type of vulnerability.
        - Do not infer based on general knowledge
        - If multiple components are mentioned, identify only the one directly tied to the vulnerability.
    """,
    "Weakness Type": """
        Steps to extract the weakness type:
        1. Read the context and locate any statement that names the vulnerability type or categorizes its technical nature (e.g., buffer overflow, integer truncation, TOCTOU race).
        2. Match the terminology with common CVE/CWE categories if the name is clearly stated.
        3. Ignore discussions of exploit behavior or consequences if they do not name a specific vulnerability type.
        4. If multiple types are listed, select all the ones that are clearly linked to the vulnerable condition.
        - If the weakness type is not clearly stated, respond with: "Not found".

        Constraints:
        - Do not make any assumptions or guesses.
        - Do not infer the weakness type based on general vulnerability descriptions or CWE IDs unless it is explicitly labeled or stated.
        - Only respond if the type of weakness is clearly mentioned in the context (e.g., "buffer overflow", "use-after-free", etc.).
        - Do not convert technical details into a weakness category unless the mapping is explicitly provided.
    """,

    "root_cause": """
        Steps to extract the root cause of the vulnerability:
        1. Identify statements that describe why the vulnerability exists at a technical level.
        2. Focus on flaws in logic, design, or implementation that enable the vulnerability.
        3. Extract language that explicitly identifies the root issue (e.g., "The bug occurs due to...", "This is caused by...").
        - If no root cause is given, respond with "Not found".

        Do not:
        - Do not speculate or generalize causes.
        - Only extract if the explanation is clearly stated in the context.
    """,

    "secure_coding_violation": """
        Steps to extract secure coding violations:
        1. Go through the provided vulnerable source code and any function snippet and explain the potential secure programming violation in it. 
        1. Look for mentions of programming practices that are labeled as unsafe or violating best practices.
        2. Identify references such as missing validation, unsafe memory use, or incorrect error handling.
        3. Extract the practice or pattern that violates secure coding principles.
        - If no violation is stated, respond with: "Not found".

        Constraints:
        - Avoid extracting based solely on general coding quality.
    """,

    "mitigation": """
        Steps to extract mitigation strategies:
        1. Identify configuration changes, access controls, or patches intended to prevent exploitation.
        Look for any script, command, or tool (e.g., SystemTap) related to mitigation.
        2. Extract the sequence of actions described to apply the mitigation.
        3. Note any stated limitations or affected system behaviors.
        4. Summarize the purpose of any code snippets, especially `.stp` files or probes.
        - If not mentioned, respond with: "Not found".

        Constraints:
        - Do not create mitigation strategies.
        - Only report if the mitigation is clearly stated.
        - If mitigation is stated to be incomplete or partial, mention that.
    """, 

    "Exploit Code": """
    Steps:
    1. Scan the context for any code blocks, typically enclosed in backticks, indentation, or starting with known patterns like `#include`, `int main()`, or `#!/bin/bash`.
    2. Confirm that the code is specifically intended as an exploit or Proof of Concept (PoC) by checking if it's labeled as such.
    3. Extract the code block exactly as written, preserving its formatting, indentation, and syntax.
    4. If only part of the code is available, extract only the part shown. Do not complete or guess the missing portions.
    5. If no code is included, leave the field empty with: `Not found`.

    Constraints:
    - Do not extract explanatory text, comments, or narrative outside the code block.
    - Do not infer or synthesize code that is not explicitly shown.
    - Do not convert descriptive steps into code.
    """,

    "remote_exploitability": """

    Steps:
        1. Look for CVSS v2 (`accessVector`) or CVSS v3 (`attackVector`) fields.
        2. Explain what the access vector means in technical terms:
        - For example, "accessVector: LOCAL" means the attacker needs direct access to the system.
        - "NETWORK" means it can be exploited over a network connection.
        3. Also examine the context for phrases like:
        - "can be triggered remotely"
        - "requires physical access"
        - "can be exploited via network"
        - "local privilege escalation", etc.
        4. Based on the above, write a concise sentence:
        - Start with what the accessVector says and is it remotely exploitable.
        If no specific detail was found, respoind with "Not found"

        Constraints:
        - Do not speculate or infer beyond the provided context.
        - Only include facts present in the context.
        - Maintain a formal, technical tone.
    """,

    "cia_impact": """
        Steps to extract CIA (Confidentiality, Integrity, Availability) impact:
        1. Search for phrases that indicate how the vulnerability affects system security.
        2. Extract explicit statements about compromise to confidentiality, integrity, or availability.
        3. Include all three dimensions when stated.
        - If not explicitly described, respond with: "Not found".

        Constraints:
        - Do not assume impact based on vulnerability type.
        - Do not infer the impact based on the exlpoit code or uulnerability code
    """,

    "exploit_expl": """
        Steps to extract exploit explanation:
        1. Identify how the vulnerability is triggered and leveraged to gain control or access.
        2. Extract procedural or descriptive content detailing the attack.
        3. Detail how the exploit is executed and what component / vulnerability is leveraged in order to successfully exploit the vulnerability
        - If not found, respond with: "Not found".
        
        Constraints:
        - Do not invent exploitation methods.
        - Use only information presented in the context.
    """,

    "abusable_interfaces": """
    Steps to extract abusable kernel interfaces or components:

    1. Identify the kernel subsystems, device drivers, kernel modules, or hardware interfaces directly involved in the vulnerability.
    2. Look for directory paths or file paths in the kernel source tree (e.g., drivers/block/xen-blkback/blkback.c).
    3. Extract interface names such as Xen blkback, netfilter, eBPF, TTY, io_uring, etc.
    4. Only report components that are explicitly mentioned in the context as related to the vulnerability or exploited behavior.
    - If none are found, respond with: “Not found.”

    Constraints:
    - Do not list function names unless they are clearly identified as interfaces (e.g., syscalls).
    - Do not infer component names; only use what is present in the context.
    """,

    "privs_req" : """
        Steps to extract required privileges:
        1. From the CVSS, CPE scores and provided information, extract what level of system access is needed to exploit the vulnerability.
        2. Identify if root, user, admin, or kernel-level access is required to exploit this vulnerability.
        3. Extract the privilege level as written.
        - If none are stated, respond with: "Not found".

        Constraints:
        - Do not infer from code or typical behavior or weakness types.
    """,

    "exploited_versions": """
    Steps:
    1. Scan for CPE entries or textual references to affected kernel or OS versions.
    2. Extract version strings exactly as written, including build/release numbers if present.
    3. Identify vendor+product+version when possible (e.g., "Ubuntu 20.04 LTS").
    4. Avoid interpreting or completing partial version info.
    5. If no version information is found, return "Not found". 

    Constraints:
    - **Do not guess** version ranges from patch notes or context.
    - Only include versions that are clearly associated with the vulnerability.
    - Ignore fixed versions — only extract affected ones.
    """,

    "abusable_interfaces": """
    Steps:
        1. Look for specific system calls (e.g., `ptrace`, `ioctl`, `clone`) or kernel subsystems mentioned in the exploit or cause analysis.
        2. Identify components such as `/proc`, `/sys`, or device nodes like `/dev/kmem`, if present.
        3. Include only those interfaces that are mentioned in connection with triggering the vulnerability.
        4. If no specific information is found, return with "Not found".

    Constraints:
        - Do not list interfaces generically (e.g., "kernel API") unless explicitly named.
        - If multiple interfaces are mentioned, list all those that are directly related to the vulnerability trigger or exploit path.
        - Do not confuse system interfaces with function names and prototypes
    """,

    "exploit_privs": """
        Steps to extract post-exploit privilege level:
        1. Understand the context and identify the access level gained after successful exploitation (e.g., file system, root ...).
        2. detail the privilage level that can be gained after a successful exploittation.
        - If no outcome is described, respond with: "Not found".

        Constraints:
        - Do not assume or infer based on any information provided.
    """,

    "privs_req": """
        Steps:
        1. Look for privilege levels such as: root, CAP_* capabilities, user-level, unprivileged, etc.
        2. Extract the exact privilege description mentioned, if present.
        3. If multiple privilege levels are discussed, extract all the ones that are tied to the initial exploit.
        4. If no information is found, return with Not found. 
        
        Constraints:
        - Do not assume based on the type of vulnerability.
        - Do not infer from affected components (e.g., "kernel mode" ≠ root).
        - If missing, respond with: "privs_req": null.
    """,

    "crash_dump":"""
        Steps to extract crash information:
        1. Scan the context for outputs like: "segfault at", "RIP", "EIP", "Call Trace", "Oops", or "BUG:".
        or Look for stack traces, panic logs, or crash messages.
        2. Copy the full crash output block, preserving line breaks and formatting.
        3. If multiple dumps are shown, select all the ones that are clearly tied to the exploit event.
        - If none is found, respond with: "Not found".

        Constraints:
        - Do not rewrite or paraphrase the crash trace.
        - Do not guess crash patterns based on the vulnerability type.
        - Only extract labeled or contextual crash info.
    """,

    "exploit_privs": """
        Steps:
        1. Identify what access level the attacker achieves post-exploit.
        2. Look for mentions of root shell, kernel access, system privileges, etc.
        3. Include technical phrases like "ring 0", "write to /etc/passwd", "arbitrary code execution as root".

        Constraints:
        - Do not infer based on common exploit types.
        - Only include what’s clearly stated in the context.
        - If not explicitly described, return: Not found.
    """,

    "patch_date": """
        Steps to identify patch release date:
        1. Locate explicit dates or changelog entries that represent the date when patch was released and available. For example "2025-05-15: Patch committed to mainline kernel"
        2. Extract the full date exactly as it appears (ISO, long form, etc.).
        3. Read through the entire context for chat messages and discussion forums that discuss the availability of patch and if that they state a patch was pushed to mainline kernel, extract the date from chat messages.
        4. If multiple dates are listed, choose the one associated with the fix commit or security patch announcement.
        - If no date is mentioned, respond with: "Not found".

        Donot:
        - infer any date from the context or the anticipated timeline. 
        - Do not guess dates based on unrelated file timestamps.
        - Do not use relative references like "last week" or "recently".
        """,

    "patched_versions": """
        Steps to identify and extract patched Linux versions:
        1. identify the version numbers or linux distro names for which the patch was explicitly mentioned.
        2. Follow specific statements such as "The patch was updated in..." or "The patch is pushed from Linux version..."
        3. Extract all the kernel versions that mention that this patch is pushed or the vulnerability is patched.
        - If no versions are listed, respond with: "Not found".

        Constraints:
        - Do not include inferred ranges or unsupported guesses.
        - Do not infer based on year or kernel trends.
        """,

    "Code diff": """
        Steps to extract code differences:
        1. Locate the patch section with `diff --git` or `---` / `+++` headers.
        2. Copy the full diff block, including all `+`, `-`, and `@@` lines.
        3. Ensure function signatures and context lines are preserved.
        - If diff is not present, respond with: "Not found".

        Constraints:
        - Do not paraphrase or summarize the diff.
        - Do not extract unrelated code blocks or comments.
        - Do not invent or modify code.
        - Do not infer based on the difference in the given code blocks unless explicitly specified
        """,

    "Patch Code": """
        Steps:
        1. If a unified diff is present, extract only the `+` lines.
        2. If the patch code is shown outside a diff (e.g., standalone fixed function), copy it as-is.
        3. Preserve indentation, structure, and syntax exactly.
        - If nothing was found, return Not found. 

        Constraints:
        - Do not include deletions or unrelated unchanged context.
        - Do not attempt to reconstruct the patch if only partial code is shown.
    """,

    "score_explain": """
        Steps:
        1. Parse the context for all CVSS and CPE metrics such as base score, impact score, exploitability score, attack vector, or privilege required.
        2. Use CVSS v3 or v4 definitions (if known) to explain what the score implies about severity and exploitability.
        3. Combine present metrics into one technical paragraph describing the vulnerability’s seriousness, attack complexity, and consequences.
        - If no scores are found, respond with: "Not found".

        Constraints:
        - Do not retrieve information from outside the context.
        - Do not invent missing fields or speculate based on vulnerability type.
        - Only interpret the metrics that are explicitly available.
    """

}

qa_questions = {
    "Vulnerability": {
        "Vulnerable code": "Vulnerable code block"
    },
    "Localization": {
        "Function name": "What is the vulnerable function?",
        "File name": "What file contains the vulnerable function?",
        "Vulnerable OS component": "What kernel component is affected?",
    },
    "CWE": {
        "Weakness Type": "What type of vulnerability is this?",
    },
    "Reasoning": {
        "root_cause": "Explain the root cause of the vulnerability?",
        "secure_coding_violation": "What is the secure coding practices that are violated and explain?",
        "mitigation": "How can this vulnerability be mitigated?",
        "cia_impact": "What is the CIA impact of this vulnerability?",
        "exploit_expl": "How is this vulnerability exploited?",
    },
    "Exploit": {
        "Exploit Code": "What is the exploit or PoC code?",
        "remote_exploitability": "Is this vulnerability remotely exploitable?",
        "abusable_interfaces": "What are the kernel components, device drivers, or interfaces that are involved in triggering or exploiting this vulnerability?",
        "exploit_steps": "What are the steps to exploit this vulnerability?",
        "exploit_privs": "What are the privileges that are gained after exploitation?",
        "privs_req": "What are the privileges that are required to exploit this vulnerability?",
        "crash_dump": "What is the expected crash dump or stack trace?",
        "exploited_versions": "List the versions of the linux kernel or distro that are affected by this CVE"
    },
    "Patch": {
        "patch_expl": "What does the patch do to fix the issue?",
        "patch_date": "When was the patch released?",
        "patched_versions": "Which Linux versions have this patch?",
        "Code diff": "What are the code changes introduced in the patch?",
        "Patch code": "What is the patch code?",
    },
    "SCORES": {
        "baseSeverity": "What is the base CVSS severity?",
        "baseScore": "What is the base CVSS score?",
        "impactScore": "What is the impact score?",
        "exploitabilityScore": "What is the exploitability score?",
        "availabilityImpact": "What is the availability impact?",
        "score_explain": "Explain about the vulnerability scores and comprehend the details.",
    },
}

rag_questions = {
    "Localization": {
        # Intrinsic attributes -> Vulnerable location -> Function name
        "Function name": "From the vulnerable source code and data, extract specifically the function name and function prototypes from the provided vulnerable source code and do not infer or imply the functions that were not stated in the context.", 
        # Intrinsic attributes -> Vulnerable location -> File name
        "File name": "Identify and extract the file name which contains the vulnerability code or vulnerable function from the context. Do not guess.",
        # Intrinsic attributes -> Vulnerable location -> Vulnerable OS component
        "Vulnerable OS component": """
            Identify the specific Linux kernel subsystem, module, or OS-level component that is affected by the vulnerability. Look only for explicit mentions of affected components (e.g., memory management, ptrace, user namespaces, netfilter, etc.) in the context. Do not infer based on filenames, functions, or general discussion. Only include the component if it is directly stated or unambiguously indicated in the context.
        """

    },
    "CWE": {
        # Intrinsic attributes -> CWE ID -> <list> -> Weakness Type
        "Weakness Type": """
            Identify the type or category of the vulnerability as explicitly mentioned in the context. Look for terms that match or describe common weakness types (e.g., use-after-free, buffer overflow, privilege escalation, race condition, etc.). Do not infer the weakness based on behavior, file names, or function names. If multiple weakness types are mentioned, extract all the ones that is clearly associated with the vulnerability.
        """
    },
    # The following are taken using the RAG system taking the  developeer discussions and description as context
    "Reasoning": {
        "root_cause": """
         Identify any vulnerability that is explicitly described in the context. If present, write a clear, concise vulnerability_description in paragraph form. The paragraph may include any of the following details, but only if they are stated in the context:
        - What the vulnerability is (e.g., a use-after-free, buffer overflow, race condition)
        - The root cause or failure that leads to it
        - The conditions or environment required to trigger it (e.g., namespace setup, user privileges)
        - The affected components, files, functions, structures, or flags
        - The potential impact or consequence of the vulnerability (e.g., privilege escalation, memory corruption)
    Your description should focus solely on the weakness or flaw itself — not how it is exploited or what the attacker might do. Do not include proof-of-concept (PoC), exploitation techniques, or patch information.
    If no vulnerability is described in the context, respond with:
    "Not found"
    
    Example of a valid vulnerability_description:
        “A logic flaw in the memory subsystem allows a non-stateful expression to be added to a set and subsequently destroyed without proper cleanup. This causes a dangling pointer to remain in the bindings list, leading to a use-after-free condition. The issue occurs when nft_set_elem_expr_alloc() initializes an expression that fails the NFT_EXPR_STATEFUL check.”

    Do not infer, assume, complete, or invent any technical details that are not clearly and explicitly stated in the context.
        
        """,
        "secure_coding_violation": "Identify and explain the violation of any secure coding practicies that are found in the vulnerable code block in detail",
        "mitigation": """
            Describe the mitigation steps that are explicitly mentioned in the context. Include any system-level tools, kernel options, configuration files, or manual steps involved. If code snippets or commands are included (such as SystemTap scripts), extract and specify them and explain what functionality they affect. Clearly indicate if the mitigation introduces limitations or side effects (e.g., disables ptrace or debugging features). Only extract steps and effects that are stated in the context.
        """,
        "cia_impact": "From the context provided, extract to what extant does the Confidentiality, Integrity and the Availability of the system would be affected by this vulnerability?",
        "exploit_expl": """        
        Identify any exploitation methods or techniques that are described in the context. If present, write a clear, concise exploit_explanation in paragraph form. The paragraph may include any or all of the following details, but only if they are explicitly stated:
            - How the vulnerability is exploited (e.g., triggering a use-after-free)
            - What the attacker requires (e.g., local access, unprivileged user, crafted netlink messages)
            - The specific method, sequence, or steps used to trigger the flaw
            - Any tools, PoC code, scripts, or commands involved in the exploitation
            - The result or outcome of successful exploitation (e.g., privilege escalation, system crash)
        Focus only on the method of exploitation. Do not describe the underlying vulnerability or the patch, and do not discuss system design or intended behavior unless directly relevant to the exploit.
        
        Example of a valid exploit explanation:
            “An unprivileged local user can exploit the vulnerability by submitting a crafted NFT_MSG_NEWSET netlink message containing a lookup expression. The kernel adds the expression to the set bindings but fails to remove it before freeing the memory. Re-triggering set operations causes a write to a freed object, enabling arbitrary kernel memory writes and privilege escalation.”    

        Do not infer, assume, complete, or invent any technical details that are not clearly and explicitly stated in the context.
        """
    },
    "Exploit": {
        "Exploit Code": """
            Extract the complete exploit or Proof of Concept (PoC) code if it is present in the context. Only extract well-formed exploit code blocks that demonstrate the actual exploitation of the vulnerability. If the code is partial or incomplete, include only what is explicitly available without attempting to complete it. Do not extract descriptive text, shell output, or non-code explanations.
        """,
        "exploited_versions": """
            Identify the specific Linux kernel versions or distribution versions that are affected by this vulnerability. Use only information explicitly mentioned in the CPE metadata or in version-related statements from the context. Extract version numbers exactly as they appear such as "2.6.32-504", "Ubuntu 18.04", or "Red Hat Enterprise Linux 7.2". Do not generalize or infer version ranges unless explicitly stated.
        """,
        "abusable_interfaces": """
        What kernel components, device drivers, or interfaces are explicitly mentioned in the context as being involved in triggering or exploiting this vulnerability?
        """,

        "exploit_steps": """ 
        What are the step-by-step instructions or actions required to successfully exploit the vulnerability described?

        Include as much technical detail as available, such as:
        - The environment or setup needed
        - Input format or payload used
        - Functions or files involved in triggering the vulnerability
        - Expected behavior that confirms successful exploitation

        Avoid assumptions. Do not invent or guess information that is not explicitly stated in the context.
        """,
     
        "privs_req": """
            Identify the level of privileges required to successfully exploit the vulnerability, based only on the explicit statements in the context. Look for terms like "requires root", "requires CAP_SYS_ADMIN", or "no privileges required".
        """,

        "exploit_privs": """
            Determine the privileges or access levels gained after successful exploitation of the vulnerability, based strictly on the context. Extract statements that indicate privilege escalation, such as "gained root", "gained kernel code execution", or "access to arbitrary memory".
        """,
        
        "remote_exploitability": """
            Explain whether this vulnerability is remotely exploitable, using access vector information and any supporting technical indicators from the context.
        """,
    
        "crash_dump": """
            Extract the crash dump, stack trace, or system logs resulting from execution of the exploit or failure triggered by the vulnerability. Look for typical crash formats like EIP, RIP, kernel panic messages, or segmentation faults.
        """
    },
    "Patch": {
        "patch_expl": """
        If no code-level description of the patch is provided (i.e., no details about what changed or how it fixed the issue), you may still write a patch_description only if the context includes clear metadata, such as:
            - Git commit IDs or patch references
            - Kernel versions or advisory numbers where the patch is officially applied
            - Patch URLs

            In such cases, your patch_description should only describe these metadata elements (e.g., commit ID, kernel version, affected subsystem). Do not infer or speculate about what the patch does unless it is explicitly stated.

            For each patch, write a clear, concise patch_description in paragraph form. Each paragraph may include any of the following only if they appear in the context:
            - What change was made to fix the issue
            - Why this change was necessary (i.e., what it prevents or corrects)
            - The files, functions, or components that were modified
            - How the change resolves the vulnerability or bug
            - Git commit references or versions where the fix was applied

            If the commit is mentioned but no code-level description of the fix is included, only describe the metadata (e.g., commit ID, subsystem, kernel version). Do not assume what the patch does based on the commit ID or your own knowledge.

            If no patch description or metadata is present, respond with:
            "Not found"
                    
            example of a valid patch_description:
            “The vulnerability was fixed in commit a1b2c3d, which modifies the mm/mmap.c file to properly check memory region boundaries before performing copy-on-write. This change prevents race conditions that could previously lead to memory corruption. The patch also ensures proper reference counting on shared memory regions to avoid double-free errors.”
            
        Do not infer, assume, complete, or invent any technical details that are not clearly and explicitly stated in the context.
        """,
        "patch_date": """
            Extract the date when the patch for this vulnerability was released or committed, as explicitly stated in the context. Look for date formats in commit metadata, changelogs, or release notes (e.g., "2023-07-15", "July 15, 2023").
        """,
        "patched_versions": """
            Identify the Linux kernel or distribution versions that contain the patch fixing this vulnerability. Extract only version numbers with distro release names that are explicitly stated as patched or fixed. 
        """,
        "Code diff": """
            Extract the git code diff (patch delta) that compares the fixed and vulnerable code for this CVE. Look for unified diff formats (starting with `diff --git`, `+`, `-`, or `@@` syntax) typically found in mailing list patches or kernel commits. Only extract the actual diff block.
        """, 
        "Patch code": """
            Extract the patch code that was added or modified to fix the vulnerability. Focus on the new or changed code introduced by the patch. If a diff is available, extract only the `+` lines or the new implementation. 
        """
    },
    "SCORES": {
        "baseSeverity": "What is the base CVSS severity of this vulnerability?",
        "baseScore": "What is the base CVSS score of this vulnerability?",
        "impactScore": "What is the impact score of this vulnerability?",
        "exploitabilityScore": "What is the eploitability CVSS score of this vulnerability?",
        "availabilityImpact": "What is the availability impact of the CVE?",
        "score_explain": "Explain the CVSS scores found in the provided context in a single, cohesive technical paragraph. Include interpretation of base, impact, exploitability, and temporal scores if they are present. Use precise language and formal tone, interpreting the severity and real-world implication of each metric using CVSS definitions. Do not infer or guess any scores that are not explicitly provided."
    },
}

TEMPLATE = """
    You are an information extraction and comprehension agent working for a security analyst. Your role is to analyze CVE (Common Vulnerabilities and Exposures) and CVSS details  from a given text corpus either extract or comprehend specific attribute details with precision and completeness.
    
    # Instructions  
    Ensure the output is strictly derived from the given content.
    - Do not include any introductory phrases, headings, or comments in your response.
    {instructions}

    # Context
    {context}

    # Final instructions:
    Before generating the answer, carefully check that the detail exists in the context and is correctly identified. Always verify that no assumptions are being made. Use precise, formal language suitable for security documentation. Do not speculate, infer, or assume technical details.

    Question:
    {question}
"""


coding_attribs = [
    "Exploit Code", "exploit_steps", "crash_dump", "Code diff", "Patch code"
]

single_answer_attribs = [
    "Function name", "File name", "Vulnerable OS component", "Weakness Type"
]