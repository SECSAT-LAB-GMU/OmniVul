linux_kernel_cve_keywords = [
    "Linux kernel vulnerability", "Linux kernel CVE",
    "Linux kernel security issue", "Linux kernel exploit",
    "Linux kernel patch", "Linux kernel privilege escalation",
    "Linux kernel remote code execution", "Linux kernel syscall vulnerability",
    "Linux kernel buffer overflow", "Linux kernel memory corruption",
    "Linux kernel heap overflow", "Linux kernel race condition",
    "Linux kernel null pointer dereference", "Linux kernel use-after-free",
    "Linux kernel double free", "Linux kernel info leak",
    "Linux kernel integer overflow", "Linux kernel arbitrary code execution",
    "Linux kernel privilege escalation", "Linux kernel RCE",
    "Linux kernel DoS", "Linux kernel local privilege escalation",
    "Linux kernel denial of service", "site:seclists.org linux kernel CVE",
    "site:seclists.org linux kernel vulnerability",
    "site:seclists.org linux kernel security", "site:seclists.org linux kernel exploit",
    "site:seclists.org linux kernel patch", "site:seclists.org/oss-sec Linux kernel CVE",
    "site:seclists.org/bugtraq Linux kernel CVE",
    "site:seclists.org/full-disclosure Linux kernel CVE",
    "Linux kernel CVE RedHat", "Linux kernel CVE Debian",
    "Linux kernel CVE Ubuntu", "Linux kernel CVE SUSE",
    "Linux kernel CVE exploit-db", "Linux kernel CVE MITRE"
]

# Additional flexible patterns
flexible_patterns = [
    r"CVE-\d{4}-\d+.*(Linux|kernel)",  # Matches "CVE-2024-1234 Linux" or "CVE-2024-1234 kernel"
    r"Linux.*CVE",      # Matches "Linux ... CVE" (any words between them)
    r"CVE.*Linux",      # Matches "CVE ... Linux" (any words between them)
    r"Linux.*syscall.*CVE",  # Matches "Linux ... syscall ... CVE"
    r"CVE.*syscall.*Linux",  # Matches "CVE ... syscall ... Linux"
    r"CVE.*kernel",    # Matches cases where CVE appears near "kernel"
]
