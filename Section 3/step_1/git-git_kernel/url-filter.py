import json
import re
import sys
from urllib.parse import unquote

with open('../nvd/nvd_cve_detail/linux_cve_dict_with_links.json', 'r', encoding='utf-8') as f:
    top500_nvd_cve_dict = json.load(f)
    top500_nvd_cve_ids = list(top500_nvd_cve_dict.keys())

def extract_git_kernel_urls_from_nvd_cve_dict(cve_dict):
    git_kernel_patterns = [
        r'https?://git\.kernel\.org/[^\s\'"<>]+',  # git.kernel.org
        r'https?://github\.com/torvalds/linux/[^\s\'"<>]+',  # GitHub Linus Torvalds repo
        r'https?://git\.kernel\.org/pub/scm/linux/kernel/git/[^\s\'"<>]+',  # 具体的kernel git路径
        r'https?://cgit\.kernel\.org/[^\s\'"<>]+',  # cgit.kernel.org
        r'https?://git\.kernel\.org/cgit/[^\s\'"<>]+',  # cgit interface
    ]
    
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in git_kernel_patterns]
    
    git_kernel_urls = set()  
    cve_url_mapping = {}  
    
    for cve_id, cve_data in cve_dict.items():
        cve_urls = []
        
        references = cve_data.get('references', [])
        for ref in references:
            url = ref.get('url', '')
            if url:
                for pattern in compiled_patterns:
                    if pattern.search(url):
                        git_kernel_urls.add(url)
                        cve_urls.append(url)
                        break
        
        if cve_urls:
            cve_url_mapping[cve_id] = cve_urls
    
    return list(git_kernel_urls), cve_url_mapping

def analyze_git_urls(git_urls):

    url_types = {
        'git.kernel.org': [],
        'github.com/torvalds/linux': [],
        'cgit.kernel.org': [],
        'lore.kernel.org': [],
        'patchwork.kernel.org': [],
        'other': []
    }
    
    for url in git_urls:
        if 'git.kernel.org' in url:
            url_types['git.kernel.org'].append(url)
        elif 'github.com/torvalds/linux' in url:
            url_types['github.com/torvalds/linux'].append(url)
        elif 'cgit.kernel.org' in url:
            url_types['cgit.kernel.org'].append(url)
        elif 'lore.kernel.org' in url:
            url_types['lore.kernel.org'].append(url)
        elif 'patchwork.kernel.org' in url:
            url_types['patchwork.kernel.org'].append(url)
        else:
            url_types['other'].append(url)
    
    return url_types

def extract_commit_hash_from_url(cve_url_dict):
    commit_hash_patterns = [
        r'github\.com/torvalds/linux/commit/([a-f0-9]{7,40})',
        r'[?&]id=([a-f0-9]{7,40})',
        r'%3Bh=([a-f0-9]{7,40})',
        r';h=([a-f0-9]{7,40})',
        r'git\.kernel\.org/linus/([a-f0-9]{7,40})',
        r'git\.kernel\.org/stable/c/([a-f0-9]{7,40})',
        r'commit/\?id=([a-f0-9]{7,40})',
        r'/([a-f0-9]{40})(?:[/?&#]|$)',
        r'/([a-f0-9]{7,12})(?:[/?&#]|$)'
    ]

    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in commit_hash_patterns]
    
    cve_commit_mapping = {}
    all_commit_hashes = set()
    hash_to_cves = {}  

    for cve_id, urls in cve_url_dict.items():
        commit_hashes = set()
        
        for url in urls:
            decoded_url = unquote(url)
            
            for pattern in compiled_patterns:
                matches = pattern.findall(decoded_url)
                for match in matches:
                    if len(match) >= 7 and len(match) <= 40 and match.isalnum():
                        # 转换为小写以保持一致性
                        hash_lower = match.lower()
                        commit_hashes.add(hash_lower)
                        all_commit_hashes.add(hash_lower)
                        
                        # 建立反向映射
                        if hash_lower not in hash_to_cves:
                            hash_to_cves[hash_lower] = []
                        if cve_id not in hash_to_cves[hash_lower]:
                            hash_to_cves[hash_lower].append(cve_id)
        
        if commit_hashes:
            cve_commit_mapping[cve_id] = list(commit_hashes)
        else:
            print(f"No commit hashes found for {cve_id}")
    
    return cve_commit_mapping, list(all_commit_hashes), hash_to_cves

if __name__ == "__main__":
    print("开始提取git kernel相关URL...")
    
    git_urls, cve_mapping = extract_git_kernel_urls_from_nvd_cve_dict(top500_nvd_cve_dict)
    
    print(f"找到 {len(git_urls)} 个唯一的git kernel URL")
    print(f"涉及 {len(cve_mapping)} 个CVE")
    
    url_types = analyze_git_urls(git_urls)
    print("\nURL类型分布:")
    for url_type, urls in url_types.items():
        if urls:
            print(f"  {url_type}: {len(urls)} 个URL")
    
    with open('complete_references/nvd-git-kernel-references.json', 'w', encoding='utf-8') as f:
        json.dump(cve_mapping, f, indent=4)
        print(f"Saved {len(cve_mapping)} CVE - Git Kernel References Mapping to top500_references/nvd-git-kernel-references.json")
    
    cve_commits, all_hashes, hash_to_cves = extract_commit_hash_from_url(cve_mapping)
    
    with open('complete_references/nvd-git-kernel-commit-hashes.json', 'w', encoding='utf-8') as f:
        json.dump(cve_commits, f, indent=4)
        print(f"Saved {len(cve_commits)} CVE - Git Kernel Commit Hashes Mapping to top500_references/nvd-git-kernel-commit-hashes.json")
