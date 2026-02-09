
import pandas as pd
import json
import re

data = pd.read_csv("linux_links.csv", names = ["Group", "Title", "Article"])


articles = []

cve_pattern = r"CVE-\d{4}-\d{4,7}"

articles = data["Article"].tolist()

with open("lwn_articles_full_content.json", 'r') as f:
    json_dict = json.load(f)


dataset = {}
for val in json_dict:
    dataset[val["URL"]] = val

count = 0
dir = "complete_cve_arrangement"


for url in articles:
    article = dataset[url]["Content"]
    cve_matches = re.findall(cve_pattern, article)

    # create a folder named after the found CVE if not exists and put the content as a file in that folder
    if cve_matches:
        count += 1
        for cve in cve_matches:
            folder_name = f"{dir}/{cve}"
            file_name = f"{folder_name}/article_{count}.txt"
            try:
                # Create directory if it doesn't exist
                import os
                os.makedirs(folder_name, exist_ok=True)
                
                # Write the article content to a file
                with open(file_name, 'w') as f:
                    f.write(article)
            except Exception as e:
                print(f"Error creating folder or writing file for {cve}: {e}")







