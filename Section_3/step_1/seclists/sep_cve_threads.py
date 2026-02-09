import os
import shutil
import pandas as pd

# Load the CSV file
csv_path = "Seclist_2008-2024_CVEs.csv"
df = pd.read_csv(csv_path)

# Define source and destination directories
source_directory = "seclist_thread_messages" 
destination_directory = "CVE_threads"  # Change to your desired destination folder

# Ensure destination directory exists
os.makedirs(destination_directory, exist_ok=True)

# Iterate through the CSV to move files
for index, row in df.iterrows():

    if row["cve_found"] == 0:
        continue

    year = str(row["year"])
    quarter = str(row["quarter"])
    file_id = str(row["thread_id"])
    if str(row["children_ids"]) == "nan":
        other_file_ids = []
    else:
        other_file_ids = str(row["children_ids"]).split(",")
        other_file_ids = [id.strip() for id in other_file_ids]

    thread_ids = [file_id] + other_file_ids

    cve_id = row["CVE_id"]
    for count, thread_id in enumerate(thread_ids):

        file_path = f"{source_directory}/{year}_{quarter}/{thread_id}.txt"

        destination_file_path = os.path.join(destination_directory, f"{year}_{quarter}_{cve_id}_{count}.txt")
        # Check if file exists and move it
        if os.path.exists(file_path):
            shutil.copy(file_path, destination_file_path)
        else:
            print(f"File not found: {file_path}")

print("File moving process completed.")



