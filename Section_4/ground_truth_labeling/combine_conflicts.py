import json
import os


main_dir = "conflicts_json_main"
loc_dir = "loc_cwe_conflicts"

tag = ["init10", "init20", "init30", "init40", "init50", "init60", "init70", "init80", "init90", "init100"]

loc_cwe = ["Localization", "CWE"]

os.makedirs("conflicts", exist_ok=True)


for t in tag:
    main_file = f"{main_dir}/{t}_conflicts.json"
    loc_file = f"{loc_dir}/loc_cwe_{t}_conflicts.json"

    with open(main_file, 'r') as f:
        main_data = json.load(f)

    with open(loc_file, 'r') as f:
        loc_data = json.load(f)    
    for cve in loc_data.keys():
        for attribute in loc_cwe:
                if attribute not in loc_data[cve]:
                     continue
                if cve not in main_data:
                    main_data[cve] = {}
                main_data[cve][attribute] = loc_data[cve][attribute]
    output_file = f"conflicts/{t}_conflicts.json"
    with open(output_file, 'w') as f:
        json.dump(main_data, f, indent=4)

    print(f"Processed {t} conflicts and saved to {output_file}")
print("All conflicts processed and saved in the 'conflicts' directory.")
print("Done!")


