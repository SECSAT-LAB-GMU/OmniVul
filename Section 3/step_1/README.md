This folder contains the important code to generate the portfolio using the data collected from diverse vulnerability information sources. 

THe major source of these all is the NVD which downloads the initial CVE information. Using NVD, we can then generate and map the information in git-hub, seclists, packetstorm, exploitDB and so on. 

Websites such as Ubuntu and redhat-cve-details can work directly by searching the CVE id collected from NVD. 

Each folder represents a vulnerability source and each source contains a scraper and some contain a parser to parse the downloaded offline files using scraper. 

