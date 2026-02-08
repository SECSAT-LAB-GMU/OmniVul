
This section involves the following steps: 
    Step 1: Downloading the vulnerability date from different sources and creating a portfolio
    Step 2: Creating the QA pairs from the portfolio using the constructed portfolio in Step 1. 
    Step 3: Creating and validating the LLM-as-a-Judge system using conformal predictionn. 


Step 1 contains the scripts for donloading data from different websites. The execution should start with NVD as we will download the CVEs and the exploit and patch links from NVD. 

Step 2 contains taking the generated portfolio and creating QA pairs. This require adding the OPENAI API key to the `constants.py` file. 


Finally, step_3 involves the code to create a website for human evaluation, and  running LLM-as-a-Judge. 


