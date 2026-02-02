
gen_qa_cves.py is the primary file used to run the rag pipeline that takes in portfolio as input. 


You can get the portfolio as output of step_1. Once taken that portfolio, the gen_qa_cves will generate the qa pairs for all the CVEs in the portfolio using chat gpt. 

Please update the CHATGPT API key in constants.py file. 

