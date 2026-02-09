"""
This is the main program to generate the QA pairs using the RAG pipeline
"""



import logging

logging.basicConfig(
    level=logging.INFO,            # Minimum level to log
    format='%(asctime)s - %(levelname)s - %(message)s'  # Log format
)

import os
import json
from collections import defaultdict

from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.docstore.document import Document
from langchain_community.vectorstores import FAISS
from langchain.prompts import PromptTemplate
from langchain_ollama import OllamaLLM
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from constants import *        
from questions import INSTRUCTIONS_DICT, rag_questions, TEMPLATE       
from qa_utils import ret_documents

import tiktoken

def num_tokens_from_string(string: str) -> int:
    num_tokens = len(encoding.encode(string))
    return num_tokens

def batch_texts_by_token_limit(texts, max_tokens=300000):
    batches = []
    current_batch = []
    current_tokens = 0

    for text in texts:
        tokens = len(encoding.encode(text))
        if current_tokens + tokens > max_tokens:
            batches.append(current_batch)
            current_batch = [text]
            current_tokens = tokens
        else:
            current_batch.append(text)
            current_tokens += tokens

    if current_batch:
        batches.append(current_batch)

    return batches


# replace the portfolio file here..
with open("final_restructure_sampled_2000.json", 'r') as file:
        cve_portfolios = json.load(file)

test_keys = ["Localization", "CWE", "Reasoning", "Exploit", "Patch", "SCORES"]
# test_keys = ["Reasoning"]
# test_keys = ["Localization"]

def ask_with_sources(context: str, question: str, instructions: str):
    """Run retrieval + generation and return answer + source docs."""
    answer = llm_chain.invoke({
        "question": question,
        "context": context,
        "instructions": instructions,
    })
    return answer

# RAG నిత్యావసరాలు 
# RAG requirements:
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=100,
    separators=["\n\n", "\n", " ", "", "```"],  # tries to split at sensible places
    add_start_index=True
)


# embedding_model = HuggingFaceEmbeddings(model_name="intfloat/e5-base-v2", encode_kwargs={'normalize_embeddings': True})
# embedding_model = OpenAIEmbeddings(api_key=GPT_KEY)
embedding_model = OpenAIEmbeddings(model="text-embedding-3-large", api_key=GPT_KEY)
encoding = tiktoken.encoding_for_model("text-embedding-3-large")

llm = ChatOpenAI(
    api_key=GPT_KEY,
    model_name="gpt-4o",
    temperature=0.0,
    max_tokens=None,
    seed = 111
).bind(logprobs = True)
MODEL = "GPT"

# llm = OllamaLLM(model = "llama3:70b", temperature = 0)
# MODEL = "OLLAMA"

prompt = PromptTemplate(
    template=TEMPLATE, 
    input_variables=["question", "context", "instructions"]
)

llm_chain = prompt | llm
contexts = defaultdict(dict)

answers = defaultdict(dict)
embedding_answers = defaultdict(dict)

# with open("tuning_cves.txt" , 'r') as file:
    # cves_list = file.readlines()

# initial test CVEs. 
# cves_list = [
#     "CVE-2016-9313",
#     "CVE-2011-4110",
#     "CVE-2021-38198",
#     "CVE-2013-2140",
#     "CVE-2020-29371"
# ]

cves_list = list(cve_portfolios.keys())

# you can select the start and end index of the CVE:
start = 700
end = 1500

# We use a convention of tagging the data with the end index, as we are making each part contain 10 CVEs,
# Each part ocntains data from end-10 to end index in it. 
# folder_id = "second"+str(end)

# filling the CVEs that has missing vulnerabiillty code data. 
folder_id = f"init{end}"

cves_list = [cve.strip() for cve in cves_list][start:]

os.makedirs(f"{folder_id}_qas", exist_ok = True)
os.makedirs(f"{folder_id}_context_qas", exist_ok= True)
os.makedirs(f"{folder_id}_token_usage", exist_ok = True)
os.makedirs(f"{folder_id}_embeddings_qa", exist_ok = True)

try:
    with open("completed_cves.txt", 'r') as file:
        completed_cves = file.readlines()
except FileNotFoundError:
    completed_cves = []

completed_cves = [cve.strip() for cve in completed_cves]

for count, cve in enumerate(cves_list):
    if cve in completed_cves:
        continue
    logging.info(f"Currently on {cve} with number {count}")
    portfolio = cve_portfolios[cve]
    answer_dict = defaultdict(lambda: defaultdict(dict))
    embeddings_dict = defaultdict(lambda: defaultdict(dict))
    context_dict = defaultdict(lambda: defaultdict(dict))
    tokens_dict = defaultdict(lambda: defaultdict(dict))

    discussions = portfolio[INTRINSIC_ATTRIBS][DISCUSSIONS]
    documents = []

    # adding vulnerability description to the documents:
    for source, desc in portfolio[INTRINSIC_ATTRIBS]["Vulnerability Description"].items():
        doc = Document(desc, metadata = {"source": source})
        documents.append(doc)

    # checking and extracting vulnerable source code:
    if "Vulnerable code block" in portfolio[INTRINSIC_ATTRIBS][VULN_LOCATION]:
        if len(portfolio[INTRINSIC_ATTRIBS][VULN_LOCATION]["Vulnerable code block"]) != 0:
            vuln_code = ""
            for codes in portfolio[INTRINSIC_ATTRIBS][VULN_LOCATION]["Vulnerable code block"]:
                if isinstance(codes, list):
                    for code in codes:
                        vuln_code += "\n\n" + code
                if isinstance(codes, dict):
                    for code in codes.values():
                        vuln_code += "\n\n" + code
                elif isinstance(code, str):
                    vuln_code += "\n\n" + codes
                doc = Document("VULNERABLE CODE BLOCK: \n"+vuln_code, metadata= {"source": "Vulnerable code"})
                documents.append(doc)
            answer_dict["Vulnerability"]["Vulnerable code"]["portfolio"] = vuln_code
    else:
        answer_dict["Vulnerability"]["Vulnerable code"]["portfolio"] = ""

    # adding patch message to the documents
    if len(portfolio[PATCH_SET]) != 0:
        patch_message = "[PATCH MESSAGE] \n"
        for message in portfolio[PATCH_SET]["Patch Message"]:
            if isinstance(message, list):
                for m in message:
                    patch_message += "\n" + m
            elif isinstance(message, str):
                patch_message += "\n" + message 
            doc = Document(patch_message, metadata = {"source": "patch message"})
            documents.append(doc)
        doc = Document(" [PATCH CODE] \n" + str(portfolio[PATCH_SET]["Patch Code"]), metadata = {"source": "patch code"})
        documents.append(doc)
        doc = Document(" [CODE DIFF] +\n" + str(portfolio[PATCH_SET]["Code diff"]), metadata = {"source": "code diff"})
        documents.append(doc)
        answer_dict["Patch"]["Patch code"]["portfolio"] = portfolio[PATCH_SET]["Patch Code"]
        answer_dict["Patch"]["Code diff"]["portfolio"] = portfolio[PATCH_SET]["Code diff"]

    # adding exploit code for better understanding of the documents
    if len(portfolio[EXPLOIT_SET]) != 0:
        exploit_code = ""
        for code in portfolio[EXPLOIT_SET]["Exploit Code"]:
            exploit_code += code + "\n\n"
            doc = Document(" [EXPLOIT CODE] \n" + exploit_code, metadata = {"source": "exploit code"})
            documents.append(doc)
        answer_dict["Exploit"]["Exploit Code"]["portfolio"] = exploit_code

    # adding scores to the document
    scores_documents = []
    for item in portfolio[IMPACT].values():
        document = Document(str(item), metadata={"source": "impact scores"})
        scores_documents.append(document)
    documents.extend(scores_documents)

    documents.extend(ret_documents(discussions))
    doc_chunks = text_splitter.split_documents(documents)

    texts = [doc.page_content for doc in doc_chunks]
    embedding_tkn_count = sum([num_tokens_from_string(text) for text in texts])

    tokens_dict["embedding_tokens"] = embedding_tkn_count
    batches = batch_texts_by_token_limit(texts)

    all_embeddings = []
    for batch in batches:
        embeddings = embedding_model.embed_documents(batch)
        # save or process embeddings...
        all_embeddings.extend(embeddings)

    text_embeddings = list(zip(texts, all_embeddings))
    # vector_index = FAISS.from_documents(doc_chunks, embedding_model)
    vector_index = FAISS.from_embeddings(text_embeddings, embedding_model, metadatas=[doc.metadata for doc in doc_chunks])
    
    retriever = vector_index.as_retriever(search_type="mmr", search_kwargs={"k": 12}) 

    logging.info(f"\t {cve} Completed loading documents, Total documents = {len(documents)} ")

    for key in test_keys:
        logging.info(f"\t\t Currently on {key}")
        focus_questions = rag_questions[key]
        if key == "Localization":
            part_attributes = portfolio[INTRINSIC_ATTRIBS][VULN_LOCATION]
            for tag, question in focus_questions.items():
                logging.info(f"\t\t\t Currently on {tag}")
                instr = INSTRUCTIONS_DICT.get(tag, "")
                docs = retriever.invoke(question)
                # context = "\n\n".join(d.page_content for d in docs)
                context = ""
                for d in docs:
                    context += "Source: " + d.metadata.get('source', "Unknown") + "\n"
                    context += d.page_content + "\n"
                response = ask_with_sources(context, question, instr)
                answer_dict[key][tag]["rag"] = response.content if MODEL == "GPT" else response
                answer_dict[key][tag]["portfolio"] = part_attributes.get(tag, "")
                if MODEL == "GPT":
                    embeddings_dict[key][tag] = response.response_metadata["logprobs"]["content"]
                    tokens_dict[key][tag] = response.response_metadata["token_usage"]

                context_chunks = "===============================================\n"
                for d in docs:
                    context_chunks += d.page_content + "\n"
                    context_chunks += d.metadata.get('source', "Unknown") + "\n"
                    context_chunks += "=============================================\n"
                # context_chunks = "\n\n============================================\n".join(d.page_content for d in docs)
                context_dict[key][tag] = context_chunks

        elif key == "CWE":
            part_attributes = portfolio[INTRINSIC_ATTRIBS]["CWE"]["CWE_ID"][0]
            for tag, question in focus_questions.items():
                logging.info(f"\t\t\t Currently on {tag}")
                instr = INSTRUCTIONS_DICT.get(tag, "")
                docs = retriever.invoke(question)
                # context = "\n\n".join(d.page_content for d in docs)
                context = ""
                for d in docs:
                    context += "Source: " + d.metadata.get('source', "Unknown") + "\n"
                    context += d.page_content + "\n"
                response = ask_with_sources(context, question, instr)
                answer_dict[key][tag]["rag"] = response.content if MODEL == "GPT" else response
                answer_dict[key][tag]["portfolio"] = part_attributes[tag]
                if MODEL == "GPT":
                    embeddings_dict[key][tag] = response.response_metadata["logprobs"]["content"]
                    tokens_dict[key][tag] = response.response_metadata["token_usage"]

                context_chunks = "===============================================\n"
                for d in docs:
                    context_chunks += d.page_content + "\n"
                    context_chunks += d.metadata.get('source', "Unknown") + "\n"
                    context_chunks += "=============================================\n"
                # context_chunks = "\n\n============================================\n".join(d.page_content for d in docs)
                context_dict[key][tag] = context_chunks

        elif key in ["Exploit", "Patch", "Reasoning"]:
            for tag, question in focus_questions.items():
                logging.info(f"\t\t\t Currently on {tag}")
                instr = INSTRUCTIONS_DICT.get(tag, "")
                docs = retriever.invoke(question)
                context = ""
                for d in docs:
                    context += "Source: " + d.metadata.get('source', "Unknown") + "\n"
                    context += d.page_content + "\n"
                response = ask_with_sources(context, question, instr)
                answer_dict[key][tag]["rag"] = response.content if MODEL == "GPT" else response
                if MODEL == "GPT":
                    embeddings_dict[key][tag] = response.response_metadata["logprobs"]["content"]
                    tokens_dict[key][tag] = response.response_metadata["token_usage"]
                context_chunks = "===============================================\n"
                for d in docs:
                    context_chunks += d.page_content + "\n"
                    context_chunks += d.metadata.get('source', "Unknown") + "\n"
                    context_chunks += "=============================================\n"
                context_dict[key][tag] = context_chunks

        elif key == "SCORES":
            try:
                part_portfolio = list(portfolio[IMPACT]["CVSS Metric"].values())[0]
            except IndexError:
                logging.info(f"No scores found for {cve}")
                answer_dict[key]["portfolio"] = None
                continue
            scores = part_portfolio["Primary"] if "Primary" in part_portfolio else part_portfolio["Secondary"]
            for tag, question in focus_questions.items():
                if tag == "score_explain":
                    instr = INSTRUCTIONS_DICT.get(tag, "")
                    docs = retriever.invoke(question)
                    context = ""
                    for d in docs:
                        context += "Source: " + d.metadata.get('source', "Unknown") + "\n"
                        context += d.page_content + "\n"

                    response = ask_with_sources(context, question, instr)
                    answer_dict[key][tag]["rag"] = response.content if MODEL == "GPT" else response

                    if MODEL == "GPT":
                        embeddings_dict[key][tag] = response.response_metadata["logprobs"]["content"]
                        tokens_dict[key][tag] = response.response_metadata["token_usage"]
                    context_chunks = "===============================================\n"
                    for d in docs:
                        context_chunks += d.page_content + "\n"
                        context_chunks += d.metadata.get('source', "Unknown") + "\n"
                        context_chunks += "=============================================\n"
                    
                    context_dict[key][tag] = context_chunks
                else:
                    try:
                        answer_dict[key][tag]["portfolio"] = scores[tag]
                    except: 
                        answer_dict[key][tag]["portfolio"] = "Not Given"

    answers[cve] = answer_dict
    embedding_answers[cve] = embeddings_dict
    contexts[cve] = context_dict

    with open(f"{folder_id}_qas/{cve}.json", 'w') as file:
        json.dump(answer_dict, file, indent=2)

    with open(f"{folder_id}_context_qas/{cve}.json", 'w') as file:
        json.dump(context_dict, file, indent=2)

    with open(f"{folder_id}_token_usage/{cve}.json", 'w') as file:
        json.dump(tokens_dict, file, indent=2)

    with open(f"{folder_id}_embeddings_qa/{cve}.json", 'w') as file:
        json.dump(embeddings_dict, file, indent=2)

    with open("completed_cves.txt", 'a') as file:
        file.write(cve + "\n")

with open(f"{folder_id}_complete_QA_data.json", "w") as f:
    json.dump(answers, f, indent=2)

with open(f"{folder_id}_context_QA_data.json", "w") as f:
    json.dump(contexts, f, indent=2)

with open(f"{folder_id}_embeddings_QA_data.json", "w") as f:
    json.dump(embedding_answers, f, indent=2)

