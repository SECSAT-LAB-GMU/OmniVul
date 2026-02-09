import json

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


def num_tokens_from_string(string: str, encoding_name = "o200k_base") -> int:
    encoding = tiktoken.get_encoding(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens

with open("portfolio.json", 'r') as file:
    cve_portfolios = json.load(file)


def ask_with_sources(context: str, question: str, instructions: str):
    """Run retrieval + generation and return answer + source docs."""
    answer = llm_chain.invoke({
        "question": question,
        "context": context,
        "instructions": instructions,
    })
    return answer


text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=50,
    separators=["\n\n", "\n", " ", "", "```"],  # tries to split at sensible places
    add_start_index=True
)

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


cve = "CVE-2014-8559"
portfolio = cve_portfolios[cve]
key = "Localization"
# key = "Reasoning"
focus_questions = rag_questions[key]

tag = "File name"
# tag = "secure_coding_violation"

question = focus_questions[tag]

discussions = portfolio[INTRINSIC_ATTRIBS][DISCUSSIONS]
documents = []

# adding vulnerability description to the documents:
for source, desc in portfolio[INTRINSIC_ATTRIBS]["Vulnerability Description"].items():
    doc = Document(desc, metadata = {"source": source})
    documents.append(doc)

# checking and extracting vulnerable source code:
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

# adding exploit code for better understanding of the documents
if len(portfolio[EXPLOIT_SET]) != 0:
    exploit_code = ""
    for code in portfolio[EXPLOIT_SET]["Exploit Code"]:
        exploit_code += code + "\n\n"
        doc = Document(" [EXPLOIT CODE] \n" + exploit_code, metadata = {"source": "exploit code"})
        documents.append(doc)

scores_documents = []
for item in portfolio[IMPACT].values():
    document = Document(str(item), metadata={"source": "impact scores"})
    scores_documents.append(document)
documents.extend(scores_documents)

documents.extend(ret_documents(discussions))
doc_chunks = text_splitter.split_documents(documents)

texts = [doc.page_content for doc in doc_chunks]

batches = batch_texts_by_token_limit(texts)

all_embeddings = []
for batch in batches:
    embeddings = embedding_model.embed_documents(batch)
    # save or process embeddings...
    all_embeddings.extend(embeddings)

# vector_index = FAISS.from_documents(doc_chunks, embedding_model)

text_embeddings = list(zip(texts, all_embeddings))
vector_index = FAISS.from_embeddings(text_embeddings, embedding_model, metadatas=[doc.metadata for doc in doc_chunks])
retriever = vector_index.as_retriever(search_type="mmr", search_kwargs={"k": 12}) 

print("Completed Loading documents")

instr = INSTRUCTIONS_DICT.get(tag, "")
docs = retriever.invoke(question)
context = ""
for d in docs:
    context += "Source: " + d.metadata.get('source', "Unknown") + "\n"
    context += d.page_content + "\n"
# context = "\n\n".join(d.page_content for d in docs)

context_chunks = "===============================================\n"
for d in docs:
    context_chunks += d.page_content + "\n"
    context_chunks += d.metadata.get('source', "Unknown") + "\n"
    context_chunks += "=============================================\n"

print(context)
print("*"*30)

response = ask_with_sources(context, question, instr)
print(response.content) if MODEL == "GPT" else print(response)
