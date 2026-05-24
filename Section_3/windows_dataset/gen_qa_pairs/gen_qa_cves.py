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

# NOTE: langchain_core 1.x dropped the legacy `langchain.*` shim modules
# (langchain.prompts / langchain.text_splitter / langchain.docstore), so import
# from the split-out packages directly.
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_core.prompts import PromptTemplate
from langchain_ollama import OllamaLLM
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_core.embeddings import Embeddings

from constants import *
from questions import INSTRUCTIONS_DICT, rag_questions, TEMPLATE
from qa_utils import build_documents

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


# Offline smoke-test toggle (no key / network / cost). See QA_DRY_RUN below.
DRY_RUN = os.environ.get("QA_DRY_RUN") == "1"


class _FakeEmbeddings(Embeddings):
    """Deterministic 16-dim embeddings so FAISS works offline."""

    def embed_documents(self, texts):
        return [self._vec(t) for t in texts]

    def embed_query(self, text):
        return self._vec(text)

    @staticmethod
    def _vec(text):
        import hashlib
        digest = hashlib.md5(str(text).encode("utf-8", "ignore")).digest()
        return [b / 255.0 for b in digest]


class _FakeResp:
    def __init__(self, content):
        self.content = content
        self.response_metadata = {
            "logprobs": {"content": []},
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }


class _FakeChain:
    def invoke(self, payload):
        q = str(payload.get("question", ""))[:80]
        return _FakeResp(f"[DRY-RUN] would answer: {q}")


# Portfolio produced by ../filter_portfolio.py (CVEs with >=1 patch/exploit link).
PORTFOLIO_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "filtered_portfolio.json",
)
with open(PORTFOLIO_FILE, 'r') as file:
        cve_portfolios = json.load(file)

if not GPT_KEY and not DRY_RUN:
    raise SystemExit(
        "No OpenAI key found. Set OPENAI_API_KEY in your environment "
        "(export OPENAI_API_KEY=sk-...) or paste it into constants.py:GPT_KEY. "
        "To smoke-test the pipeline offline without a key, run with QA_DRY_RUN=1."
    )

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


encoding = tiktoken.encoding_for_model("text-embedding-3-large")

prompt = PromptTemplate(
    template=TEMPLATE,
    input_variables=["question", "context", "instructions"]
)
MODEL = "GPT"

if DRY_RUN:
    # Offline smoke-test mode: deterministic fake embeddings + canned answers so
    # the whole pipeline (chunking, FAISS, retrieval, output writing) can run
    # without an OpenAI key or any network/cost. Set QA_DRY_RUN=1 to enable.
    embedding_model = _FakeEmbeddings()
    llm_chain = _FakeChain()
else:
    # embedding_model = HuggingFaceEmbeddings(model_name="intfloat/e5-base-v2", encode_kwargs={'normalize_embeddings': True})
    # embedding_model = OpenAIEmbeddings(api_key=GPT_KEY)
    embedding_model = OpenAIEmbeddings(model="text-embedding-3-large", api_key=GPT_KEY)

    llm = ChatOpenAI(
        api_key=GPT_KEY,
        model_name="gpt-4o",
        temperature=0.0,
        max_tokens=None,
        seed = 111
    ).bind(logprobs = True)

    # llm = OllamaLLM(model = "llama3:70b", temperature = 0)
    # MODEL = "OLLAMA"

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

# Process a slice of the portfolio. start/end let you shard the run or resume a
# crashed batch; defaults cover the whole filtered portfolio.
start = int(os.environ.get("QA_START", 0))
end = int(os.environ.get("QA_END", len(cves_list)))

# Output folders are tagged with this id so separate shards don't collide.
folder_id = os.environ.get("QA_FOLDER_ID", "windows")

cves_list = [cve.strip() for cve in cves_list][start:end]

os.makedirs(f"{folder_id}_qas", exist_ok = True)
os.makedirs(f"{folder_id}_context_qas", exist_ok= True)
os.makedirs(f"{folder_id}_token_usage", exist_ok = True)
os.makedirs(f"{folder_id}_embeddings_qa", exist_ok = True)

# Resume file is scoped to the folder_id so separate shards / dry-runs don't
# skip each other's CVEs.
COMPLETED_FILE = f"{folder_id}_completed_cves.txt"

try:
    with open(COMPLETED_FILE, 'r') as file:
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

    # Flatten the merged portfolio entry into RAG documents + portfolio-side
    # ground-truth answers (see ../gen_qa_pairs/qa_utils.py:build_documents).
    documents, ground_truth = build_documents(portfolio)
    if not documents:
        logging.info(f"No documents for {cve}; skipping.")
        with open(COMPLETED_FILE, 'a') as file:
            file.write(cve + "\n")
        continue

    # Patch code / code diff / exploit code ground truth come straight from the
    # scraped diffs (these tags are not answered by RAG below).
    answer_dict["Patch"]["Patch code"]["portfolio"] = ground_truth["Patch"].get("Patch code", "")
    answer_dict["Patch"]["Code diff"]["portfolio"] = ground_truth["Patch"].get("Code diff", "")
    answer_dict["Exploit"]["Exploit Code"]["portfolio"] = ground_truth["Exploit"].get("Exploit Code", "")

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
            # The Windows portfolio has no curated vulnerable-location ground
            # truth; we still ask the RAG questions, leaving portfolio answers blank.
            part_attributes = {}
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
            # Ground-truth weakness from the NVD CWE list (see qa_utils.cwe_values).
            cwe_ground_truth = ground_truth["CWE"]
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
                answer_dict[key][tag]["portfolio"] = cwe_ground_truth
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
            # CVSS ground truth pulled from the most recent NVD metric.
            scores = ground_truth["SCORES"]
            if not scores:
                logging.info(f"No scores found for {cve}")
                answer_dict[key]["portfolio"] = None
                continue
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

    with open(COMPLETED_FILE, 'a') as file:
        file.write(cve + "\n")

with open(f"{folder_id}_complete_QA_data.json", "w") as f:
    json.dump(answers, f, indent=2)

with open(f"{folder_id}_context_QA_data.json", "w") as f:
    json.dump(contexts, f, indent=2)

with open(f"{folder_id}_embeddings_QA_data.json", "w") as f:
    json.dump(embedding_answers, f, indent=2)

