from langchain.docstore.document import Document



def ret_documents(discussions):
    documents = []
    for source, discussion in discussions.items():
        if source == "ubuntu":
            doc = Document(discussion["value"], metadata = {"source": source})
            documents.append(doc)
        elif source == "redhat-bugzilla":
            data = discussion[0]
            for comment in data["comments"]:
                doc = Document(comment["comment_content"], metadata = {"source":source})
                documents.append(doc)
        else:
            for disc in discussion:
                doc = Document(disc,  metadata={"source": source})
                documents.append(doc)
    return documents


