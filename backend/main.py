from fastapi import FastAPI
import ollama
import os

from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

app = FastAPI()

# Base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Chroma DB path
CHROMA_PATH = os.path.join(BASE_DIR, "rag", "chroma_db")

# Load embedding model
embedding_model = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

# Load vector database
vector_db = Chroma(
    persist_directory=os.path.join(BASE_DIR, "rag", "multi_threat_db"),
    embedding_function=embedding_model
)

@app.get("/")
def home():
    return {"message": "Cyber AI Platform Running"}

@app.post("/analyze")
def analyze_threat(query: str):

    # Retrieve relevant threat intelligence
    results = vector_db.similarity_search(query, k=2)

    context = "\n".join([doc.page_content for doc in results])

    # AI Prompt
    prompt = f"""
    You are an expert cybersecurity analyst.

    Use the threat intelligence context below to answer professionally.

    Threat Intelligence Context:
    {context}

    User Query:
    {query}

    Generate:
    1. Threat Summary
    2. MITRE ATT&CK Mapping
    3. Indicators
    4. Mitigation Recommendations
    """

    # Send to Llama via Ollama
    response = ollama.chat(
        model="llama3.2:3b",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return {
        "query": query,
        "retrieved_context": context,
        "analysis": response['message']['content']
    }