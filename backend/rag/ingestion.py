"""Build the threat-intelligence Chroma vector store from data/threat_intel/*.txt.

Run as a script to (re)build the store from scratch:

    uv run python -m backend.rag.ingestion
"""

import shutil

from langchain_chroma import Chroma
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter

from backend.rag.config import (
    CHROMA_PERSIST_DIR,
    CHUNK_OVERLAP,
    CHUNK_SIZE,
    COLLECTION_NAME,
    THREAT_INTEL_DIR,
)
from backend.rag.embeddings import get_embedding_model


def load_threat_intel_documents():
    """Load every .txt file in THREAT_INTEL_DIR, tagging each with source/threat_type metadata."""
    documents = []
    for file_path in sorted(THREAT_INTEL_DIR.glob("*.txt")):
        for doc in TextLoader(str(file_path)).load():
            doc.metadata["source"] = file_path.name
            doc.metadata["threat_type"] = file_path.stem
            documents.append(doc)
    return documents


def chunk_documents(documents):
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
    )
    chunks = splitter.split_documents(documents)
    for index, chunk in enumerate(chunks):
        chunk.metadata["chunk_index"] = index
    return chunks


def build_vector_store() -> Chroma:
    """Deterministically rebuild the persisted Chroma collection from current source documents.

    The persist directory is wiped before ingestion so re-running this never mixes
    stale embeddings from a previous version of a document with the current ones.
    """
    if not THREAT_INTEL_DIR.exists():
        raise FileNotFoundError(f"Threat intel directory not found: {THREAT_INTEL_DIR}")

    documents = load_threat_intel_documents()
    if not documents:
        raise ValueError(f"No .txt documents found in {THREAT_INTEL_DIR}")

    chunks = chunk_documents(documents)

    if CHROMA_PERSIST_DIR.exists():
        shutil.rmtree(CHROMA_PERSIST_DIR)
    CHROMA_PERSIST_DIR.mkdir(parents=True, exist_ok=True)

    vector_store = Chroma.from_documents(
        documents=chunks,
        embedding=get_embedding_model(),
        collection_name=COLLECTION_NAME,
        persist_directory=str(CHROMA_PERSIST_DIR),
    )

    print(f"Loaded {len(documents)} document(s) from {THREAT_INTEL_DIR}")
    print(f"Split into {len(chunks)} chunk(s) (chunk_size={CHUNK_SIZE}, overlap={CHUNK_OVERLAP})")
    print(f"Persisted collection '{COLLECTION_NAME}' to {CHROMA_PERSIST_DIR}")

    return vector_store


if __name__ == "__main__":
    build_vector_store()
