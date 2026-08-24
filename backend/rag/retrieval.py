from functools import lru_cache

from langchain_chroma import Chroma
from langchain_core.documents import Document

from backend.rag.config import (
    CHROMA_PERSIST_DIR,
    COLLECTION_NAME,
    RAG_SCORE_THRESHOLD,
    RAG_TOP_K,
)
from backend.rag.embeddings import get_embedding_model


@lru_cache(maxsize=1)
def get_vector_store() -> Chroma:
    return Chroma(
        collection_name=COLLECTION_NAME,
        embedding_function=get_embedding_model(),
        persist_directory=str(CHROMA_PERSIST_DIR),
    )


def vector_store_available() -> bool:
    """True if a persisted collection with at least one chunk exists on disk."""
    if not CHROMA_PERSIST_DIR.exists():
        return False
    try:
        result = get_vector_store().get(limit=1)
        return len(result.get("ids", [])) > 0
    except Exception:
        return False


def retrieve_relevant(
    query: str,
    k: int = RAG_TOP_K,
    threshold: float = RAG_SCORE_THRESHOLD,
) -> list[tuple[Document, float]]:
    """Retrieve up to k chunks and keep only those within the relevance threshold.

    Results are returned best-match-first. See RAG_SCORE_THRESHOLD in config.py for
    how the default threshold was derived. Returns an empty list when nothing in the
    knowledge base is actually relevant to the query -- callers should treat that as
    "no supported answer", not fall back to the nearest (irrelevant) chunks.
    """
    results = get_vector_store().similarity_search_with_score(query, k=k)
    return [(doc, score) for doc, score in results if score <= threshold]
