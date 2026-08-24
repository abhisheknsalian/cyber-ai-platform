from functools import lru_cache

from langchain_huggingface import HuggingFaceEmbeddings

from backend.rag.config import EMBEDDING_MODEL


@lru_cache(maxsize=1)
def get_embedding_model() -> HuggingFaceEmbeddings:
    return HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
