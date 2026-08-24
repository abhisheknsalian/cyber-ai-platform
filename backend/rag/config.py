import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

THREAT_INTEL_DIR = Path(
    os.getenv("THREAT_INTEL_DIR", str(PROJECT_ROOT / "data" / "threat_intel"))
)
CHROMA_PERSIST_DIR = Path(
    os.getenv("CHROMA_PERSIST_DIR", str(PROJECT_ROOT / "rag" / "chroma_db"))
)
COLLECTION_NAME = os.getenv("CHROMA_COLLECTION", "threat_intel")

EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")

CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "300"))
CHUNK_OVERLAP = int(os.getenv("CHUNK_OVERLAP", "50"))

# Chroma's default collection space is squared-L2 distance, so *lower is more similar*.
# RAG_TOP_K candidates are retrieved, then only those with score <= RAG_SCORE_THRESHOLD
# are kept as "relevant" and passed to the LLM.
#
# The default threshold was chosen empirically (see README "Relevance Filtering"), by
# measuring similarity_search_with_score() against the five real threat-intel documents:
#   - On-topic queries (phishing/ransomware/ddos/sql_injection/botnet): best-matching
#     chunks scored 0.36-1.33.
#   - Off-topic queries ("capital of France", "bake a chocolate cake"): the closest
#     chunk still scored 1.77-1.98.
# 1.5 sits in the gap between those two clusters with margin on both sides.
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "5"))
RAG_SCORE_THRESHOLD = float(os.getenv("RAG_SCORE_THRESHOLD", "1.5"))

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
