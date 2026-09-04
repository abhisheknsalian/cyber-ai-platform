"""Formal Recall@k / Precision@k / Hit Rate@k / MRR@k retrieval evaluation (Phase 16).

Ground truth: a vector-store chunk's own `threat_type` metadata, set deterministically
at ingestion time (backend/rag/ingestion.py::file_path.stem, tagged onto every chunk
from that source document) -- never invented for this evaluation. For a query
associated with category `c`, every chunk currently in the collection tagged
threat_type == c is "relevant"; nothing else is. This is a real, verifiable property
of the actual knowledge base, not a fabricated relevance judgment.

Deliberately bypasses backend/rag/retrieval.py::retrieve_relevant()'s production
RAG_SCORE_THRESHOLD cutoff and queries the underlying Chroma store directly
(get_vector_store().similarity_search_with_score()) for raw top-k ranked results --
standard IR-evaluation practice for measuring RANKING quality independent of a
separate accept/reject threshold, which backend/evaluation/retrieval_evaluation.py's
topic_coverage_rate already evaluates on its own terms. Production retrieval code and
behavior are never modified; this only reads from the same store through the same
public API every production call site already uses.

The 15 evaluation queries below are hand-authored against the actual content of
data/threat_intel/*.txt (three per real category), extending -- not replacing --
retrieval_evaluation.py's original 5-query set. Negative controls are intentionally
excluded from this module: with no target category, "Recall@k against category X" is
undefined for an off-topic query -- retrieval_evaluation.py's existing negative
control + topic_coverage_rate already covers that question.
"""

from __future__ import annotations

from collections import defaultdict

from backend.evaluation.schemas import (
    CategoryRelevanceReport,
    QueryRelevanceResult,
    RelevanceMetricsAtK,
    RetrievalRelevanceReport,
)
from backend.rag.retrieval import get_vector_store, vector_store_available

K_VALUES = [3, 5, 10]

# (query, category) -- category must match a real data/threat_intel/*.txt stem.
EVALUATION_QUERIES: list[tuple[str, str]] = [
    ("Explain phishing attacks and how they steal credentials", "phishing"),
    ("What are common phishing indicators like fake login pages?", "phishing"),
    ("How does business email compromise work as a phishing technique?", "phishing"),
    ("Explain ransomware and how it encrypts victim files", "ransomware"),
    ("What are common indicators of a ransomware infection?", "ransomware"),
    ("How is ransomware typically delivered to a victim, e.g. via phishing or exploit kits?", "ransomware"),
    ("How can DDoS attacks be mitigated?", "ddos_attack"),
    ("What are the signs of a distributed denial of service attack?", "ddos_attack"),
    ("Explain how a DDoS attack exhausts server resources with traffic", "ddos_attack"),
    ("What are SQL injection indicators?", "sql_injection"),
    ("How do attackers exploit insecure input validation in a web app database?", "sql_injection"),
    ("Explain how SQL injection can bypass authentication", "sql_injection"),
    ("Explain botnet attacks and command-and-control servers", "botnet"),
    ("What indicates a device has become part of a botnet?", "botnet"),
    ("How are botnets used for DDoS attacks and spam campaigns?", "botnet"),
]


class RelevanceEvaluationUnavailableError(RuntimeError):
    """Raised when the vector store isn't built -- never fabricates retrieval results."""


def relevant_chunk_keys_by_category(store) -> dict[str, set[tuple[str, int]]]:
    """(source, chunk_index) is a stable, ingestion-assigned identity for a chunk --
    used instead of Chroma's internal id so this doesn't depend on chromadb id
    plumbing, only on metadata every production chunk already carries."""
    all_docs = store.get()
    by_category: dict[str, set[tuple[str, int]]] = defaultdict(set)
    for metadata in all_docs.get("metadatas", []):
        threat_type = metadata.get("threat_type")
        if threat_type:
            by_category[threat_type].add((metadata.get("source"), metadata.get("chunk_index")))
    return by_category


def ranked_chunk_keys(store, query: str, k: int) -> list[tuple[str, int]]:
    results = store.similarity_search_with_score(query, k=k)
    return [(doc.metadata.get("source"), doc.metadata.get("chunk_index")) for doc, _score in results]


def compute_metrics_at_k(ranked: list[tuple[str, int]], relevant: set[tuple[str, int]], k: int) -> RelevanceMetricsAtK:
    top_k = ranked[:k]
    hits = [key in relevant for key in top_k]
    num_relevant_retrieved = sum(hits)

    recall = (num_relevant_retrieved / len(relevant)) if relevant else 0.0
    precision = num_relevant_retrieved / k
    hit_rate = 1.0 if num_relevant_retrieved > 0 else 0.0
    reciprocal_rank = 0.0
    for rank, is_hit in enumerate(hits, start=1):
        if is_hit:
            reciprocal_rank = 1.0 / rank
            break

    return RelevanceMetricsAtK(
        k=k,
        recall_at_k=round(recall, 6),
        precision_at_k=round(precision, 6),
        hit_rate_at_k=round(hit_rate, 6),
        mrr_at_k=round(reciprocal_rank, 6),
    )


def average_metrics_at_k(rows: list[RelevanceMetricsAtK], k: int) -> RelevanceMetricsAtK:
    matching = [row for row in rows if row.k == k]
    n = len(matching) or 1
    return RelevanceMetricsAtK(
        k=k,
        recall_at_k=round(sum(r.recall_at_k for r in matching) / n, 6),
        precision_at_k=round(sum(r.precision_at_k for r in matching) / n, 6),
        hit_rate_at_k=round(sum(r.hit_rate_at_k for r in matching) / n, 6),
        mrr_at_k=round(sum(r.mrr_at_k for r in matching) / n, 6),
    )


def run_retrieval_relevance_evaluation(
    queries: list[tuple[str, str]] | None = None, *, k_values: list[int] | None = None
) -> RetrievalRelevanceReport:
    if not vector_store_available():
        raise RelevanceEvaluationUnavailableError(
            "Vector store not found. Build it first with: uv run python -m backend.rag.ingestion"
        )

    queries = queries if queries is not None else EVALUATION_QUERIES
    k_values = k_values if k_values is not None else K_VALUES
    store = get_vector_store()
    relevant_by_category = relevant_chunk_keys_by_category(store)
    max_k = max(k_values)

    per_query: list[QueryRelevanceResult] = []
    for query, category in queries:
        relevant = relevant_by_category.get(category, set())
        ranked = ranked_chunk_keys(store, query, max_k)
        per_query.append(
            QueryRelevanceResult(
                query=query,
                category=category,
                relevant_chunk_count=len(relevant),
                ranked_chunk_count=len(ranked),
                metrics=[compute_metrics_at_k(ranked, relevant, k) for k in k_values],
            )
        )

    categories_seen = sorted({category for _, category in queries})
    category_reports: list[CategoryRelevanceReport] = []
    for category in categories_seen:
        category_rows = [q for q in per_query if q.category == category]
        all_metrics = [m for q in category_rows for m in q.metrics]
        category_reports.append(
            CategoryRelevanceReport(
                category=category,
                query_count=len(category_rows),
                relevant_chunk_count=len(relevant_by_category.get(category, set())),
                metrics=[average_metrics_at_k(all_metrics, k) for k in k_values],
            )
        )

    all_metrics_overall = [m for q in per_query for m in q.metrics]
    overall = [average_metrics_at_k(all_metrics_overall, k) for k in k_values]

    return RetrievalRelevanceReport(
        k_values=k_values,
        queries_evaluated=len(per_query),
        categories=category_reports,
        overall=overall,
        per_query=per_query,
        methodology_note=(
            "Ground truth = each chunk's own threat_type metadata (deterministic, set "
            "at ingestion time), not an independently annotated relevance judgment "
            "set. Recall@k treats ALL chunks of a query's category as relevant, so "
            "Recall@k < 1.0 is expected whenever a category has more chunks than k. "
            "Raw top-k ranking bypasses the production relevance threshold "
            "(RAG_SCORE_THRESHOLD) deliberately -- see module docstring."
        ),
    )
