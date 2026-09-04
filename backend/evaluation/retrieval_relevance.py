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

The 25 evaluation queries below are hand-authored against the actual content of
data/threat_intel/*.txt (five per real category), extending -- not replacing --
retrieval_evaluation.py's original 5-query set. Negative controls are intentionally
excluded from this module: with no target category, "Recall@k against category X" is
undefined for an off-topic query -- retrieval_evaluation.py's existing negative
control + topic_coverage_rate already covers that question.

Phase 17 (RQ2) expanded this set from 3 to 5 queries per category, provenance-checked
by re-reading every source .txt file: each added query paraphrases a real bullet
point already present in that category's document (e.g. phishing.txt's "multi-factor
authentication" / "email filtering" bullets, sql_injection.txt's "parameterized
queries" / "prepared statements" bullets), never a topic the document doesn't
actually cover. Going meaningfully beyond ~5 queries/category has diminishing value
here: this corpus has only 14 chunks total across 5 categories (roughly 2-3 chunks
per category), so additional queries increasingly re-target the same small set of
chunks rather than adding independent coverage -- this is a real ceiling on the
corpus, not a limitation of this module. See
backend/evaluation/statistics.py::MIN_N_FOR_INFERENCE for how the resulting per-query
sample size (25, or 5 per category) is treated for interval estimation.
"""

from __future__ import annotations

from collections import defaultdict

from backend.evaluation.schemas import (
    CategoryRelevanceReport,
    QueryRelevanceResult,
    RelevanceMetricsAtK,
    RetrievalRelevanceReport,
)
from backend.evaluation.statistics import MIN_N_FOR_INFERENCE, bootstrap_mean_ci
from backend.rag.retrieval import get_vector_store, vector_store_available

K_VALUES = [3, 5, 10]

# (query, category) -- category must match a real data/threat_intel/*.txt stem.
# Every query paraphrases a real bullet point in that category's source document --
# see module docstring for the Phase 17 (RQ2) provenance re-check.
EVALUATION_QUERIES: list[tuple[str, str]] = [
    ("Explain phishing attacks and how they steal credentials", "phishing"),
    ("What are common phishing indicators like fake login pages?", "phishing"),
    ("How does business email compromise work as a phishing technique?", "phishing"),
    ("What is spear phishing and how does it differ from general phishing?", "phishing"),
    ("How can multi-factor authentication and email filtering help prevent phishing attacks?", "phishing"),
    ("Explain ransomware and how it encrypts victim files", "ransomware"),
    ("What are common indicators of a ransomware infection?", "ransomware"),
    ("How is ransomware typically delivered to a victim, e.g. via phishing or exploit kits?", "ransomware"),
    ("What backup and patch management strategies help mitigate ransomware attacks?", "ransomware"),
    ("What are ransom notes and blocked file access as signs of a ransomware attack?", "ransomware"),
    ("How can DDoS attacks be mitigated?", "ddos_attack"),
    ("What are the signs of a distributed denial of service attack?", "ddos_attack"),
    ("Explain how a DDoS attack exhausts server resources with traffic", "ddos_attack"),
    ("What DDoS mitigation techniques include rate limiting and traffic filtering?", "ddos_attack"),
    ("What kinds of targets do DDoS attacks commonly affect, such as websites or cloud infrastructure?", "ddos_attack"),
    ("What are SQL injection indicators?", "sql_injection"),
    ("How do attackers exploit insecure input validation in a web app database?", "sql_injection"),
    ("Explain how SQL injection can bypass authentication", "sql_injection"),
    ("How do parameterized queries and prepared statements prevent SQL injection?", "sql_injection"),
    ("Can SQL injection be used to delete records or modify a database?", "sql_injection"),
    ("Explain botnet attacks and command-and-control servers", "botnet"),
    ("What indicates a device has become part of a botnet?", "botnet"),
    ("How are botnets used for DDoS attacks and spam campaigns?", "botnet"),
    ("How are botnets used for credential stuffing and malware distribution?", "botnet"),
    ("What mitigation strategies help defend against a botnet, such as network monitoring or endpoint detection?", "botnet"),
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

    recall_at_5_ci = precision_at_5_ci = None
    if 5 in k_values:
        recall_values = [m.recall_at_k for q in per_query for m in q.metrics if m.k == 5]
        precision_values = [m.precision_at_k for q in per_query for m in q.metrics if m.k == 5]
        if recall_values:
            recall_at_5_ci = bootstrap_mean_ci(recall_values)
            precision_at_5_ci = bootstrap_mean_ci(precision_values)

    n = len(per_query)
    return RetrievalRelevanceReport(
        k_values=k_values,
        queries_evaluated=n,
        categories=category_reports,
        overall=overall,
        per_query=per_query,
        recall_at_5_ci=recall_at_5_ci,
        precision_at_5_ci=precision_at_5_ci,
        methodology_note=(
            "Ground truth = each chunk's own threat_type metadata (deterministic, set "
            "at ingestion time), not an independently annotated relevance judgment "
            "set. Recall@k treats ALL chunks of a query's category as relevant, so "
            "Recall@k < 1.0 is expected whenever a category has more chunks than k. "
            "Raw top-k ranking bypasses the production relevance threshold "
            "(RAG_SCORE_THRESHOLD) deliberately -- see module docstring. "
            f"recall_at_5_ci/precision_at_5_ci are bootstrap intervals over "
            f"{n} per-query values -- "
            + (
                "descriptive only; sample size/design does not justify treating this "
                "interval as a precise population estimate."
                if n < MIN_N_FOR_INFERENCE
                else "n meets this project's inference threshold, but still reflects "
                "only this one small, hand-authored query set, not an external "
                "benchmark."
            )
        ),
    )
