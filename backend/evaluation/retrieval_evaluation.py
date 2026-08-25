"""Read-only benchmark of the existing vector/graph/hybrid retrieval architecture.
Calls backend/rag/retrieval.py, backend/intelligence/hybrid_retrieval.py, and
backend/intelligence/graph_store.py exactly as backend/services/threat_analysis.py
and backend/services/classification.py already do -- nothing here changes retrieval
behavior, thresholds, or the graph.

The evaluation query set is not invented: it's the same five example queries already
shown to users in frontend/src/components/analysis/SampleQueries.tsx, one per real
threat-intelligence document, plus one deliberate off-topic negative control (already
an established pattern -- see README "Relevance Filtering" and
tests/test_api.py::test_unrelated_query_does_not_produce_valid_threat_analysis). Their
query->document association is the same one Phase 2's relevance threshold was
originally tuned and verified against; nothing new is fabricated here.
"""

from __future__ import annotations

import time

from backend.evaluation.schemas import RetrievalBenchmark, RetrievalQueryResult, latency_stats
from backend.intelligence.graph_store import graph_available
from backend.intelligence.hybrid_retrieval import gather_hybrid_evidence, graph_evidence_for_threat
from backend.intelligence.normalizer import slug_for
from backend.rag.config import RAG_SCORE_THRESHOLD, RAG_TOP_K
from backend.rag.retrieval import retrieve_relevant, vector_store_available

# (query, expected_threat_type) -- expected_threat_type is None for the negative
# control, which must legitimately return no vector evidence.
_EVALUATION_QUERIES: list[tuple[str, str | None]] = [
    ("Explain phishing attacks and mitigation", "phishing"),
    ("Explain ransomware attacks", "ransomware"),
    ("How can DDoS attacks be mitigated?", "ddos_attack"),
    ("What are SQL injection indicators?", "sql_injection"),
    ("Explain botnet attacks", "botnet"),
    ("What is the capital of France?", None),  # negative control
]


class RetrievalUnavailableError(RuntimeError):
    """Raised when the vector store or graph isn't built/available -- the benchmark
    never fabricates retrieval results for an unavailable backend."""


def run_retrieval_benchmark(queries: list[tuple[str, str | None]] | None = None) -> RetrievalBenchmark:
    if not vector_store_available():
        raise RetrievalUnavailableError(
            "Vector store not found. Build it first with: uv run python -m backend.rag.ingestion"
        )
    if not graph_available():
        raise RetrievalUnavailableError("Threat graph could not be built from data/threat_intel/*.txt.")

    queries = queries if queries is not None else _EVALUATION_QUERIES

    vector_latencies: list[float] = []
    graph_latencies: list[float] = []
    hybrid_latencies: list[float] = []
    per_query: list[RetrievalQueryResult] = []
    topic_matches = 0
    both_sources_count = 0
    non_control_count = 0

    for query, expected_threat_type in queries:
        vector_start = time.perf_counter()
        vector_hits = retrieve_relevant(query, k=RAG_TOP_K, threshold=RAG_SCORE_THRESHOLD)
        vector_duration_ms = (time.perf_counter() - vector_start) * 1000
        vector_latencies.append(vector_duration_ms)

        vector_top_threat_type = vector_hits[0][0].metadata.get("threat_type") if vector_hits else None

        graph_start = time.perf_counter()
        # Graph latency measured against the *expected* topic when known (so it's
        # measuring graph lookup cost independent of whether vector retrieval found
        # the right topic), falling back to whatever vector retrieval found for the
        # negative control (which has no expected topic at all).
        graph_lookup_target = expected_threat_type or vector_top_threat_type
        graph_relations = (
            graph_evidence_for_threat(slug_for(graph_lookup_target)) if graph_lookup_target else []
        )
        graph_duration_ms = (time.perf_counter() - graph_start) * 1000
        graph_latencies.append(graph_duration_ms)

        hybrid_start = time.perf_counter()
        hybrid = gather_hybrid_evidence(query, threat_hint=expected_threat_type)
        hybrid_duration_ms = (time.perf_counter() - hybrid_start) * 1000
        hybrid_latencies.append(hybrid_duration_ms)

        is_negative_control = expected_threat_type is None
        if not is_negative_control:
            non_control_count += 1
            if vector_top_threat_type == expected_threat_type:
                topic_matches += 1
            has_both = len(hybrid.vector_evidence) > 0 and len(hybrid.graph_evidence) > 0
            if has_both:
                both_sources_count += 1

        per_query.append(
            RetrievalQueryResult(
                query=query,
                is_negative_control=is_negative_control,
                expected_threat_type=expected_threat_type,
                vector_top_threat_type=vector_top_threat_type,
                vector_hit_count=len(vector_hits),
                vector_latency_ms=round(vector_duration_ms, 4),
                graph_relation_count=len(graph_relations),
                graph_latency_ms=round(graph_duration_ms, 4),
                hybrid_latency_ms=round(hybrid_duration_ms, 4),
                hybrid_has_vector_evidence=len(hybrid.vector_evidence) > 0,
                hybrid_has_graph_evidence=len(hybrid.graph_evidence) > 0,
            )
        )

    return RetrievalBenchmark(
        queries_evaluated=len(queries),
        vector_latency=latency_stats(vector_latencies),
        graph_latency=latency_stats(graph_latencies),
        hybrid_latency=latency_stats(hybrid_latencies),
        topic_coverage_rate=round(topic_matches / non_control_count, 6) if non_control_count else 0.0,
        hybrid_preserves_both_sources_rate=round(both_sources_count / non_control_count, 6) if non_control_count else 0.0,
        per_query=per_query,
        methodology_note=(
            "Query set: the 5 example queries already shown in the frontend's "
            "Threat Analysis page (one per real threat-intelligence document) plus "
            "one off-topic negative control. 'topic_coverage_rate' checks whether "
            "vector retrieval's top hit matches each query's pre-established "
            "intended topic -- a coverage/sanity signal, not formal retrieval "
            "accuracy/precision@k, since this repository has no independently-"
            "labeled relevance judgment set to compute that against."
        ),
    )
