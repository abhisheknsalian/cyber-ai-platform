"""RQ3 (item 6): does graph evidence change the DOWNSTREAM LLM analysis, even though
backend/evaluation/hybrid_ablation.py already established it does not change vector
RETRIEVAL RANKING (Phase 16 finding: relevance_delta == 0.0 at every k, because
hybrid retrieval augments vector results rather than re-ranking them -- see that
module's docstring). This module asks the separate, downstream question: for the
SAME retrieved text, does adding graph evidence to the LLM's context measurably
change what the LLM writes?

Methodology: for each query, build two evidence contexts from the identical
retrieved vector text (backend/intelligence/evidence_context.py::build_evidence_context())
-- one with the real graph evidence attached, one with graph_evidence=[] -- and call
the real generate_analysis_fragment() once against each. Compares severity,
attack_vectors, and (since backend/services/threat_analysis.py::analyze_query()
falls back to the LLM's own indicators/mitigations only when the graph has none)
indicator/mitigation counts between the two conditions.

Two real LLM calls per query (with vs. without graph evidence) -- costs roughly
double a single-pass evaluation, so this uses a small, deliberately bounded query set
(one per real category), same cost-control convention as
backend/evaluation/llm_evaluation.py's DEFAULT_CASES.
"""

from __future__ import annotations

from backend.evaluation.retrieval_relevance import EVALUATION_QUERIES
from backend.evaluation.schemas import DownstreamUsefulnessReport, DownstreamUsefulnessRow
from backend.intelligence.evidence_context import build_evidence_context, graph_derived_indicators, graph_derived_mitigations
from backend.intelligence.hybrid_retrieval import graph_evidence_for_threat
from backend.intelligence.normalizer import slug_for
from backend.rag.config import RAG_SCORE_THRESHOLD, RAG_TOP_K
from backend.rag.retrieval import retrieve_relevant, vector_store_available
from backend.services.llm import LLMResponseError, LLMUnavailableError, generate_analysis_fragment

_CATEGORIES_SEEN: set[str] = set()
_DEFAULT_QUERIES: list[tuple[str, str]] = []
for _query, _category in EVALUATION_QUERIES:
    if _category not in _CATEGORIES_SEEN:
        _DEFAULT_QUERIES.append((_query, _category))
        _CATEGORIES_SEEN.add(_category)


class DownstreamUsefulnessUnavailableError(RuntimeError):
    """Raised when a prerequisite (vector store, reachable Ollama) is missing --
    never fabricates a downstream-usefulness result."""


def run_downstream_usefulness(queries: list[tuple[str, str]] | None = None) -> DownstreamUsefulnessReport:
    if not vector_store_available():
        raise DownstreamUsefulnessUnavailableError(
            "Vector store not found. Build it first with: uv run python -m backend.rag.ingestion"
        )

    queries = queries if queries is not None else _DEFAULT_QUERIES
    rows: list[DownstreamUsefulnessRow] = []

    for query, category in queries:
        relevant = retrieve_relevant(query, k=RAG_TOP_K, threshold=RAG_SCORE_THRESHOLD)
        if not relevant:
            continue
        primary_threat = relevant[0][0].metadata.get("threat_type")
        primary_chunks = [(doc, score) for doc, score in relevant if doc.metadata.get("threat_type") == primary_threat]
        retrieved_text = "\n\n".join(doc.page_content for doc, _score in primary_chunks)
        graph_evidence = graph_evidence_for_threat(slug_for(primary_threat)) if primary_threat else []

        context_with_graph = build_evidence_context(retrieved_text=retrieved_text, graph_evidence=graph_evidence)
        context_without_graph = build_evidence_context(retrieved_text=retrieved_text, graph_evidence=[])

        try:
            fragment_with = generate_analysis_fragment(query, context_with_graph)
            fragment_without = generate_analysis_fragment(query, context_without_graph)
        except (LLMUnavailableError, LLMResponseError):
            continue

        indicators_with = graph_derived_indicators(graph_evidence) or fragment_with.indicators
        indicators_without = fragment_without.indicators  # no graph evidence in this context -> always the LLM's own fragment
        mitigations_with = graph_derived_mitigations(graph_evidence) or fragment_with.mitigations
        mitigations_without = fragment_without.mitigations

        rows.append(
            DownstreamUsefulnessRow(
                query=query,
                category=category,
                severity_changed=fragment_with.severity != fragment_without.severity,
                attack_vectors_changed=set(fragment_with.attack_vectors) != set(fragment_without.attack_vectors),
                with_graph_indicator_count=len(indicators_with),
                without_graph_indicator_count=len(indicators_without),
                with_graph_mitigation_count=len(mitigations_with),
                without_graph_mitigation_count=len(mitigations_without),
            )
        )

    n = len(rows)
    severity_changed_rate = round(sum(1 for r in rows if r.severity_changed) / n, 6) if n else 0.0
    attack_vectors_changed_rate = round(sum(1 for r in rows if r.attack_vectors_changed) / n, 6) if n else 0.0
    indicators_gained_rate = round(
        sum(1 for r in rows if r.with_graph_indicator_count > r.without_graph_indicator_count) / n, 6
    ) if n else 0.0
    mitigations_gained_rate = round(
        sum(1 for r in rows if r.with_graph_mitigation_count > r.without_graph_mitigation_count) / n, 6
    ) if n else 0.0

    return DownstreamUsefulnessReport(
        cases_evaluated=n,
        severity_changed_rate=severity_changed_rate,
        attack_vectors_changed_rate=attack_vectors_changed_rate,
        indicators_gained_with_graph_rate=indicators_gained_rate,
        mitigations_gained_with_graph_rate=mitigations_gained_rate,
        per_query=rows,
        methodology_note=(
            "Two real LLM calls per query against the IDENTICAL retrieved vector "
            "text -- one with real graph evidence attached to the context, one with "
            "graph_evidence=[]. This isolates the graph's downstream contribution "
            "from retrieval ranking (already measured as unchanged by "
            "hybrid_ablation.py). indicators/mitigations 'gained' reflects this "
            "architecture's real behavior (backend/services/threat_analysis.py): "
            "when the graph has evidence, indicators/mitigations come from it "
            "deterministically; when it doesn't (as simulated here), they fall back "
            "to the LLM's own, less consistently-structured fragment. "
            "severity/attack_vectors are genuinely LLM-authored in both conditions, "
            "so a change there reflects the LLM's own sensitivity to the graph "
            "evidence in its prompt, not a deterministic backend computation."
        ),
    )
