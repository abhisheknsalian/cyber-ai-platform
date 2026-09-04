"""RQ6 component ablation (Phase 17): what does each major pipeline component
contribute, measured progressively rather than assumed.

Four conditions, each orchestrating calls to the SAME existing production functions
used elsewhere in this evaluation layer (backend/ml/predictor.py::predict(),
backend/rag/retrieval.py::retrieve_relevant(),
backend/intelligence/hybrid_retrieval.py::gather_hybrid_evidence(),
backend/services/threat_analysis.py::analyze_query()) -- no invasive changes to
production code, no new code paths added to the application itself:

1. ml_only            -- classifier inference alone.
2. ml_plus_vector      -- classifier + vector-only retrieval (evidence coverage only,
                          no LLM call).
3. ml_plus_hybrid      -- classifier + hybrid (vector + graph) retrieval (evidence
                          coverage only, no LLM call).
4. ml_plus_retrieval_plus_llm -- the full real pipeline: classify_and_analyze()
                          (classifier evidence attached to the LLM context, exactly
                          as POST /analyze/classification does), adding schema
                          validity and grounding on top. A Phase 17 audit found an
                          earlier version of this condition called analyze_query()
                          directly with NO classifier evidence attached -- a real
                          scope mismatch from the other "total pipeline" latency
                          numbers elsewhere in this report (classifier evidence
                          measurably lengthens the LLM's generated summary, per
                          backend/services/llm.py's system prompt rule 8), fixed
                          here so this condition is directly comparable to
                          benchmark.py's total_classify_and_analyze and
                          reliability.py's total_latency.

This deliberately does NOT claim an "LLM-only" or "retrieval-only-without-ML"
condition: in this architecture, analyze_query()'s primary-threat resolution comes
from vector retrieval regardless of whether a classifier prediction is involved (see
backend/services/threat_analysis.py), so there is no existing code path that runs the
LLM over evidence with retrieval fully disabled -- building one purely for this
experiment would be new production-adjacent code, which the task instructions
explicitly rule out ("do not implement these if doing so requires invasive changes").
The four conditions above are the ones the existing architecture actually supports
without that.
"""

from __future__ import annotations

import time

from backend.evaluation.benchmark import DDOS_QUERY, DDOS_THREAT_STEM, sample_ddos_rows
from backend.evaluation.grounding import is_supported, significant_words
from backend.evaluation.schemas import AblationConditionResult, ComponentAblationReport, distribution_stats
from backend.intelligence.hybrid_retrieval import gather_hybrid_evidence
from backend.ml.config import RAW_DATA_PATH
from backend.ml.predictor import predict as classifier_predict
from backend.ml.schemas import ClassificationAnalysisRequest
from backend.rag.retrieval import retrieve_relevant, vector_store_available
from backend.services.classification import classify_and_analyze
from backend.services.llm import LLMResponseError, LLMUnavailableError

_DEFAULT_SAMPLE_SIZE = 10


class ComponentAblationUnavailableError(RuntimeError):
    """Raised when a hard prerequisite is missing -- never fabricates an ablation result."""


def _ml_only(features_samples) -> AblationConditionResult:
    latencies = []
    for features in features_samples:
        start = time.perf_counter()
        classifier_predict(features)
        latencies.append((time.perf_counter() - start) * 1000)
    return AblationConditionResult(
        condition="ml_only",
        description="Classifier inference alone -- no retrieval, no LLM call.",
        samples=len(features_samples),
        latency=distribution_stats(latencies),
    )


def _ml_plus_vector(features_samples) -> AblationConditionResult:
    latencies, chunk_counts = [], []
    for features in features_samples:
        start = time.perf_counter()
        classifier_predict(features)
        relevant = retrieve_relevant(DDOS_QUERY)
        latencies.append((time.perf_counter() - start) * 1000)
        chunk_counts.append(len(relevant))
    return AblationConditionResult(
        condition="ml_plus_vector",
        description="Classifier inference + vector-only retrieval -- evidence coverage, no graph, no LLM call.",
        samples=len(features_samples),
        latency=distribution_stats(latencies),
        evidence_chunk_count_mean=round(sum(chunk_counts) / len(chunk_counts), 4) if chunk_counts else None,
    )


def _ml_plus_hybrid(features_samples) -> AblationConditionResult:
    latencies, chunk_counts, entity_counts, relationship_counts = [], [], [], []
    for features in features_samples:
        start = time.perf_counter()
        classifier_predict(features)
        evidence = gather_hybrid_evidence(DDOS_QUERY, threat_hint=DDOS_THREAT_STEM)
        latencies.append((time.perf_counter() - start) * 1000)
        chunk_counts.append(len(evidence.vector_evidence))
        entity_counts.append(len({item.target_id for item in evidence.graph_evidence}))
        relationship_counts.append(len(evidence.graph_evidence))
    return AblationConditionResult(
        condition="ml_plus_hybrid",
        description="Classifier inference + hybrid (vector + graph) retrieval -- evidence coverage including graph, no LLM call.",
        samples=len(features_samples),
        latency=distribution_stats(latencies),
        evidence_chunk_count_mean=round(sum(chunk_counts) / len(chunk_counts), 4) if chunk_counts else None,
        graph_entity_count_mean=round(sum(entity_counts) / len(entity_counts), 4) if entity_counts else None,
        graph_relationship_count_mean=round(sum(relationship_counts) / len(relationship_counts), 4) if relationship_counts else None,
    )


def _ml_plus_retrieval_plus_llm(features_samples) -> AblationConditionResult:
    latencies = []
    schema_valid = 0
    grounding_ratios: list[float] = []
    for features in features_samples:
        # Phase 17 audit fix: this condition previously called analyze_query()
        # directly with no classifier evidence, while its own description already
        # claimed to measure "classify_and_analyze()'s ... path: classifier
        # context + hybrid evidence + LLM analysis" -- a real scope mismatch, not
        # just a documentation gap. When classifier evidence IS present in the
        # context, backend/services/llm.py's system prompt (rule 8) instructs the
        # LLM to also explain it, which measurably lengthens the generated summary
        # and therefore the latency (~1000ms difference observed in this audit) --
        # so the two code paths were silently measuring different prompts/outputs.
        # Calling the real classify_and_analyze() here makes this condition an
        # actual apples-to-apples "full pipeline" measurement, directly comparable
        # to benchmark.py's total_classify_and_analyze and reliability.py's
        # total_latency (both of which already went through classify_and_analyze()).
        classification = classifier_predict(features)
        request = ClassificationAnalysisRequest(prediction=classification.prediction, probability=classification.probability)

        start = time.perf_counter()
        try:
            _classification_result, result, _evidence = classify_and_analyze(request)
        except (LLMUnavailableError, LLMResponseError):
            latencies.append((time.perf_counter() - start) * 1000)
            continue
        latencies.append((time.perf_counter() - start) * 1000)
        schema_valid += 1

        if result is not None and result.status == "analyzed" and result.attack_vectors:
            relevant = retrieve_relevant(DDOS_QUERY)
            primary_chunks = [(doc, score) for doc, score in relevant if doc.metadata.get("threat_type") == result.threat]
            context_text = "\n\n".join(doc.page_content for doc, _score in primary_chunks)
            context_words = significant_words(context_text)
            supported = sum(1 for claim in result.attack_vectors if is_supported(claim, context_words))
            grounding_ratios.append(supported / len(result.attack_vectors))

    return AblationConditionResult(
        condition="ml_plus_retrieval_plus_llm",
        description=(
            "The full real pipeline: classify_and_analyze() -- classifier evidence "
            "attached to the LLM context + hybrid evidence + LLM analysis. Directly "
            "comparable to benchmark.py's total_classify_and_analyze and "
            "reliability.py's total_latency (all three now measure the identical "
            "classify_and_analyze() call in isolation)."
        ),
        samples=len(features_samples),
        latency=distribution_stats(latencies),
        schema_valid_rate=round(schema_valid / len(features_samples), 6) if features_samples else None,
        grounding_supported_ratio_mean=round(sum(grounding_ratios) / len(grounding_ratios), 6) if grounding_ratios else None,
    )


def run_component_ablation(*, sample_size: int = _DEFAULT_SAMPLE_SIZE) -> ComponentAblationReport:
    if not RAW_DATA_PATH.exists():
        raise ComponentAblationUnavailableError(f"Dataset not found at {RAW_DATA_PATH}.")
    if not vector_store_available():
        raise ComponentAblationUnavailableError(
            "Vector store not found. Build it first with: uv run python -m backend.rag.ingestion"
        )

    features_samples = sample_ddos_rows(sample_size)
    if not features_samples:
        raise ComponentAblationUnavailableError("No DDoS rows available in the dataset.")

    # backend/ml/predictor.py lazy-loads the joblib model artifact on its first call
    # (lru_cache) -- without this discarded warm-up call, whichever condition happens
    # to run first would absorb that one-time disk-load cost, making ml_only look
    # slower than later conditions purely from call ordering, not from doing more work.
    classifier_predict(features_samples[0])

    conditions = [
        _ml_only(features_samples),
        _ml_plus_vector(features_samples),
        _ml_plus_hybrid(features_samples),
        _ml_plus_retrieval_plus_llm(features_samples),
    ]

    return ComponentAblationReport(
        conditions=conditions,
        methodology_note=(
            "Progressive component availability, measured against the same real "
            "DDoS rows and the same real query for every condition -- each "
            "condition orchestrates calls to the existing production functions "
            "(classifier predict(), retrieve_relevant(), gather_hybrid_evidence(), "
            "analyze_query()), never a new or invasively-modified code path. This "
            "measures COMPONENT AVAILABILITY and its cost/evidence contribution, not "
            "a claim that each addition improves 'quality' -- e.g. "
            "ml_plus_hybrid's evidence_chunk_count/graph_entity_count are counts, "
            "not a quality judgment (see backend/evaluation/hybrid_ablation.py for "
            "the measured finding that graph evidence does not change vector "
            "ranking relevance in this architecture)."
        ),
    )
