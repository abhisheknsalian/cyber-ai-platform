"""End-to-end pipeline latency benchmark: times each stage of the real
classify_and_analyze() / analyze_query() path (backend/services/classification.py,
backend/services/threat_analysis.py) against real dataset rows and the real DDoS
sample query. Unlike ml_evaluation.py and retrieval_evaluation.py, this needs a
reachable Ollama server (the LLM analysis stage) -- see backend/evaluation/__main__.py's
--pipeline flag, which is the only thing that calls this module.

Per-stage numbers come from separate, isolated calls to the SAME functions the real
pipeline already calls (backend/ml/predictor.py's predict(), backend/rag/retrieval.py's
retrieve_relevant(), backend/intelligence/hybrid_retrieval.py's
graph_evidence_for_threat()/gather_hybrid_evidence(), backend/intelligence's
build_evidence_context(), backend/services/llm.py's generate_analysis_fragment())
rather than instrumenting production code paths, which would risk changing their
behavior. "total" is measured separately as one true, unmodified
classify_and_analyze() call, so it will not exactly equal the sum of the per-stage
numbers -- gather_hybrid_evidence's own internal vector search is itself a deliberate
extra call beyond analyze_query()'s (see classify_and_analyze()'s docstring), and the
isolated stage timings add a further round of calls on top of that. This mirrors an
already-existing, already-accepted duplication in the codebase; nothing here changes
what classify_and_analyze() or analyze_query() actually do.
"""

from __future__ import annotations

import time

from backend.evaluation.schemas import PipelineBenchmark, PipelineStageLatency, latency_stats
from backend.intelligence.evidence_context import build_evidence_context
from backend.intelligence.hybrid_retrieval import gather_hybrid_evidence, graph_evidence_for_threat
from backend.intelligence.normalizer import slug_for
from backend.intelligence.schemas import ClassifierEvidence
from backend.ml.config import RAW_DATA_PATH
from backend.ml.predictor import predict as classifier_predict
from backend.ml.preprocessing import load_and_clean_dataset, split_features_target
from backend.ml.schemas import ClassificationAnalysisRequest, NetworkTrafficFeatures
from backend.rag.retrieval import retrieve_relevant, vector_store_available
from backend.services.classification import PREDICTION_TO_QUERY, PREDICTION_TO_THREAT_STEM, classify_and_analyze
from backend.services.llm import LLMUnavailableError, generate_analysis_fragment

_PIPELINE_SAMPLE_SIZE = 10
DDOS_QUERY = PREDICTION_TO_QUERY["DDoS"]
DDOS_THREAT_STEM = PREDICTION_TO_THREAT_STEM["DDoS"]


class PipelineUnavailableError(RuntimeError):
    """Raised when a prerequisite (real dataset, trained model, built vector store,
    built threat graph, or a reachable Ollama server) is missing. The pipeline
    benchmark never substitutes a mocked or fabricated stage for one it can't run."""


def sample_ddos_rows(n: int, data_path=RAW_DATA_PATH) -> list[NetworkTrafficFeatures]:
    """Real DDoS rows from the real dataset, converted to the same
    NetworkTrafficFeatures schema POST /classify validates against -- exercises the
    classifier the same way a real request would, not a synthetic feature vector."""
    df = load_and_clean_dataset(data_path)
    X, y = split_features_target(df)
    ddos_rows = X[y == 1].head(n)
    return [NetworkTrafficFeatures(**row.to_dict()) for _, row in ddos_rows.iterrows()]


def run_pipeline_benchmark(*, sample_size: int = _PIPELINE_SAMPLE_SIZE) -> PipelineBenchmark:
    if not RAW_DATA_PATH.exists():
        raise PipelineUnavailableError(f"Dataset not found at {RAW_DATA_PATH}.")
    if not vector_store_available():
        raise PipelineUnavailableError(
            "Vector store not found. Build it first with: uv run python -m backend.rag.ingestion"
        )

    features_samples = sample_ddos_rows(sample_size)
    if not features_samples:
        raise PipelineUnavailableError("No DDoS rows available in the dataset to benchmark with.")

    # Ollama's first request after startup pays a one-time model-load cost that has
    # nothing to do with per-query inference latency. A discarded warm-up call before
    # timing starts (standard benchmarking practice) keeps that one-time cost out of
    # the reported llm_analysis statistics, and fails fast here rather than after
    # already spending time on the classifier/retrieval stages below.
    try:
        generate_analysis_fragment(DDOS_QUERY, "Warm-up call; this response is discarded and not measured.")
    except LLMUnavailableError as exc:
        raise PipelineUnavailableError(f"Ollama is not reachable: {exc}") from exc

    classifier_latencies: list[float] = []
    vector_latencies: list[float] = []
    graph_latencies: list[float] = []
    hybrid_latencies: list[float] = []
    llm_latencies: list[float] = []
    total_latencies: list[float] = []

    graph_stem = slug_for(DDOS_THREAT_STEM)

    for features in features_samples:
        start = time.perf_counter()
        classification = classifier_predict(features)
        classifier_latencies.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        relevant = retrieve_relevant(DDOS_QUERY)
        vector_latencies.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        graph_evidence = graph_evidence_for_threat(graph_stem)
        graph_latencies.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        gather_hybrid_evidence(DDOS_QUERY, threat_hint=DDOS_THREAT_STEM)
        hybrid_latencies.append((time.perf_counter() - start) * 1000)

        # Same context-building step analyze_query() performs before calling the LLM
        # (backend/services/threat_analysis.py) -- isolating only the LLM call itself.
        primary_chunks = [(doc, score) for doc, score in relevant if doc.metadata.get("threat_type") == DDOS_THREAT_STEM]
        retrieved_text = "\n\n".join(doc.page_content for doc, _score in primary_chunks)
        classifier_evidence = ClassifierEvidence(
            prediction=classification.prediction, probability=classification.probability, model=classification.model
        )
        context = build_evidence_context(retrieved_text=retrieved_text, graph_evidence=graph_evidence, classifier=classifier_evidence)

        start = time.perf_counter()
        try:
            generate_analysis_fragment(DDOS_QUERY, context)
        except LLMUnavailableError as exc:
            raise PipelineUnavailableError(f"Ollama is not reachable: {exc}") from exc
        llm_latencies.append((time.perf_counter() - start) * 1000)

        request = ClassificationAnalysisRequest(prediction=classification.prediction, probability=classification.probability)
        total_start = time.perf_counter()
        classify_and_analyze(request)
        total_latencies.append((time.perf_counter() - total_start) * 1000)

    stages = [
        PipelineStageLatency(stage="classifier_inference", latency=latency_stats(classifier_latencies)),
        PipelineStageLatency(stage="vector_retrieval", latency=latency_stats(vector_latencies)),
        PipelineStageLatency(stage="graph_retrieval", latency=latency_stats(graph_latencies)),
        PipelineStageLatency(stage="hybrid_retrieval", latency=latency_stats(hybrid_latencies)),
        PipelineStageLatency(stage="llm_analysis", latency=latency_stats(llm_latencies)),
        PipelineStageLatency(stage="total_classify_and_analyze", latency=latency_stats(total_latencies)),
    ]

    # Phase 16, Part H: each stage's share of end-to-end latency. Divides by
    # "total_classify_and_analyze"'s own mean (one true, unmodified pipeline call --
    # see note below) -- shares will not sum to exactly 100% for the same reason the
    # stage means don't sum to the total mean: the isolated per-stage calls are a
    # second round of calls on top of what classify_and_analyze() itself does
    # internally (e.g. gather_hybrid_evidence's own extra vector search), not
    # sub-timings sliced out of one run.
    total_mean = next((s.latency.mean_ms for s in stages if s.stage == "total_classify_and_analyze"), None)
    stage_latency_share_pct = (
        {s.stage: round(s.latency.mean_ms / total_mean * 100, 2) for s in stages if total_mean}
        if total_mean
        else None
    )

    return PipelineBenchmark(
        queries_evaluated=len(features_samples),
        stages=stages,
        stage_latency_share_pct=stage_latency_share_pct,
        note=(
            "Real DDoS rows from the local dataset, run through the unmodified "
            "classify_and_analyze() / analyze_query() path; requires a reachable "
            "Ollama server for the llm_analysis and total stages. "
            "classifier_inference/vector_retrieval/graph_retrieval/hybrid_retrieval/"
            "llm_analysis are isolated, separate calls to the same functions the "
            "pipeline itself calls (see module docstring) -- not sub-timings carved "
            "out of one run -- so they will not sum exactly to "
            "total_classify_and_analyze, which is one true, unmodified pipeline call."
        ),
    )
