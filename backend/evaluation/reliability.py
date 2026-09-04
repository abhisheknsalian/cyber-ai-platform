"""RQ5 end-to-end reliability (Phase 17): repeated real pipeline runs, tracking
success/failure and full latency variability (mean/median/stddev/p95/min/max), not
just a single measurement.

Reuses backend/evaluation/benchmark.py's real-data sampling and per-stage isolation
approach (same functions the production classify_and_analyze()/analyze_query() path
calls) rather than building a second timing system -- see benchmark.py's own
docstring for why per-stage numbers are isolated calls, not sub-timings of one run.
This module's addition is repetition: benchmark.py's run_pipeline_benchmark() runs a
fixed sample once and raises immediately on the first failure (appropriate for a
latency benchmark, where any prerequisite failure invalidates the whole measurement);
this module instead runs N repeated true end-to-end classify_and_analyze() calls and
records PER-CALL success/failure, so a transient failure is data (a reliability
measurement), not an aborted run.

Ollama's one-time model-load cost on its first request is excluded via the same
discarded warm-up call benchmark.py uses -- documented explicitly in the report's
warm_up_excluded field so the condition is never silently assumed.

Measurement boundary for `total_latency` (important -- see the Phase 17 audit that
caught an earlier version of this getting this wrong): it times ONLY the real
classify_and_analyze(request) call, in its own isolated start/stop window --
IDENTICAL in scope to benchmark.py's `total_classify_and_analyze` stage, so the two
are directly comparable across modules. It deliberately does NOT include this
function's own isolated per-stage calls (classifier/vector/graph/hybrid/llm_analysis
above it in the loop, kept only for the separate `stage_latency` diagnostic dict) --
an earlier version started the total-latency timer before those isolated calls,
which meant it was timing TWO real LLM invocations per loop iteration (the isolated
llm_analysis call, plus the independent LLM call inside classify_and_analyze()) and
reporting their combined duration as if it were one end-to-end request's latency --
roughly double the true value. `stage_latency` and `total_latency` therefore answer
two different questions and must not be added together: stage_latency times this
module's OWN extra diagnostic calls (which a real request never makes), while
total_latency times exactly what a real request actually costs.
"""

from __future__ import annotations

import time

from backend.evaluation.benchmark import DDOS_QUERY, DDOS_THREAT_STEM, sample_ddos_rows
from backend.evaluation.schemas import ReliabilityReport, distribution_stats
from backend.intelligence.evidence_context import build_evidence_context
from backend.intelligence.hybrid_retrieval import gather_hybrid_evidence, graph_evidence_for_threat
from backend.intelligence.normalizer import slug_for
from backend.intelligence.schemas import ClassifierEvidence
from backend.ml.config import RAW_DATA_PATH
from backend.ml.predictor import predict as classifier_predict
from backend.ml.schemas import ClassificationAnalysisRequest
from backend.rag.retrieval import retrieve_relevant, vector_store_available
from backend.services.classification import classify_and_analyze
from backend.services.llm import LLMResponseError, LLMUnavailableError, generate_analysis_fragment

_DEFAULT_RUNS = 20


class ReliabilityUnavailableError(RuntimeError):
    """Raised when a hard prerequisite (dataset, vector store, reachable Ollama for
    the warm-up call) is missing -- never fabricates a reliability report."""


def run_reliability_experiment(*, runs: int = _DEFAULT_RUNS) -> ReliabilityReport:
    if not RAW_DATA_PATH.exists():
        raise ReliabilityUnavailableError(f"Dataset not found at {RAW_DATA_PATH}.")
    if not vector_store_available():
        raise ReliabilityUnavailableError(
            "Vector store not found. Build it first with: uv run python -m backend.rag.ingestion"
        )

    features_samples = sample_ddos_rows(runs)
    if not features_samples:
        raise ReliabilityUnavailableError("No DDoS rows available in the dataset.")
    # Repeat rows if fewer real rows are available than requested runs, rather than
    # silently running fewer iterations than asked for or inventing synthetic rows.
    if len(features_samples) < runs:
        features_samples = [features_samples[i % len(features_samples)] for i in range(runs)]

    try:
        generate_analysis_fragment(DDOS_QUERY, "Warm-up call; this response is discarded and not measured.")
    except LLMUnavailableError as exc:
        raise ReliabilityUnavailableError(f"Ollama is not reachable: {exc}") from exc

    graph_stem = slug_for(DDOS_THREAT_STEM)

    successes = 0
    failures = 0
    failure_reasons: dict[str, int] = {}
    total_latencies: list[float] = []
    stage_latencies: dict[str, list[float]] = {
        "classifier_inference": [], "vector_retrieval": [], "graph_retrieval": [],
        "hybrid_retrieval": [], "llm_analysis": [],
    }

    for features in features_samples:
        try:
            start = time.perf_counter()
            classification = classifier_predict(features)
            stage_latencies["classifier_inference"].append((time.perf_counter() - start) * 1000)

            start = time.perf_counter()
            relevant = retrieve_relevant(DDOS_QUERY)
            stage_latencies["vector_retrieval"].append((time.perf_counter() - start) * 1000)

            start = time.perf_counter()
            graph_evidence = graph_evidence_for_threat(graph_stem)
            stage_latencies["graph_retrieval"].append((time.perf_counter() - start) * 1000)

            start = time.perf_counter()
            gather_hybrid_evidence(DDOS_QUERY, threat_hint=DDOS_THREAT_STEM)
            stage_latencies["hybrid_retrieval"].append((time.perf_counter() - start) * 1000)

            primary_chunks = [(doc, score) for doc, score in relevant if doc.metadata.get("threat_type") == DDOS_THREAT_STEM]
            retrieved_text = "\n\n".join(doc.page_content for doc, _score in primary_chunks)
            classifier_evidence = ClassifierEvidence(
                prediction=classification.prediction, probability=classification.probability, model=classification.model
            )
            context = build_evidence_context(retrieved_text=retrieved_text, graph_evidence=graph_evidence, classifier=classifier_evidence)

            start = time.perf_counter()
            generate_analysis_fragment(DDOS_QUERY, context)
            stage_latencies["llm_analysis"].append((time.perf_counter() - start) * 1000)

            # total_latencies times ONLY this one call, in isolation -- matching
            # benchmark.py's total_classify_and_analyze definition exactly (see
            # run_pipeline_benchmark(), which times classify_and_analyze() alone in
            # its own start/stop window). The isolated per-stage calls above are
            # deliberately EXCLUDED from this window: an earlier version of this
            # function started the "total" timer before them, which meant
            # total_latencies double-counted the LLM cost (once from the isolated
            # llm_analysis call above, once from the real LLM call inside
            # classify_and_analyze() below) -- a measurement bug, not a genuine
            # end-to-end latency. Fixed so this field is directly comparable to
            # benchmark.py's total_classify_and_analyze, not roughly 2x it.
            request = ClassificationAnalysisRequest(prediction=classification.prediction, probability=classification.probability)
            total_start = time.perf_counter()
            classify_and_analyze(request)
            total_latencies.append((time.perf_counter() - total_start) * 1000)
            successes += 1
        except (LLMUnavailableError, LLMResponseError) as exc:
            failures += 1
            failure_reasons[type(exc).__name__] = failure_reasons.get(type(exc).__name__, 0) + 1
        except Exception as exc:  # noqa: BLE001 -- a reliability experiment must record ANY real failure, not just anticipated ones
            failures += 1
            failure_reasons[type(exc).__name__] = failure_reasons.get(type(exc).__name__, 0) + 1

    return ReliabilityReport(
        runs_attempted=len(features_samples),
        successes=successes,
        failures=failures,
        success_rate=round(successes / len(features_samples), 6),
        failure_rate=round(failures / len(features_samples), 6),
        failure_reasons=failure_reasons,
        total_latency=distribution_stats(total_latencies) if total_latencies else None,
        stage_latency={name: distribution_stats(values) for name, values in stage_latencies.items() if values},
        warm_up_excluded=True,
        note=(
            f"{len(features_samples)} repeated true end-to-end classify_and_analyze() "
            "calls against real DDoS rows from the local dataset, each call's "
            "success/failure recorded independently rather than aborting the whole "
            "run on the first failure. total_latency times ONLY the real "
            "classify_and_analyze() call (same scope as benchmark.py's "
            "total_classify_and_analyze stage -- directly comparable to it); "
            "stage_latency times this module's OWN additional isolated diagnostic "
            "calls (classifier/vector/graph/hybrid/llm_analysis run separately, "
            "before the timed classify_and_analyze() call, purely to report a "
            "per-stage breakdown) and must not be summed into total_latency -- a "
            "real request never makes those extra calls. One discarded warm-up LLM "
            "call ran before timing started, so Ollama's one-time model-load cost is "
            "excluded from every reported statistic (warm_up_excluded=true) -- this "
            "reflects steady-state latency, not cold-start latency."
        ),
    )
