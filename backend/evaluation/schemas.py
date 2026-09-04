"""Typed report structures for the Phase 11 evaluation layer. Every section is
independently optional (None) so the report can honestly represent "this section
could not be produced" (e.g. no local dataset, no Ollama) rather than omitting the
key silently or fabricating a value.
"""

from __future__ import annotations

from typing import Literal

import numpy as np
from pydantic import BaseModel, Field


class LatencyStats(BaseModel):
    """Summary of a set of per-call durations, in milliseconds."""

    count: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    min_ms: float
    max_ms: float


def latency_stats(durations_ms: list[float]) -> LatencyStats:
    """Shared by every evaluation module that times a set of calls (ml_evaluation,
    retrieval_evaluation, benchmark) so the summary statistic definition stays in one
    place."""
    array = np.array(durations_ms, dtype=float)
    return LatencyStats(
        count=len(array),
        mean_ms=round(float(array.mean()), 4),
        p50_ms=round(float(np.percentile(array, 50)), 4),
        p95_ms=round(float(np.percentile(array, 95)), 4),
        min_ms=round(float(array.min()), 4),
        max_ms=round(float(array.max()), 4),
    )


class DatasetSummary(BaseModel):
    path: str
    total_rows_before_cleaning: int
    rows_after_cleaning: int
    duplicate_rows_removed: int
    duplicate_rate: float
    missing_value_total: int
    infinite_value_total: int
    class_distribution: dict[str, int]
    class_labels: list[str]


class ModelSummary(BaseModel):
    model_path: str
    model_version: str | None
    n_estimators: int | None
    random_state: int | None
    feature_count: int
    trained_class_labels: list[str]


class PerClassMetrics(BaseModel):
    precision: float
    recall: float
    f1: float
    support: int


class ClassificationMetrics(BaseModel):
    """One evaluation pass over one split of real data against the existing,
    unmodified trained model."""

    split: Literal["held_out_test", "full_dataset"]
    split_description: str
    samples: int
    accuracy: float
    balanced_accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    f1_weighted: float
    # None (not 0.0) when not computable -- e.g. more than 2 classes present, or only
    # one class present in this split -- rather than a misleading fabricated value.
    roc_auc: float | None
    pr_auc: float | None
    positive_label: str | None
    confusion_matrix: list[list[int]]
    confusion_matrix_labels: list[str]
    per_class: dict[str, PerClassMetrics]
    class_distribution: dict[str, int]
    inference_latency_ms: LatencyStats
    mean_winning_class_confidence: float


class ThresholdPoint(BaseModel):
    threshold: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    false_negative_rate: float


class ThresholdAnalysis(BaseModel):
    positive_label: str
    points: list[ThresholdPoint]
    best_f1_threshold: float
    best_f1: float
    production_threshold: float
    note: str = (
        "Evaluation only. The production classifier's decision boundary "
        "(argmax over class_probabilities, i.e. an implicit 0.5 threshold on the "
        "binary positive-class probability) is not changed by this analysis."
    )


class CalibrationBin(BaseModel):
    bin_lower: float
    bin_upper: float
    count: int
    mean_predicted_probability: float | None
    empirical_positive_rate: float | None


class CalibrationReport(BaseModel):
    positive_label: str
    brier_score: float
    bins: list[CalibrationBin]
    note: str


class RetrievalQueryResult(BaseModel):
    query: str
    is_negative_control: bool
    expected_threat_type: str | None
    vector_top_threat_type: str | None
    vector_hit_count: int
    vector_latency_ms: float
    graph_relation_count: int
    graph_latency_ms: float
    hybrid_latency_ms: float
    hybrid_has_vector_evidence: bool
    hybrid_has_graph_evidence: bool


class RetrievalBenchmark(BaseModel):
    queries_evaluated: int
    vector_latency: LatencyStats
    graph_latency: LatencyStats
    hybrid_latency: LatencyStats
    # Fraction of non-control queries whose top vector hit's threat_type matched the
    # query's pre-established expected topic (see README "Relevance Filtering" for
    # where that query->topic mapping originally comes from). A coverage/sanity
    # signal, deliberately not called "retrieval accuracy" -- there is no independent,
    # externally-labeled relevance judgment set in this repository to justify that
    # term.
    topic_coverage_rate: float
    # Fraction of non-control queries where hybrid evidence contained BOTH vector and
    # graph evidence -- directly answers "does hybrid retrieval add graph evidence
    # without dropping vector evidence, or vice versa".
    hybrid_preserves_both_sources_rate: float
    per_query: list[RetrievalQueryResult]
    methodology_note: str


class PipelineStageLatency(BaseModel):
    stage: str
    latency: LatencyStats


class PipelineBenchmark(BaseModel):
    queries_evaluated: int
    stages: list[PipelineStageLatency]
    note: str
    # Phase 16, additive: each stage's mean latency as a percentage of
    # "total_classify_and_analyze"'s mean -- answers "what fraction of end-to-end
    # latency does each stage contribute" without adding a field to the existing,
    # tested PipelineStageLatency/LatencyStats shapes (see
    # tests/test_evaluation_benchmark.py's exact-field-set assertions on those).
    # None when the benchmark has no "total_classify_and_analyze" stage to divide by.
    stage_latency_share_pct: dict[str, float] | None = None


# --- Phase 16: formal retrieval-relevance (Recall/Precision/HitRate/MRR @ k) -------
#
# Ground truth: a vector-store chunk's own `threat_type` metadata (set deterministically
# at ingestion time, backend/rag/ingestion.py -- never invented for this evaluation).
# For a query associated with category `c`, every chunk tagged threat_type == c in the
# CURRENT collection is "relevant"; nothing else is. See
# backend/evaluation/retrieval_relevance.py's module docstring for the full
# methodology, including why this deliberately bypasses the production relevance
# threshold to get raw top-k ranked results.


class RelevanceMetricsAtK(BaseModel):
    k: int
    recall_at_k: float
    precision_at_k: float
    hit_rate_at_k: float
    mrr_at_k: float


class QueryRelevanceResult(BaseModel):
    query: str
    category: str
    relevant_chunk_count: int
    ranked_chunk_count: int
    metrics: list[RelevanceMetricsAtK]


class CategoryRelevanceReport(BaseModel):
    category: str
    query_count: int
    relevant_chunk_count: int
    metrics: list[RelevanceMetricsAtK]  # averaged over this category's queries, one row per k


class RetrievalRelevanceReport(BaseModel):
    k_values: list[int]
    queries_evaluated: int
    categories: list[CategoryRelevanceReport]
    overall: list[RelevanceMetricsAtK]  # macro-averaged over all categories, one row per k
    per_query: list[QueryRelevanceResult]
    methodology_note: str


# --- Phase 16: vector-only vs. hybrid (vector + graph) ablation --------------------


class HybridAblationQueryResult(BaseModel):
    query: str
    category: str
    vector_only_latency_ms: float
    hybrid_latency_ms: float
    graph_entity_count: int
    graph_relationship_count: int
    hybrid_added_graph_evidence: bool


class HybridAblationReport(BaseModel):
    queries_evaluated: int
    # Recall@k/Precision@k/MRR are IDENTICAL between vector-only and hybrid in this
    # architecture by construction -- hybrid retrieval augments vector results with
    # graph evidence, it does not re-rank or filter them (see
    # backend/intelligence/hybrid_retrieval.py::gather_hybrid_evidence()). Recorded
    # here explicitly (delta == 0.0 for every k) rather than omitted, so that fact is
    # a measured, documented finding -- not an assumption and not silently dropped.
    vector_only_relevance: list[RelevanceMetricsAtK]
    hybrid_relevance: list[RelevanceMetricsAtK]
    relevance_delta: list[RelevanceMetricsAtK]  # hybrid - vector_only, per k; expect all-zero
    mean_latency_overhead_ms: float  # hybrid_latency_ms - vector_only_latency_ms, averaged
    evidence_coverage_rate: float  # fraction of queries where hybrid added >=1 graph relationship
    mean_graph_entity_count: float
    mean_graph_relationship_count: float
    per_query: list[HybridAblationQueryResult]
    methodology_note: str


# --- Phase 16: LLM analysis evaluation ---------------------------------------------
#
# Only backend/services/llm.py's genuinely LLM-authored output fields are evaluated
# here: severity, summary, attack_vectors, and the insufficient_context decision.
# `threat`, `mitre_attack`, `indicators`, and `mitigations` are deterministically
# derived from source documents / the threat graph in this architecture (see
# backend/services/threat_analysis.py::analyze_query()), not LLM-generated -- treating
# them as an "LLM quality" dimension would misattribute a backend-computed,
# already-correct-by-construction value to the model.


class LLMAutomatedMetrics(BaseModel):
    cases_evaluated: int
    schema_valid_rate: float  # fraction that produced a schema-conformant response at all
    # Of the cases with a known-answerable query (one of the 5 real categories):
    # fraction correctly NOT flagged insufficient_context.
    correct_relevance_on_topic_rate: float | None
    # Of the negative-control (off-topic) cases: fraction correctly flagged
    # insufficient_context. None if no negative controls were run.
    correct_relevance_off_topic_rate: float | None
    non_empty_attack_vectors_rate: float  # among "analyzed" (non-insufficient-context) cases
    severity_present_rate: float  # among "analyzed" cases


class LLMRubricDimension(BaseModel):
    """A dimension that genuinely requires human judgment. `scores` is empty until a
    human annotator fills in the CSV/JSON template this module writes -- see
    backend/evaluation/llm_evaluation.py::write_rubric_template()."""

    name: str
    description: str
    scale_description: str  # e.g. "0=incorrect, 1=partially correct, 2=correct"
    status: Literal["not_yet_annotated", "annotated"]
    mean_score: float | None = None
    scores: list[int] = Field(default_factory=list)


class LLMEvaluationReport(BaseModel):
    automated: LLMAutomatedMetrics
    rubric_dimensions: list[LLMRubricDimension]
    rubric_template_path: str | None
    methodology_note: str


# --- Phase 16: grounding / hallucination-proxy check --------------------------------


class GroundingQueryResult(BaseModel):
    query: str
    category: str
    claims_checked: int
    claims_supported: int
    supported_ratio: float | None  # None if claims_checked == 0


class GroundingReport(BaseModel):
    cases_evaluated: int
    mean_supported_ratio: float | None
    per_query: list[GroundingQueryResult]
    methodology_note: str


class EnvironmentInfo(BaseModel):
    """Reproducibility metadata -- Phase 16. Captured fresh at report-generation time,
    never hardcoded."""

    os: str
    os_version: str
    python_version: str
    hostname_hash: str  # sha256 prefix, not the raw hostname -- identifying, not secret, but no reason to publish it verbatim
    ollama_cli_version: str | None
    ollama_model: str
    random_seed: int


class EvaluationReport(BaseModel):
    generated_at: str
    environment: EnvironmentInfo | None = None
    dataset: DatasetSummary | None
    model: ModelSummary | None
    classification: dict[str, ClassificationMetrics] = Field(default_factory=dict)
    threshold_analysis: ThresholdAnalysis | None = None
    calibration: CalibrationReport | None = None
    retrieval: RetrievalBenchmark | None = None
    retrieval_relevance: RetrievalRelevanceReport | None = None
    hybrid_ablation: HybridAblationReport | None = None
    llm_evaluation: LLMEvaluationReport | None = None
    grounding: GroundingReport | None = None
    pipeline: PipelineBenchmark | None = None
    limitations: list[str] = Field(default_factory=list)
