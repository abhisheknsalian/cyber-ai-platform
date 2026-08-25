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


class EvaluationReport(BaseModel):
    generated_at: str
    dataset: DatasetSummary | None
    model: ModelSummary | None
    classification: dict[str, ClassificationMetrics] = Field(default_factory=dict)
    threshold_analysis: ThresholdAnalysis | None = None
    calibration: CalibrationReport | None = None
    retrieval: RetrievalBenchmark | None = None
    pipeline: PipelineBenchmark | None = None
    limitations: list[str] = Field(default_factory=list)
