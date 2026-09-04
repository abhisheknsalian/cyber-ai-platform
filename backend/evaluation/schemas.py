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
    # Phase 17, RQ5: standard deviation, needed to report variability (not just
    # central tendency) for the end-to-end reliability experiment. Additive to an
    # already-shipped, tested field set (tests/test_evaluation_benchmark.py's exact
    # {"count","mean_ms","p50_ms","p95_ms","min_ms","max_ms"} assertion is updated to
    # include this in the same change) -- a deliberate, requested schema change, not
    # accidental breakage.
    stddev_ms: float


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
        # ddof=0 (population stddev): this describes the observed sample itself, not
        # an estimate of a larger population's spread.
        stddev_ms=round(float(array.std(ddof=0)), 4) if len(array) > 0 else 0.0,
    )


class DistributionStats(BaseModel):
    """Generic sibling of LatencyStats for non-latency numeric distributions (e.g.
    nearest-neighbor distances) -- same summary shape, unitless so it isn't
    mislabeled as milliseconds."""

    count: int
    mean: float
    median: float
    stddev: float
    p95: float
    min: float
    max: float


def distribution_stats(values: list[float]) -> DistributionStats:
    array = np.array(values, dtype=float)
    return DistributionStats(
        count=len(array),
        mean=round(float(array.mean()), 6),
        median=round(float(np.percentile(array, 50)), 6),
        stddev=round(float(array.std(ddof=0)), 6),
        p95=round(float(np.percentile(array, 95)), 6),
        min=round(float(array.min()), 6),
        max=round(float(array.max()), 6),
    )


class ConfidenceInterval(BaseModel):
    """A statistical interval, computed only where sample size/design genuinely
    justify it (see backend/evaluation/statistics.py). Never attached to a metric
    whose sample size doesn't support inference -- see each report's
    methodology_note for that judgment call."""

    point_estimate: float
    lower: float
    upper: float
    confidence_level: float
    method: Literal["wilson_score", "bootstrap_percentile"]
    n_resamples: int | None = None


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
    # Phase 17: Wilson score interval on accuracy -- justified here (unlike most
    # other evaluation sections) because held_out_test has tens of thousands of
    # samples. None for splits too small to justify it (see statistics.py).
    accuracy_ci: ConfidenceInterval | None = None


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
    # Phase 17: bootstrap CIs over per-query Recall@5/Precision@5 -- a representative
    # k, not all of them, to avoid a wall of near-identical intervals. Reported with
    # the sample-size caveat spelled out in methodology_note; see statistics.py.
    recall_at_5_ci: ConfidenceInterval | None = None
    precision_at_5_ci: ConfidenceInterval | None = None


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


class RubricCaseScore(BaseModel):
    """Phase 18 (P0.2): one annotator's score for one case on one rubric dimension.
    Deliberately distinguishes three states that must never be collapsed into each
    other: a blank cell (`"unscored"`, e.g. not-yet-annotated by the time of
    reading), a cell containing something other than 0/1/2 (`"invalid"` -- reported,
    excluded, never coerced to a number), and a genuine 0/1/2 value (`"valid"`,
    the only status with `value` set). See
    backend/evaluation/llm_rubric_scoring.py::parse_annotation_csv()."""

    case_id: int
    status: Literal["unscored", "valid", "invalid"]
    value: int | None = None  # 0, 1, or 2 -- set only when status == "valid"
    raw_value: str | None = None  # the original cell text, kept for "invalid" entries as an audit trail
    # None when there is exactly one annotator (the common case); set to that
    # annotator's id when 2+ annotators' CSVs were scored together, so per-annotator
    # scores for the same case_id can coexist in one dimension's `scores` list
    # without one silently overwriting the other.
    annotator_id: str | None = None


class LLMRubricDimension(BaseModel):
    """A dimension that genuinely requires human judgment. `scores` is empty until a
    human annotator fills in the CSV/JSON template this module writes -- see
    backend/evaluation/llm_evaluation.py::write_rubric_template()."""

    name: str
    description: str
    scale_description: str  # e.g. "0=incorrect, 1=partially correct, 2=correct"
    # Phase 18 (P0.2) adds "partially_annotated" -- some but not all on-topic cases
    # scored. "annotated" is reserved for every on-topic case having a valid score.
    status: Literal["not_yet_annotated", "partially_annotated", "annotated"]
    mean_score: float | None = None
    # Phase 18 (P0.2): was list[int] (Phase 16) -- now case-linked, and able to
    # represent unscored/invalid entries explicitly rather than only ever holding
    # already-valid integers. A deliberate, documented breaking type change (see
    # Phase 18 turn's final report), not a silently-compatible extension.
    scores: list[RubricCaseScore] = Field(default_factory=list)
    # Counts over on-topic cases only -- negative controls are never scored on any
    # rubric dimension (see llm_rubric_scoring.py).
    valid_count: int = 0
    invalid_count: int = 0
    unscored_count: int = 0
    on_topic_case_count: int = 0


class InterRaterAgreementReport(BaseModel):
    """Phase 18 (P0.2): populated ONLY when 2+ annotators' filled CSVs were
    actually supplied to score_annotations() -- never fabricated, never inferred
    from a single annotator. See llm_rubric_scoring.py."""

    annotator_ids: list[str]
    dimension: str
    cases_compared: int
    percent_exact_agreement: float
    # None (not NaN, never fabricated) when kappa is mathematically undefined -- the
    # degenerate case where both annotators gave the same constant score on every
    # compared case, so there is zero variance to explain and Cohen's kappa's
    # "agreement beyond chance" correction divides by zero. percent_exact_agreement
    # (well-defined, 1.0 in that case) is still reported. See
    # llm_rubric_scoring.py::_inter_rater_for_dimension().
    cohens_weighted_kappa: float | None
    note: str


class LLMRubricAnnotationSummary(BaseModel):
    """Phase 18 (P0.2): the result of scoring one or more humans' filled-in copies
    of the rubric template -- a SEPARATE artifact from LLMEvaluationReport (which
    backend/evaluation/__main__.py's fully-automated --llm flow produces without
    any human input) so the automated/human distinction stays structurally visible,
    not just documented in prose. Never produced by the automated evaluation
    pipeline; only by backend/evaluation/llm_rubric_scoring.py, which requires a
    human-authored CSV file to already exist on disk."""

    annotator_ids: list[str]
    on_topic_case_count: int
    negative_control_case_count: int
    dimensions: list[LLMRubricDimension]
    # None (not a fabricated agreement value) unless 2+ annotators were supplied.
    inter_rater: list[InterRaterAgreementReport] | None = None
    single_annotator_note: str | None = None
    # Human-readable audit trail of any row this scoring run excluded and why
    # (invalid score text, a case_id not found among the known cases, a
    # negative-control row that carried a stray score, etc.) -- never silent.
    excluded_rows: list[str] = Field(default_factory=list)
    methodology_note: str


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
    # Phase 17: a second, complementary signal using the same sentence-transformer
    # embedding model already loaded for production RAG retrieval (no new model
    # downloaded) -- cosine similarity between a claim and its best-matching context
    # sentence, not lexical word overlap. Still NOT entailment/hallucination
    # detection: high cosine similarity means "topically similar wording", not
    # "logically implied by". See GroundingReport.methodology_note.
    claims_supported_semantic: int | None = None
    supported_ratio_semantic: float | None = None


class GroundingReport(BaseModel):
    cases_evaluated: int
    mean_supported_ratio: float | None
    mean_supported_ratio_semantic: float | None = None
    per_query: list[GroundingQueryResult]
    methodology_note: str


# --- Phase 17, RQ1: data leakage / generalization audit ----------------------------
#
# This audit describes properties of the REAL local CICIDS2017 CSV and the REAL
# production train/test split reconstruction. It never invents grouping metadata
# (Flow ID / Source IP / Timestamp) that the distributed CSV does not contain -- see
# backend/evaluation/leakage_audit.py's module docstring for exactly what this CSV
# variant does and doesn't carry.


class ExactDuplicateAudit(BaseModel):
    total_rows_before_cleaning: int
    duplicate_rows_before_cleaning: int
    duplicate_rate_before_cleaning: float
    duplicates_removed_before_split: bool
    note: str


class CrossLabelCollisionAudit(BaseModel):
    """Rows whose FEATURE_COLUMNS values are identical but whose Label differs --
    NOT caught by the production pipeline's whole-row drop_duplicates() (which only
    removes rows identical across features AND label), and NOT prevented by the
    train/test split itself. A non-zero rate means the same measured traffic pattern
    was observed under two different labels somewhere in the raw capture -- genuine
    label ambiguity in the source data, not a code defect."""

    rows_checked: int
    distinct_feature_vectors: int
    colliding_feature_vector_groups: int
    affected_rows: int
    affected_row_rate: float
    note: str


class NearDuplicateAudit(BaseModel):
    """Standardized-feature nearest-neighbor distance from a random sample of test
    rows to their closest training row (production random split). Exact duplicates
    are already removed before the split (see ExactDuplicateAudit); this measures
    how close the NEAREST surviving neighbor still is, which is what the CICIDS2017
    near-duplicate-flow literature (e.g. Engelen et al., "Troubleshooting an
    Intrusion Detection Dataset", 2021) flags as the likelier source of inflated
    scores on this dataset family."""

    method: str
    distance_metric: str
    train_rows: int
    test_sample_size: int
    seed: int
    distance: DistributionStats
    near_duplicate_fraction_by_threshold: dict[str, float]
    note: str


class FamilyGroupingAudit(BaseModel):
    """Groups rows that become identical after rounding FEATURE_COLUMNS to a coarser
    precision -- a heuristic proxy for 'likely the same or a near-identical flow',
    used only because this CSV variant has no real Flow ID/session identifier to
    group by. Explicitly a heuristic, not a verified ground-truth grouping."""

    significant_digits: int
    total_rows: int
    family_count: int
    largest_family_size: int
    mean_family_size: float
    rows_in_multi_row_families: int
    fraction_rows_in_multi_row_families: float
    note: str


class SplitFeasibilityAudit(BaseModel):
    temporal_split_possible: bool
    host_split_possible: bool
    file_split_possible: bool
    family_grouped_split_possible: bool
    reason: str


class LeakageAuditReport(BaseModel):
    dataset_path: str
    exact_duplicates: ExactDuplicateAudit
    cross_label_collisions: CrossLabelCollisionAudit
    near_duplicates: NearDuplicateAudit
    family_grouping: FamilyGroupingAudit
    split_feasibility: SplitFeasibilityAudit
    methodology_note: str


# --- Phase 17, RQ1: generalization experiment (baseline vs. stronger splits) -------


class SplitEvaluationResult(BaseModel):
    split_name: str
    split_description: str
    train_rows: int
    test_rows: int
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    roc_auc: float | None
    pr_auc: float | None
    confusion_matrix: list[list[int]]
    confusion_matrix_labels: list[str]
    class_distribution: dict[str, int]
    accuracy_ci: ConfidenceInterval | None = None
    # True only for the one split reconstructing the actual shipped production
    # artifact's split; every other row here is a research-only model, never saved
    # over models/ddos_random_forest.joblib.
    is_production_artifact: bool
    # Phase 18 (P0.1): additive, optional -- populated only for rounding-based
    # near-duplicate-controlled conditions (see
    # generalization_experiment.py::_near_duplicate_controlled_sweep()). None for
    # baseline/repeated-split conditions, which aren't grouping-based at all.
    significant_digits: int | None = None
    fraction_rows_in_multi_row_family: float | None = None


class RepeatedSplitVarianceReport(BaseModel):
    seeds: list[int]
    per_seed_accuracy: list[float]
    accuracy_mean: float
    accuracy_stddev: float
    per_seed_f1_macro: list[float]
    f1_macro_mean: float
    f1_macro_stddev: float
    note: str


class GeneralizationExperimentReport(BaseModel):
    baseline: SplitEvaluationResult
    family_grouped: SplitEvaluationResult | None
    repeated_random_splits: RepeatedSplitVarianceReport
    methodology_note: str
    limitations: list[str]
    # Phase 18 (P0.1): multi-granularity near-duplicate-controlled sweep --
    # additive, optional field so existing consumers of family_grouped (the single
    # 3-significant-figure condition) are unaffected. Contains one
    # SplitEvaluationResult per swept significant_digits value (2, 3, 4); the 3sf
    # entry here is computed identically to (but is a SEPARATE object instance
    # from) `family_grouped` above -- both are kept for backward compatibility, see
    # generalization_experiment.py's module docstring.
    near_duplicate_controlled_sweep: list[SplitEvaluationResult] | None = None
    # Generated, descriptive-only interpretation of the sweep -- never causal
    # language ("proves"/"caused by"/"accounts for"). See
    # generalization_experiment.py::_dose_response_note().
    dose_response_note: str | None = None


# --- Phase 17, RQ5: end-to-end reliability (repeated real pipeline runs) -----------


class ReliabilityReport(BaseModel):
    runs_attempted: int
    successes: int
    failures: int
    success_rate: float
    failure_rate: float
    failure_reasons: dict[str, int]
    # Timed around ONE real classify_and_analyze() call only -- same scope as
    # backend/evaluation/benchmark.py's total_classify_and_analyze stage, directly
    # comparable to it. Deliberately excludes stage_latency's own extra diagnostic
    # calls below (a real request never makes those) -- see reliability.py's module
    # docstring for the double-counting bug this field's definition was fixed to
    # avoid (Phase 17 audit).
    total_latency: DistributionStats | None
    # This module's OWN isolated per-stage diagnostic calls (classifier/vector/
    # graph/hybrid/llm_analysis run separately, purely to report a breakdown) --
    # NOT sub-timings of total_latency's call, and not additive with it.
    stage_latency: dict[str, DistributionStats]
    warm_up_excluded: bool
    note: str


# --- Phase 17, RQ6: component ablation (progressive pipeline stages) ---------------


class AblationConditionResult(BaseModel):
    condition: str
    description: str
    samples: int
    latency: DistributionStats
    evidence_chunk_count_mean: float | None = None
    graph_entity_count_mean: float | None = None
    graph_relationship_count_mean: float | None = None
    schema_valid_rate: float | None = None
    grounding_supported_ratio_mean: float | None = None


class ComponentAblationReport(BaseModel):
    conditions: list[AblationConditionResult]
    methodology_note: str


# --- Phase 17, RQ3: does graph evidence change the downstream LLM analysis? --------


class DownstreamUsefulnessRow(BaseModel):
    query: str
    category: str
    severity_changed: bool
    attack_vectors_changed: bool
    with_graph_indicator_count: int
    without_graph_indicator_count: int
    with_graph_mitigation_count: int
    without_graph_mitigation_count: int


class DownstreamUsefulnessReport(BaseModel):
    cases_evaluated: int
    severity_changed_rate: float
    attack_vectors_changed_rate: float
    indicators_gained_with_graph_rate: float
    mitigations_gained_with_graph_rate: float
    per_query: list[DownstreamUsefulnessRow]
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
    # Phase 17 additions -- all independently optional, same pattern as above.
    leakage_audit: LeakageAuditReport | None = None
    generalization_experiment: GeneralizationExperimentReport | None = None
    reliability: ReliabilityReport | None = None
    component_ablation: ComponentAblationReport | None = None
    downstream_usefulness: DownstreamUsefulnessReport | None = None
    limitations: list[str] = Field(default_factory=list)
