"""Phase 17: tests for backend/evaluation/thesis_tables.py.

Pure rendering logic -- constructs minimal EvaluationReport objects directly rather
than running any real experiment, so these stay fast and don't need Ollama/real data.
"""

from __future__ import annotations

from backend.evaluation.schemas import ConfidenceInterval, EvaluationReport
from backend.evaluation.thesis_tables import render_markdown_tables


def _empty_report() -> EvaluationReport:
    return EvaluationReport(generated_at="2026-01-01T00:00:00Z", dataset=None, model=None)


def test_empty_report_renders_not_measured_for_every_table():
    markdown = render_markdown_tables(_empty_report())
    assert markdown.count("NOT MEASURED") >= 5
    for heading in [
        "Table 1: ML Classification Performance",
        "Table 2: Leakage / Generalization Comparison",
        "Table 3: Retrieval Performance",
        "Table 4: Vector-only vs. Hybrid Retrieval",
        "Table 5: LLM Evaluation",
        "Table 6: End-to-End Latency",
        "Table 7: Component Ablation",
    ]:
        assert heading in markdown


def test_never_hardcodes_a_number_not_present_in_the_report():
    """The one number this test can meaningfully check: a distinctive, unlikely
    accuracy value placed into the report must appear verbatim in the rendered
    table, proving the renderer reads from the object rather than a fixture."""
    from backend.evaluation.schemas import (
        ClassificationMetrics,
        LatencyStats,
        PerClassMetrics,
    )

    report = _empty_report()
    report.classification["held_out_test"] = ClassificationMetrics(
        split="held_out_test",
        split_description="test",
        samples=123,
        accuracy=0.123456,
        balanced_accuracy=0.5,
        precision_macro=0.5,
        recall_macro=0.5,
        f1_macro=0.5,
        f1_weighted=0.5,
        roc_auc=None,
        pr_auc=None,
        positive_label=None,
        confusion_matrix=[[1, 0], [0, 1]],
        confusion_matrix_labels=["BENIGN", "DDoS"],
        per_class={"BENIGN": PerClassMetrics(precision=0.5, recall=0.5, f1=0.5, support=1)},
        class_distribution={"BENIGN": 1},
        inference_latency_ms=LatencyStats(count=1, mean_ms=1.0, p50_ms=1.0, p95_ms=1.0, min_ms=1.0, max_ms=1.0, stddev_ms=0.0),
        mean_winning_class_confidence=0.9,
    )
    markdown = render_markdown_tables(report)
    assert "0.123456" in markdown


def test_llm_rubric_dimensions_never_show_a_fabricated_score():
    from backend.evaluation.schemas import LLMAutomatedMetrics, LLMEvaluationReport, LLMRubricDimension

    report = _empty_report()
    report.llm_evaluation = LLMEvaluationReport(
        automated=LLMAutomatedMetrics(
            cases_evaluated=1, schema_valid_rate=1.0, correct_relevance_on_topic_rate=1.0,
            correct_relevance_off_topic_rate=None, non_empty_attack_vectors_rate=1.0, severity_present_rate=1.0,
        ),
        rubric_dimensions=[
            LLMRubricDimension(name="severity_reasonableness", description="d", scale_description="0/1/2", status="not_yet_annotated"),
        ],
        rubric_template_path="evaluation/llm_rubric_template.csv",
        methodology_note="note",
    )
    markdown = render_markdown_tables(report)
    assert "IMPLEMENTED / NOT YET MEASURED" in markdown
    assert "NOT_YET_ANNOTATED" in markdown


def test_recall_at_5_ci_is_rendered_when_present():
    from backend.evaluation.schemas import CategoryRelevanceReport, RelevanceMetricsAtK, RetrievalRelevanceReport

    report = _empty_report()
    metric = RelevanceMetricsAtK(k=5, recall_at_k=0.9, precision_at_k=0.5, hit_rate_at_k=1.0, mrr_at_k=1.0)
    report.retrieval_relevance = RetrievalRelevanceReport(
        k_values=[5],
        queries_evaluated=10,
        categories=[CategoryRelevanceReport(category="phishing", query_count=10, relevant_chunk_count=3, metrics=[metric])],
        overall=[metric],
        per_query=[],
        methodology_note="note",
        recall_at_5_ci=ConfidenceInterval(point_estimate=0.9, lower=0.7, upper=0.99, confidence_level=0.95, method="bootstrap_percentile", n_resamples=2000),
    )
    markdown = render_markdown_tables(report)
    assert "bootstrap 95% CI: [0.7000, 0.9900]" in markdown
