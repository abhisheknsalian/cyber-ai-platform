"""Phase 16: tests for backend/evaluation/retrieval_relevance.py.

tests/conftest.py builds its test vector store from the REAL data/threat_intel/*.txt
files (only the ML dataset/model are synthetic in this test session -- CHROMA_PERSIST_DIR
is isolated, but THREAT_INTEL_DIR is not overridden), so run_retrieval_relevance_evaluation()
below exercises real retrieval against real content, not a mock.
"""

from __future__ import annotations

import pytest

from backend.evaluation.retrieval_relevance import (
    EVALUATION_QUERIES,
    RelevanceEvaluationUnavailableError,
    average_metrics_at_k,
    compute_metrics_at_k,
    run_retrieval_relevance_evaluation,
)
from backend.evaluation.schemas import RelevanceMetricsAtK


# ---------------------------------------------------------------------------
# Pure metric-calculation correctness -- deterministic, no vector store needed.
# ---------------------------------------------------------------------------


def test_recall_at_k_counts_fraction_of_all_relevant_items_retrieved():
    ranked = [("a", 0), ("b", 0), ("c", 0)]
    relevant = {("a", 0), ("x", 0), ("y", 0), ("z", 0)}  # 4 relevant total, 1 retrieved in top-3
    metrics = compute_metrics_at_k(ranked, relevant, k=3)
    assert metrics.recall_at_k == pytest.approx(1 / 4)


def test_precision_at_k_counts_fraction_of_top_k_that_are_relevant():
    ranked = [("a", 0), ("b", 0), ("c", 0)]
    relevant = {("a", 0), ("c", 0)}
    metrics = compute_metrics_at_k(ranked, relevant, k=3)
    assert metrics.precision_at_k == pytest.approx(2 / 3)


def test_hit_rate_is_one_if_any_relevant_item_in_top_k_else_zero():
    ranked = [("a", 0), ("b", 0)]
    assert compute_metrics_at_k(ranked, {("z", 0)}, k=2).hit_rate_at_k == 0.0
    assert compute_metrics_at_k(ranked, {("a", 0)}, k=2).hit_rate_at_k == 1.0


def test_mrr_is_reciprocal_of_first_relevant_rank():
    ranked = [("a", 0), ("b", 0), ("c", 0)]
    assert compute_metrics_at_k(ranked, {("b", 0)}, k=3).mrr_at_k == pytest.approx(1 / 2)
    assert compute_metrics_at_k(ranked, {("a", 0)}, k=3).mrr_at_k == pytest.approx(1.0)


def test_mrr_is_zero_when_no_relevant_item_in_top_k():
    ranked = [("a", 0), ("b", 0)]
    assert compute_metrics_at_k(ranked, {("z", 0)}, k=2).mrr_at_k == 0.0


def test_recall_is_zero_not_error_when_no_relevant_items_exist():
    metrics = compute_metrics_at_k([("a", 0)], relevant=set(), k=1)
    assert metrics.recall_at_k == 0.0


def test_average_metrics_at_k_averages_only_matching_k_rows():
    rows = [
        RelevanceMetricsAtK(k=3, recall_at_k=1.0, precision_at_k=1.0, hit_rate_at_k=1.0, mrr_at_k=1.0),
        RelevanceMetricsAtK(k=3, recall_at_k=0.0, precision_at_k=0.0, hit_rate_at_k=0.0, mrr_at_k=0.0),
        RelevanceMetricsAtK(k=5, recall_at_k=1.0, precision_at_k=1.0, hit_rate_at_k=1.0, mrr_at_k=1.0),
    ]
    averaged = average_metrics_at_k(rows, k=3)
    assert averaged.recall_at_k == pytest.approx(0.5)
    assert averaged.k == 3


# ---------------------------------------------------------------------------
# End-to-end against the real (test-isolated) vector store.
# ---------------------------------------------------------------------------


def test_evaluates_all_configured_queries_and_categories():
    report = run_retrieval_relevance_evaluation()
    # Phase 17 (RQ2) expanded EVALUATION_QUERIES from 3 to 5 per category (25 total).
    assert report.queries_evaluated == len(EVALUATION_QUERIES) == 25
    assert {c.category for c in report.categories} == {
        "phishing", "ransomware", "ddos_attack", "sql_injection", "botnet",
    }
    assert report.k_values == [3, 5, 10]


def test_reports_one_averaged_row_per_k_for_each_category():
    report = run_retrieval_relevance_evaluation()
    for category in report.categories:
        assert [m.k for m in category.metrics] == [3, 5, 10]
        for m in category.metrics:
            assert 0.0 <= m.recall_at_k <= 1.0
            assert 0.0 <= m.precision_at_k <= 1.0


def test_supports_a_custom_smaller_query_set():
    report = run_retrieval_relevance_evaluation(queries=[("Explain phishing attacks", "phishing")], k_values=[3])
    assert report.queries_evaluated == 1
    assert len(report.categories) == 1
    assert report.categories[0].category == "phishing"


def test_raises_when_vector_store_unavailable(monkeypatch):
    import backend.evaluation.retrieval_relevance as module

    monkeypatch.setattr(module, "vector_store_available", lambda: False)
    with pytest.raises(RelevanceEvaluationUnavailableError):
        run_retrieval_relevance_evaluation()


def test_report_round_trips_through_json():
    report = run_retrieval_relevance_evaluation(queries=[("Explain phishing attacks", "phishing")], k_values=[3])
    dumped = report.model_dump()
    from backend.evaluation.schemas import RetrievalRelevanceReport

    reloaded = RetrievalRelevanceReport.model_validate(dumped)
    assert reloaded.queries_evaluated == report.queries_evaluated
