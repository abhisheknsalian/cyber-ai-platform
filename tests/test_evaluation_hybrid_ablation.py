"""Phase 16: tests for backend/evaluation/hybrid_ablation.py."""

from __future__ import annotations

import pytest

from backend.evaluation.hybrid_ablation import HybridAblationUnavailableError, run_hybrid_ablation


def test_vector_only_and_hybrid_relevance_are_identical_by_construction():
    """The central, architecture-grounded claim this module exists to verify: hybrid
    retrieval never changes vector ranking in this codebase, so relevance metrics
    must be exactly equal and every delta exactly zero -- not approximately, exactly,
    since both are computed from the identical underlying ranked list."""
    report = run_hybrid_ablation()
    assert report.vector_only_relevance == report.hybrid_relevance
    for delta in report.relevance_delta:
        assert delta.recall_at_k == 0.0
        assert delta.precision_at_k == 0.0
        assert delta.hit_rate_at_k == 0.0
        assert delta.mrr_at_k == 0.0


def test_evidence_coverage_rate_reflects_whether_graph_evidence_was_added():
    report = run_hybrid_ablation()
    assert 0.0 <= report.evidence_coverage_rate <= 1.0
    # Every query in the default set maps to a real, graph-known category, so graph
    # evidence should be added for all of them.
    assert report.evidence_coverage_rate == 1.0


def test_per_query_rows_match_queries_evaluated_count():
    report = run_hybrid_ablation(queries=[("Explain phishing attacks", "phishing")])
    assert report.queries_evaluated == 1
    assert len(report.per_query) == 1
    assert report.per_query[0].category == "phishing"


def test_raises_when_vector_store_unavailable(monkeypatch):
    import backend.evaluation.hybrid_ablation as module

    monkeypatch.setattr(module, "vector_store_available", lambda: False)
    with pytest.raises(HybridAblationUnavailableError):
        run_hybrid_ablation()


def test_raises_when_graph_unavailable(monkeypatch):
    import backend.evaluation.hybrid_ablation as module

    monkeypatch.setattr(module, "graph_available", lambda: False)
    with pytest.raises(HybridAblationUnavailableError):
        run_hybrid_ablation()


def test_report_round_trips_through_json():
    from backend.evaluation.schemas import HybridAblationReport

    report = run_hybrid_ablation(queries=[("Explain phishing attacks", "phishing")])
    reloaded = HybridAblationReport.model_validate(report.model_dump())
    assert reloaded.queries_evaluated == report.queries_evaluated
