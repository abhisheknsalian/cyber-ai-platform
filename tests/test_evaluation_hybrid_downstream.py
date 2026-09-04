"""Phase 17: tests for backend/evaluation/hybrid_downstream.py.

Mocks backend.services.llm.generate_analysis_fragment (imported directly into
hybrid_downstream.py) with two different responses (with-graph vs without-graph
call) to prove the comparison logic actually detects a real difference, not just
that it runs.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from backend.evaluation import hybrid_downstream
from backend.evaluation.hybrid_downstream import DownstreamUsefulnessUnavailableError, run_downstream_usefulness
from backend.models.schemas import LLMAnalysisFragment

_WITH_GRAPH = LLMAnalysisFragment(
    severity="High", summary="s", attack_vectors=["credential harvesting"], indicators=[], mitigations=[],
)
_WITHOUT_GRAPH = LLMAnalysisFragment(
    severity="Medium", summary="s", attack_vectors=["credential harvesting", "fake login pages"], indicators=[], mitigations=[],
)


def test_detects_severity_and_attack_vector_changes_between_conditions():
    with patch(
        "backend.evaluation.hybrid_downstream.generate_analysis_fragment",
        side_effect=[_WITH_GRAPH, _WITHOUT_GRAPH],
    ):
        report = run_downstream_usefulness([("Explain phishing attacks and how they steal credentials", "phishing")])

    assert report.cases_evaluated == 1
    row = report.per_query[0]
    assert row.severity_changed is True
    assert row.attack_vectors_changed is True
    assert report.severity_changed_rate == 1.0
    assert report.attack_vectors_changed_rate == 1.0


def test_identical_responses_report_no_change():
    with patch(
        "backend.evaluation.hybrid_downstream.generate_analysis_fragment",
        side_effect=[_WITH_GRAPH, _WITH_GRAPH],
    ):
        report = run_downstream_usefulness([("Explain phishing attacks and how they steal credentials", "phishing")])

    row = report.per_query[0]
    assert row.severity_changed is False
    assert row.attack_vectors_changed is False


def test_skips_queries_with_no_retrieved_evidence():
    with patch("backend.evaluation.hybrid_downstream.retrieve_relevant", return_value=[]):
        report = run_downstream_usefulness([("completely unrelated off-topic query", "phishing")])
    assert report.cases_evaluated == 0


def test_raises_when_vector_store_unavailable(monkeypatch):
    monkeypatch.setattr(hybrid_downstream, "vector_store_available", lambda: False)
    with pytest.raises(DownstreamUsefulnessUnavailableError):
        run_downstream_usefulness([("Explain phishing attacks", "phishing")])


def test_report_round_trips_through_json():
    from backend.evaluation.schemas import DownstreamUsefulnessReport

    with patch(
        "backend.evaluation.hybrid_downstream.generate_analysis_fragment",
        side_effect=[_WITH_GRAPH, _WITHOUT_GRAPH],
    ):
        report = run_downstream_usefulness([("Explain phishing attacks and how they steal credentials", "phishing")])
    reloaded = DownstreamUsefulnessReport.model_validate(report.model_dump())
    assert reloaded.cases_evaluated == report.cases_evaluated
