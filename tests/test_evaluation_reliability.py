"""Phase 17: tests for backend/evaluation/reliability.py.

Mocks both LLM call sites (backend.evaluation.reliability's own isolated
llm_analysis-stage call, and backend.services.threat_analysis's call inside the real
classify_and_analyze() path) -- same two-target pattern
tests/test_evaluation_benchmark.py already established, for the same reason: either
site left unmocked is a real, non-instant network call to Ollama.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from backend.evaluation import reliability
from backend.evaluation.reliability import ReliabilityUnavailableError, run_reliability_experiment
from backend.models.schemas import LLMAnalysisFragment
from backend.services.llm import LLMResponseError, LLMUnavailableError

_FRAGMENT = LLMAnalysisFragment(
    severity="High", summary="Test summary.", attack_vectors=["flood"], indicators=["high SYN rate"], mitigations=["rate limiting"],
)

_STAGES = {"classifier_inference", "vector_retrieval", "graph_retrieval", "hybrid_retrieval", "llm_analysis"}


def test_reliability_runs_and_reports_full_success():
    with (
        patch("backend.evaluation.reliability.generate_analysis_fragment", return_value=_FRAGMENT) as mocked_local,
        patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=_FRAGMENT) as mocked_pipeline,
    ):
        report = run_reliability_experiment(runs=3)

    assert report.runs_attempted == 3
    assert report.successes == 3
    assert report.failures == 0
    assert report.success_rate == 1.0
    assert report.failure_rate == 0.0
    assert report.total_latency is not None
    assert report.total_latency.count == 3
    assert set(report.stage_latency) == _STAGES
    assert report.warm_up_excluded is True
    # 1 warm-up call + 1 isolated llm_analysis call per run.
    assert mocked_local.call_count == 1 + 3
    assert mocked_pipeline.call_count == 3


def test_reliability_records_a_partial_failure_without_aborting_the_run():
    side_effects = [_FRAGMENT, _FRAGMENT, LLMResponseError("malformed"), _FRAGMENT]
    with (
        patch("backend.evaluation.reliability.generate_analysis_fragment", side_effect=side_effects),
        patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=_FRAGMENT),
    ):
        report = run_reliability_experiment(runs=3)

    assert report.runs_attempted == 3
    assert report.successes == 2
    assert report.failures == 1
    assert report.failure_reasons.get("LLMResponseError") == 1
    assert report.total_latency.count == 2  # only successful runs contribute a total latency


def test_reliability_raises_when_ollama_unreachable_at_warmup():
    with patch("backend.evaluation.reliability.generate_analysis_fragment", side_effect=LLMUnavailableError("no server")):
        with pytest.raises(ReliabilityUnavailableError):
            run_reliability_experiment(runs=2)


def test_reliability_raises_when_vector_store_unavailable(monkeypatch):
    monkeypatch.setattr(reliability, "vector_store_available", lambda: False)
    with pytest.raises(ReliabilityUnavailableError):
        run_reliability_experiment(runs=1)


def test_reliability_raises_when_dataset_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(reliability, "RAW_DATA_PATH", tmp_path / "does_not_exist.csv")
    with pytest.raises(ReliabilityUnavailableError):
        run_reliability_experiment(runs=1)


def test_reliability_report_round_trips_through_json():
    from backend.evaluation.schemas import ReliabilityReport

    with (
        patch("backend.evaluation.reliability.generate_analysis_fragment", return_value=_FRAGMENT),
        patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=_FRAGMENT),
    ):
        report = run_reliability_experiment(runs=1)
    reloaded = ReliabilityReport.model_validate(report.model_dump())
    assert reloaded.successes == report.successes
