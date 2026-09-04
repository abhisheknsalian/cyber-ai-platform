"""Phase 17: tests for backend/evaluation/component_ablation.py.

Mocks backend.services.threat_analysis.generate_analysis_fragment (the only LLM call
site this module reaches, via analyze_query() in the ml_plus_retrieval_plus_llm
condition) -- never makes a real Ollama call in the unit-test suite.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from backend.evaluation import component_ablation
from backend.evaluation.component_ablation import ComponentAblationUnavailableError, run_component_ablation
from backend.models.schemas import LLMAnalysisFragment

_FRAGMENT = LLMAnalysisFragment(
    severity="High", summary="Test summary.", attack_vectors=["flood"], indicators=["high SYN rate"], mitigations=["rate limiting"],
)

_CONDITIONS = {"ml_only", "ml_plus_vector", "ml_plus_hybrid", "ml_plus_retrieval_plus_llm"}


def test_all_four_conditions_are_reported_with_progressive_evidence():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=_FRAGMENT):
        report = run_component_ablation(sample_size=2)

    conditions = {c.condition: c for c in report.conditions}
    assert set(conditions) == _CONDITIONS

    ml_only = conditions["ml_only"]
    assert ml_only.evidence_chunk_count_mean is None
    assert ml_only.latency.count == 2

    ml_plus_vector = conditions["ml_plus_vector"]
    assert ml_plus_vector.evidence_chunk_count_mean is not None
    assert ml_plus_vector.graph_entity_count_mean is None

    ml_plus_hybrid = conditions["ml_plus_hybrid"]
    assert ml_plus_hybrid.graph_entity_count_mean is not None
    assert ml_plus_hybrid.graph_relationship_count_mean is not None

    full = conditions["ml_plus_retrieval_plus_llm"]
    assert full.schema_valid_rate == 1.0
    assert full.grounding_supported_ratio_mean is not None


def test_raises_when_dataset_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(component_ablation, "RAW_DATA_PATH", tmp_path / "does_not_exist.csv")
    with pytest.raises(ComponentAblationUnavailableError):
        run_component_ablation(sample_size=1)


def test_raises_when_vector_store_unavailable(monkeypatch):
    monkeypatch.setattr(component_ablation, "vector_store_available", lambda: False)
    with pytest.raises(ComponentAblationUnavailableError):
        run_component_ablation(sample_size=1)


def test_report_round_trips_through_json():
    from backend.evaluation.schemas import ComponentAblationReport

    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=_FRAGMENT):
        report = run_component_ablation(sample_size=1)
    reloaded = ComponentAblationReport.model_validate(report.model_dump())
    assert len(reloaded.conditions) == len(report.conditions)
