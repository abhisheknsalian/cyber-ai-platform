"""Phase 16: tests for backend/evaluation/llm_evaluation.py.

Mocks backend.services.threat_analysis.generate_analysis_fragment -- never makes a
real Ollama call in the unit-test suite (see that module's own docstring / the
project's existing tests/test_evaluation_benchmark.py for the same pattern). A
genuinely off-topic query never reaches the LLM at all in this architecture (RAG
retrieval itself finds nothing above the relevance threshold and analyze_query()
returns "no_relevant_intelligence" before calling generate_analysis_fragment) -- so
the negative-control cases below are real, unmocked behavior, not a second mock path.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from backend.evaluation.llm_evaluation import (
    LLMEvaluationUnavailableError,
    run_llm_evaluation,
    write_rubric_template,
)
from backend.models.schemas import LLMAnalysisFragment

_FRAGMENT = LLMAnalysisFragment(
    severity="High",
    summary="Test-only summary grounded in retrieved context.",
    attack_vectors=["test attack vector"],
    indicators=["test indicator"],
    mitigations=["test mitigation"],
    insufficient_context=False,
)

_CASES = [
    ("Explain phishing attacks and how they steal credentials", "phishing"),
    ("What is the capital of France?", None),
]


def test_automated_metrics_reflect_correct_relevance_decisions(tmp_path):
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=_FRAGMENT):
        report = run_llm_evaluation(_CASES, rubric_template_path=tmp_path / "rubric.csv")

    assert report.automated.cases_evaluated == 2
    assert report.automated.schema_valid_rate == 1.0
    assert report.automated.correct_relevance_on_topic_rate == 1.0
    assert report.automated.correct_relevance_off_topic_rate == 1.0  # off-topic never reaches the LLM at all
    assert report.automated.non_empty_attack_vectors_rate == 1.0
    assert report.automated.severity_present_rate == 1.0


def test_rubric_dimensions_are_unscored_until_annotated(tmp_path):
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=_FRAGMENT):
        report = run_llm_evaluation(_CASES, rubric_template_path=tmp_path / "rubric.csv")

    assert len(report.rubric_dimensions) == 3
    for dimension in report.rubric_dimensions:
        assert dimension.status == "not_yet_annotated"
        assert dimension.scores == []
        assert dimension.mean_score is None


def test_rubric_template_is_written_with_one_row_per_case(tmp_path):
    import csv as csv_module

    output = tmp_path / "rubric.csv"
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=_FRAGMENT):
        report = run_llm_evaluation(_CASES, rubric_template_path=output)

    assert report.rubric_template_path == str(output)
    assert output.exists()
    # csv.reader (not naive splitlines()) -- retrieved_context_excerpt can contain
    # embedded newlines inside a properly-quoted CSV field, which splitlines() would
    # miscount as multiple rows.
    with output.open(newline="", encoding="utf-8") as handle:
        rows = list(csv_module.reader(handle))
    assert len(rows) == 1 + len(_CASES)  # header + one row per case


def test_write_rubric_template_header_has_only_the_documented_columns(tmp_path):
    """Structural guard: the CSV header must be exactly the documented columns --
    proves the template can't silently grow into an unbounded dump of arbitrary
    model output."""
    import csv as csv_module

    rows = [{
        "case_id": 0, "query": "q", "category": "phishing", "severity": "High", "summary": "s",
        "attack_vectors": "a", "retrieved_context_excerpt": "ctx", "is_negative_control": False,
    }]
    output = tmp_path / "rubric.csv"
    write_rubric_template(rows, output)

    with output.open(newline="", encoding="utf-8") as handle:
        header = next(csv_module.reader(handle))
    assert "case_id" in header and "query" in header and "category" in header
    assert "retrieved_context_excerpt" in header and "is_negative_control" in header
    assert len(header) == 8 + 3  # 8 case fields (incl. retrieved evidence + negative-control flag) + 3 rubric-dimension score columns


def test_schema_invalid_response_excluded_from_valid_rate_not_crashed(tmp_path):
    from backend.services.llm import LLMResponseError

    with patch(
        "backend.services.threat_analysis.generate_analysis_fragment",
        side_effect=LLMResponseError("malformed"),
    ):
        report = run_llm_evaluation([("Explain phishing attacks", "phishing")], rubric_template_path=tmp_path / "r.csv")

    assert report.automated.schema_valid_rate == 0.0
    assert report.automated.cases_evaluated == 1


def test_raises_when_vector_store_unavailable(monkeypatch):
    import backend.evaluation.llm_evaluation as module

    monkeypatch.setattr(module, "vector_store_available", lambda: False)
    with pytest.raises(LLMEvaluationUnavailableError):
        run_llm_evaluation(_CASES)


def test_report_round_trips_through_json(tmp_path):
    from backend.evaluation.schemas import LLMEvaluationReport

    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=_FRAGMENT):
        report = run_llm_evaluation(_CASES, rubric_template_path=tmp_path / "rubric.csv")
    reloaded = LLMEvaluationReport.model_validate(report.model_dump())
    assert reloaded.automated.cases_evaluated == report.automated.cases_evaluated
