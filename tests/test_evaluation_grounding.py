"""Phase 16: tests for backend/evaluation/grounding.py.

Mocks backend.services.threat_analysis.generate_analysis_fragment -- never makes a
real Ollama call in the unit-test suite (same pattern as test_evaluation_llm.py).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from backend.evaluation.grounding import (
    GroundingEvaluationUnavailableError,
    _is_supported,
    _significant_words,
    run_grounding_evaluation,
)
from backend.models.schemas import LLMAnalysisFragment


# ---------------------------------------------------------------------------
# Pure lexical-overlap logic -- deterministic, no retrieval needed.
# ---------------------------------------------------------------------------


def test_significant_words_drops_stopwords_and_short_tokens():
    words = _significant_words("The attacker used a phishing email to steal credentials")
    assert "the" not in words
    assert "a" not in words
    assert "to" not in words
    assert "phishing" in words
    assert "credentials" in words


def test_claim_is_supported_when_overlap_meets_threshold():
    context_words = {"phishing", "credentials", "email", "attacker", "spoofing"}
    assert _is_supported("phishing email credentials", context_words) is True


def test_claim_is_not_supported_when_overlap_is_below_threshold():
    context_words = {"ransomware", "encryption", "payment"}
    assert _is_supported("phishing email credentials theft", context_words) is False


def test_empty_claim_is_never_supported():
    assert _is_supported("", {"anything"}) is False


# ---------------------------------------------------------------------------
# End-to-end with a mocked LLM.
# ---------------------------------------------------------------------------


def test_grounded_attack_vector_scores_supported():
    # "credential harvesting" and "phishing" both appear verbatim in
    # data/threat_intel/phishing.txt's real content.
    fragment = LLMAnalysisFragment(
        severity="High",
        summary="Test summary.",
        attack_vectors=["credential harvesting phishing"],
        indicators=["test indicator"],
        mitigations=["test mitigation"],
        insufficient_context=False,
    )
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=fragment):
        report = run_grounding_evaluation([("Explain phishing attacks", "phishing")])

    assert report.cases_evaluated == 1
    assert report.per_query[0].claims_checked == 1
    assert report.per_query[0].claims_supported == 1
    assert report.per_query[0].supported_ratio == 1.0


def test_unsupported_attack_vector_scores_zero():
    fragment = LLMAnalysisFragment(
        severity="High",
        summary="Test summary.",
        attack_vectors=["completely unrelated fabricated nonsense zebra giraffe"],
        indicators=["test indicator"],
        mitigations=["test mitigation"],
        insufficient_context=False,
    )
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=fragment):
        report = run_grounding_evaluation([("Explain phishing attacks", "phishing")])

    assert report.per_query[0].claims_supported == 0
    assert report.per_query[0].supported_ratio == 0.0


def test_no_claims_reports_none_not_zero():
    fragment = LLMAnalysisFragment(
        severity="High", summary="Test summary.", attack_vectors=[], indicators=[], mitigations=[],
        insufficient_context=False,
    )
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=fragment):
        report = run_grounding_evaluation([("Explain phishing attacks", "phishing")])

    assert report.per_query[0].claims_checked == 0
    assert report.per_query[0].supported_ratio is None


def test_mean_supported_ratio_excludes_none_rows():
    fragment_with_claims = LLMAnalysisFragment(
        severity="High", summary="s", attack_vectors=["credential harvesting phishing"],
        indicators=[], mitigations=[], insufficient_context=False,
    )
    fragment_without_claims = LLMAnalysisFragment(
        severity="High", summary="s", attack_vectors=[], indicators=[], mitigations=[], insufficient_context=False,
    )
    with patch(
        "backend.services.threat_analysis.generate_analysis_fragment",
        side_effect=[fragment_with_claims, fragment_without_claims],
    ):
        report = run_grounding_evaluation(
            [("Explain phishing attacks", "phishing"), ("What are phishing indicators?", "phishing")]
        )

    assert report.mean_supported_ratio == 1.0  # only the scored row counts


def test_raises_when_vector_store_unavailable(monkeypatch):
    import backend.evaluation.grounding as module

    monkeypatch.setattr(module, "vector_store_available", lambda: False)
    with pytest.raises(GroundingEvaluationUnavailableError):
        run_grounding_evaluation([("Explain phishing attacks", "phishing")])


def test_report_round_trips_through_json():
    from backend.evaluation.schemas import GroundingReport

    fragment = LLMAnalysisFragment(
        severity="High", summary="s", attack_vectors=["credential harvesting phishing"],
        indicators=[], mitigations=[], insufficient_context=False,
    )
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=fragment):
        report = run_grounding_evaluation([("Explain phishing attacks", "phishing")])
    reloaded = GroundingReport.model_validate(report.model_dump())
    assert reloaded.cases_evaluated == report.cases_evaluated
