from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.schemas import LLMAnalysisFragment
from backend.security import require_auth
from backend.services.llm import LLMResponseError, LLMUnavailableError

client = TestClient(app)


@pytest.fixture(autouse=True)
def _bypass_auth():
    """This file tests RAG/business logic, not auth (see tests/test_auth.py for
    that) -- FastAPI's dependency_overrides is the standard way to isolate the two."""
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)

FAKE_FRAGMENT = LLMAnalysisFragment(
    severity="Medium",
    summary="Test summary grounded in retrieved context.",
    attack_vectors=["test vector"],
    indicators=["test indicator"],
    mitigations=["test mitigation"],
    insufficient_context=False,
)


def test_valid_analysis_request_returns_expected_schema():
    with patch(
        "backend.services.threat_analysis.generate_analysis_fragment",
        return_value=FAKE_FRAGMENT,
    ):
        response = client.post("/analyze", json={"query": "Explain phishing attacks and mitigation"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "analyzed"
    assert body["threat"] == "phishing"
    assert body["severity"] == "Medium"
    assert body["sources"], "expected at least one source"
    assert all({"source", "threat_type", "chunk_index", "score"} <= s.keys() for s in body["sources"])


def test_empty_query_returns_validation_error():
    response = client.post("/analyze", json={"query": ""})
    assert response.status_code == 422


def test_whitespace_only_query_returns_validation_error():
    response = client.post("/analyze", json={"query": "   "})
    assert response.status_code == 422


def test_very_long_query_returns_validation_error():
    response = client.post("/analyze", json={"query": "a" * 5000})
    assert response.status_code == 422


def test_unrelated_query_does_not_produce_valid_threat_analysis():
    with patch(
        "backend.services.threat_analysis.generate_analysis_fragment",
        return_value=FAKE_FRAGMENT,
    ) as mocked_llm:
        response = client.post("/analyze", json={"query": "What is the capital of France?"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "no_relevant_intelligence"
    assert body["threat"] is None
    assert body["sources"] == []
    mocked_llm.assert_not_called()  # relevance filter must short-circuit before calling the LLM


def test_vector_store_unavailable_returns_503():
    with patch("backend.services.threat_analysis.vector_store_available", return_value=False):
        response = client.post("/analyze", json={"query": "Explain phishing attacks"})
    assert response.status_code == 503


def test_llm_unavailable_is_handled_cleanly():
    with patch(
        "backend.services.threat_analysis.generate_analysis_fragment",
        side_effect=LLMUnavailableError("boom"),
    ):
        response = client.post("/analyze", json={"query": "Explain phishing attacks and mitigation"})

    assert response.status_code == 503
    assert "detail" in response.json()


def test_malformed_llm_output_does_not_crash_app():
    with patch(
        "backend.services.threat_analysis.generate_analysis_fragment",
        side_effect=LLMResponseError("bad json"),
    ):
        response = client.post("/analyze", json={"query": "Explain phishing attacks and mitigation"})

    assert response.status_code == 502
    assert "detail" in response.json()
