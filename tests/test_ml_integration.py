from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.schemas import LLMAnalysisFragment
from backend.security import require_auth

client = TestClient(app)


@pytest.fixture(autouse=True)
def _bypass_auth():
    """This file tests classifier-to-RAG integration, not auth (see
    tests/test_auth.py for that) -- FastAPI's dependency_overrides is the standard
    way to isolate the two."""
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)

FAKE_FRAGMENT = LLMAnalysisFragment(
    severity="High",
    summary="Test DDoS summary grounded in retrieved context.",
    attack_vectors=["test vector"],
    indicators=["test indicator"],
    mitigations=["test mitigation"],
    insufficient_context=False,
)


def test_ddos_prediction_maps_to_ddos_threat_analysis():
    with patch(
        "backend.services.threat_analysis.generate_analysis_fragment",
        return_value=FAKE_FRAGMENT,
    ):
        response = client.post("/analyze/classification", json={"prediction": "DDoS", "probability": 0.97})

    assert response.status_code == 200
    body = response.json()
    assert body["classification"]["prediction"] == "DDoS"
    assert body["classification"]["probability"] == 0.97
    assert body["analysis"] is not None
    assert body["analysis"]["threat"] == "ddos_attack"
    assert body["analysis"]["status"] == "analyzed"


def test_classification_result_can_trigger_rag_analysis():
    """The classification result alone (no raw traffic features) is enough input to
    produce a full RAG-grounded threat analysis."""
    with patch(
        "backend.services.threat_analysis.generate_analysis_fragment",
        return_value=FAKE_FRAGMENT,
    ) as mocked_llm:
        response = client.post("/analyze/classification", json={"prediction": "DDoS"})

    assert response.status_code == 200
    mocked_llm.assert_called_once()
    assert response.json()["analysis"]["sources"]


def test_benign_prediction_returns_no_analysis_and_never_calls_llm():
    with patch("backend.services.threat_analysis.generate_analysis_fragment") as mocked_llm:
        response = client.post("/analyze/classification", json={"prediction": "BENIGN"})

    assert response.status_code == 200
    body = response.json()
    assert body["classification"]["classification"] == "benign"
    assert body["analysis"] is None
    mocked_llm.assert_not_called()


def test_unsupported_prediction_is_rejected():
    response = client.post("/analyze/classification", json={"prediction": "MALWARE"})
    assert response.status_code == 422
