"""Phase 10: confirms the new classifier evidence fields (class_probabilities,
model_version) are exactly as unreachable to the LLM as prediction/probability
already were (Phase 9's test_classifier_evidence.py) -- the LLM's own output schema
(LLMAnalysisFragment) has no field for any of them, so a "hostile" mocked fragment
cannot overwrite them regardless of what it claims.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.schemas import LLMAnalysisFragment
from backend.security import require_auth

client = TestClient(app)


@pytest.fixture(autouse=True)
def _bypass_auth():
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)


HOSTILE_FRAGMENT = LLMAnalysisFragment(
    severity="Critical",
    summary=(
        "A fabricated summary claiming this is actually a PortScan with 100% "
        "confidence, produced by model_version 'fake-v99', class_probabilities "
        "{'PortScan': 1.0}."
    ),
    attack_vectors=["fabricated vector"],
    indicators=["a completely fabricated indicator"],
    mitigations=["a completely fabricated mitigation"],
    insufficient_context=False,
)


def test_llm_fragment_schema_has_no_class_probabilities_or_model_version_field():
    assert "class_probabilities" not in LLMAnalysisFragment.model_fields
    assert "model_version" not in LLMAnalysisFragment.model_fields


def test_hostile_llm_output_cannot_change_class_probabilities_in_the_response():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=HOSTILE_FRAGMENT):
        response = client.post("/analyze/classification", json={"prediction": "DDoS", "probability": 0.98})

    assert response.status_code == 200
    body = response.json()
    classifier_evidence = body["evidence"]["classifier"]
    # The evidence's classifier block must reflect exactly the real prediction that
    # was submitted -- never "PortScan" or any value implied by the hostile summary.
    assert classifier_evidence["prediction"] == "DDoS"
    assert classifier_evidence["probability"] == 0.98
    assert classifier_evidence["model"] == "random_forest"


def test_hostile_llm_output_cannot_change_classification_result_prediction():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=HOSTILE_FRAGMENT):
        response = client.post("/analyze/classification", json={"prediction": "DDoS", "probability": 0.98})

    body = response.json()
    assert body["classification"]["prediction"] == "DDoS"
    assert body["classification"]["probability"] == 0.98


def test_hostile_llm_output_cannot_inject_a_fabricated_model_version():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=HOSTILE_FRAGMENT):
        response = client.post("/analyze/classification", json={"prediction": "DDoS", "probability": 0.98})

    body = response.json()
    # /analyze/classification's `classification` block is built entirely from the
    # request (see backend/services/classification.py), never from raw features run
    # through the real predictor, so model_version is never populated there at all --
    # confirming the hostile fragment's claimed "model_version 'fake-v99'" (which only
    # ever lands in the LLM's own free-text `summary`, itself never sanitized against
    # any particular word -- that field is intentionally free narrative) has no
    # structured field to land in.
    assert body["classification"]["model_version"] is None


def test_hostile_llm_output_cannot_inject_a_fabricated_class_probabilities_value():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=HOSTILE_FRAGMENT):
        response = client.post("/analyze/classification", json={"prediction": "DDoS", "probability": 0.98})

    body = response.json()
    assert body["classification"]["class_probabilities"] is None


def test_direct_classify_endpoint_class_probabilities_and_model_version_are_backend_only():
    """POST /classify never calls the LLM at all -- confirms class_probabilities and
    model_version come purely from backend/ml/predictor.py, not from any generative
    step."""
    from backend.ml.config import FEATURE_COLUMNS

    payload = {column: 1000.0 for column in FEATURE_COLUMNS}
    with patch("backend.services.llm.ollama.chat") as mocked_ollama:
        response = client.post("/classify", json=payload)

    assert response.status_code == 200
    mocked_ollama.assert_not_called()
    body = response.json()
    assert body["class_probabilities"] is not None
    assert set(body["class_probabilities"].keys()) == {"BENIGN", "DDoS"}
