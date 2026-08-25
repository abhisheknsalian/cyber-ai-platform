"""Phase 10: tests that ClassificationResult/ClassificationAnalysisRequest validate
`prediction` at runtime against LABEL_MAP (backend/ml/config.py) rather than a
hardcoded Literal["BENIGN", "DDoS"] -- still strictly rejecting anything outside the
currently configured labels, and that an unsupported prediction which somehow reaches
the service layer anyway fails through the explicit, controlled
UnsupportedPredictionError path rather than producing an incorrect analysis.

No label is added to LABEL_MAP anywhere in this file.
"""

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from backend.ml.config import LABEL_MAP
from backend.ml.schemas import ClassificationAnalysisRequest, ClassificationResult
from backend.services.classification import UnsupportedPredictionError, classify_and_analyze


# --- Schema-level validation (ClassificationResult) ------------------------------


@pytest.mark.parametrize("label", sorted(LABEL_MAP))
def test_classification_result_accepts_every_currently_configured_label(label):
    result = ClassificationResult(prediction=label, classification="benign" if label == "BENIGN" else "malicious")
    assert result.prediction == label


def test_classification_result_rejects_a_label_outside_label_map():
    with pytest.raises(ValidationError):
        ClassificationResult(prediction="PortScan", classification="malicious")


def test_classification_result_rejection_message_names_the_configured_labels():
    with pytest.raises(ValidationError) as exc_info:
        ClassificationResult(prediction="PortScan", classification="malicious")
    message = str(exc_info.value)
    assert "PortScan" in message
    assert "BENIGN" in message and "DDoS" in message


def test_classification_result_class_probabilities_accepts_configured_labels():
    result = ClassificationResult(
        prediction="DDoS",
        classification="malicious",
        class_probabilities={"BENIGN": 0.02, "DDoS": 0.98},
    )
    assert result.class_probabilities == {"BENIGN": 0.02, "DDoS": 0.98}


def test_classification_result_class_probabilities_rejects_an_unconfigured_label_key():
    with pytest.raises(ValidationError):
        ClassificationResult(
            prediction="DDoS",
            classification="malicious",
            class_probabilities={"BENIGN": 0.02, "PortScan": 0.98},
        )


def test_classification_result_prediction_is_not_weakened_to_arbitrary_strings():
    # A blank string, or any string not in LABEL_MAP, must still be rejected -- this
    # is runtime validation against a configured set, not "accept any string".
    for bogus in ["", "benign", "ddos", "  DDoS  ", "NOT_A_LABEL"]:
        with pytest.raises(ValidationError):
            ClassificationResult(prediction=bogus, classification="malicious")


# --- Schema-level validation (ClassificationAnalysisRequest) ---------------------


@pytest.mark.parametrize("label", sorted(LABEL_MAP))
def test_classification_analysis_request_accepts_every_currently_configured_label(label):
    request = ClassificationAnalysisRequest(prediction=label)
    assert request.prediction == label


def test_classification_analysis_request_rejects_unsupported_label():
    with pytest.raises(ValidationError):
        ClassificationAnalysisRequest(prediction="PortScan")


# --- Service-level: the controlled UnsupportedPredictionError path ---------------


def test_unsupported_prediction_raises_controlled_error_not_a_wrong_analysis():
    """Exercises classify_and_analyze()'s own UnsupportedPredictionError branch by
    temporarily patching PREDICTION_TO_QUERY/PREDICTION_TO_THREAT_STEM to no longer
    cover "DDoS" -- a real, currently-configured LABEL_MAP label, so the internal
    ClassificationResult construction still succeeds (it validates against LABEL_MAP,
    which is untouched here) while the query/threat-stem lookup fails. This proves
    that if a real class is ever added to LABEL_MAP before its query/graph mapping is
    wired up, the system fails loudly and explicitly rather than silently producing
    an incorrect threat analysis for a class it doesn't know how to handle. Does not
    modify LABEL_MAP, the real dataset, or the real mapping dicts outside this
    test's patch context.
    """
    request = ClassificationAnalysisRequest(prediction="DDoS", probability=0.9)
    with (
        patch("backend.services.classification.PREDICTION_TO_QUERY", {}),
        patch("backend.services.classification.PREDICTION_TO_THREAT_STEM", {}),
    ):
        with pytest.raises(UnsupportedPredictionError):
            classify_and_analyze(request)


def test_unsupported_prediction_via_api_returns_422_with_no_analysis_leak():
    """End-to-end: today, an unsupported label is rejected at the schema boundary
    (422) before classify_and_analyze() ever runs -- confirming no incorrect
    graph/RAG mapping can be generated for a label the system doesn't recognize."""
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.security import require_auth

    app.dependency_overrides[require_auth] = lambda: None
    try:
        client = TestClient(app)
        response = client.post("/analyze/classification", json={"prediction": "PortScan"})
        assert response.status_code == 422
        assert "analysis" not in response.json()
    finally:
        app.dependency_overrides.pop(require_auth, None)
