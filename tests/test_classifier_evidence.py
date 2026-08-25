"""Tests that the classifier's prediction/probability are immutable evidence the LLM
can never override, and that sources/MITRE IDs/indicators/mitigations are backend-
owned (deterministic) rather than LLM-authored -- i.e. a "hallucinated" value the LLM
might produce cannot reach the response in place of the real evidence.
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


# --- Structural guarantees: the LLM's own output schema has no field for these ----


def test_llm_fragment_schema_has_no_source_field():
    assert "sources" not in LLMAnalysisFragment.model_fields


def test_llm_fragment_schema_has_no_mitre_field():
    assert "mitre_attack" not in LLMAnalysisFragment.model_fields
    assert "mitre" not in LLMAnalysisFragment.model_fields


def test_llm_fragment_schema_has_no_prediction_or_probability_field():
    assert "prediction" not in LLMAnalysisFragment.model_fields
    assert "probability" not in LLMAnalysisFragment.model_fields


# --- Behavioral guarantees: response content is backend-computed regardless of what
# the (mocked) LLM call returns -------------------------------------------------

# A deliberately "hostile" fragment: if the LLM's free-text fields somehow leaked into
# source/MITRE/classifier data, these obviously-wrong values would appear.
HOSTILE_FRAGMENT = LLMAnalysisFragment(
    severity="Critical",
    summary="A fabricated summary claiming BENIGN traffic and a fake MITRE ID.",
    attack_vectors=["fabricated vector"],
    indicators=["a completely fabricated indicator not in any source document"],
    mitigations=["a completely fabricated mitigation not in any source document"],
    insufficient_context=False,
)


def test_classifier_prediction_in_response_is_never_overridden_by_llm_output():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=HOSTILE_FRAGMENT):
        response = client.post("/analyze/classification", json={"prediction": "DDoS", "probability": 0.98})

    assert response.status_code == 200
    body = response.json()
    # The classifier evidence must reflect exactly what was requested, regardless of
    # the LLM's summary text claiming something else.
    assert body["classification"]["prediction"] == "DDoS"
    assert body["classification"]["probability"] == 0.98
    assert body["evidence"]["classifier"]["prediction"] == "DDoS"
    assert body["evidence"]["classifier"]["probability"] == 0.98


def test_sources_are_deterministic_regardless_of_llm_output():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=HOSTILE_FRAGMENT):
        response = client.post("/analyze", json={"query": "How can DDoS attacks be mitigated?"})

    body = response.json()
    assert body["sources"], "expected deterministic sources regardless of LLM output"
    assert all(s["source"] == "ddos_attack.txt" for s in body["sources"])


def test_mitre_ids_are_deterministic_regardless_of_llm_output():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=HOSTILE_FRAGMENT):
        response = client.post("/analyze", json={"query": "How can DDoS attacks be mitigated?"})

    body = response.json()
    mitre_ids = {m["id"] for m in body["mitre_attack"]}
    assert mitre_ids == {"T1498"}  # exactly what's in ddos_attack.txt, never invented


def test_indicators_are_graph_derived_not_the_llms_fabricated_ones():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=HOSTILE_FRAGMENT):
        response = client.post("/analyze", json={"query": "How can DDoS attacks be mitigated?"})

    body = response.json()
    assert "a completely fabricated indicator not in any source document" not in body["indicators"]
    assert "Extremely high traffic volume" in body["indicators"]


def test_mitigations_are_graph_derived_not_the_llms_fabricated_ones():
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=HOSTILE_FRAGMENT):
        response = client.post("/analyze", json={"query": "How can DDoS attacks be mitigated?"})

    body = response.json()
    assert "a completely fabricated mitigation not in any source document" not in body["mitigations"]
    assert "Rate limiting" in body["mitigations"]


def test_evidence_source_attribution_answers_why_the_conclusion_was_reached():
    with patch(
        "backend.services.threat_analysis.generate_analysis_fragment",
        return_value=LLMAnalysisFragment(
            severity="High", summary="DDoS mitigation summary.", indicators=[], mitigations=[], insufficient_context=False
        ),
    ):
        response = client.post("/analyze/classification", json={"prediction": "DDoS", "probability": 0.97})

    body = response.json()
    evidence = body["evidence"]
    assert evidence["classifier"] == {"prediction": "DDoS", "probability": 0.97, "model": "random_forest"}
    assert any(v["source"] == "ddos_attack.txt" for v in evidence["vector_evidence"])
    assert any(g["relation"] == "USES" and g["target_name"] == "Network Denial of Service" for g in evidence["graph_evidence"])
    assert any(g["relation"] == "MITIGATED_BY" for g in evidence["graph_evidence"])
