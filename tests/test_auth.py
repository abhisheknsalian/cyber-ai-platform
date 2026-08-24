"""Auth tests set/unset CYBER_AI_API_KEY per-test via monkeypatch. This works cleanly
because backend/security.py reads the env var fresh on every request rather than
caching it at import time (see the module docstring there) -- no import-order tricks
needed, unlike CHROMA_PERSIST_DIR/DDOS_DATASET_PATH in conftest.py.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.ml.config import FEATURE_COLUMNS
from backend.models.schemas import LLMAnalysisFragment

client = TestClient(app)

TEST_KEY = "test-only-key-never-a-real-secret"

VALID_CLASSIFY_PAYLOAD = {column: 1000.0 for column in FEATURE_COLUMNS}

FAKE_FRAGMENT = LLMAnalysisFragment(
    severity="High",
    summary="Test summary grounded in retrieved context.",
    attack_vectors=["test vector"],
    indicators=["test indicator"],
    mitigations=["test mitigation"],
    insufficient_context=False,
)

# (method, path, json body) for each protected endpoint, used by the parametrized tests.
PROTECTED_REQUESTS = [
    ("POST", "/analyze", {"query": "Explain phishing attacks and mitigation"}),
    ("POST", "/classify", VALID_CLASSIFY_PAYLOAD),
    ("GET", "/ml/feature-importance", None),
    ("POST", "/analyze/classification", {"prediction": "BENIGN"}),
]

PUBLIC_REQUESTS = [
    ("GET", "/"),
    ("GET", "/health"),
    ("GET", "/threats"),
]


def _send(method: str, path: str, json_body, headers: dict | None = None):
    if method == "GET":
        return client.get(path, headers=headers)
    return client.post(path, json=json_body, headers=headers)


# ---------------------------------------------------------------------------
# Public endpoints: never require auth, regardless of whether a key is configured.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method,path", PUBLIC_REQUESTS)
def test_public_endpoint_works_without_auth_and_without_key_configured(monkeypatch, method, path):
    monkeypatch.delenv("CYBER_AI_API_KEY", raising=False)
    response = _send(method, path, None)
    assert response.status_code == 200


@pytest.mark.parametrize("method,path", PUBLIC_REQUESTS)
def test_public_endpoint_works_without_auth_even_when_key_is_configured(monkeypatch, method, path):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    response = _send(method, path, None)
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Protected endpoints: missing / invalid / malformed credentials -> 401.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method,path,body", PROTECTED_REQUESTS)
def test_protected_endpoint_without_header_returns_401(monkeypatch, method, path, body):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    response = _send(method, path, body)
    assert response.status_code == 401
    assert response.json()["detail"] == "Missing or invalid API key."


@pytest.mark.parametrize("method,path,body", PROTECTED_REQUESTS)
def test_protected_endpoint_with_invalid_key_returns_401(monkeypatch, method, path, body):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    response = _send(method, path, body, headers={"Authorization": "Bearer wrong-key"})
    assert response.status_code == 401


@pytest.mark.parametrize(
    "bad_header",
    [
        "Basic dXNlcjpwYXNz",  # wrong scheme
        "Bearer",  # scheme with no token
        "just-a-raw-token",  # no scheme at all
        "Bearer ",  # scheme with only whitespace as the token
    ],
)
def test_malformed_authorization_header_returns_401(monkeypatch, bad_header):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    response = client.post(
        "/analyze",
        json={"query": "Explain phishing attacks and mitigation"},
        headers={"Authorization": bad_header},
    )
    assert response.status_code == 401


@pytest.mark.parametrize("method,path,body", PROTECTED_REQUESTS)
def test_missing_api_key_configuration_fails_closed_not_crashed(monkeypatch, method, path, body):
    """If CYBER_AI_API_KEY isn't configured server-side at all, protected endpoints
    must reject every request (401) rather than crash or silently allow it through --
    even if the caller happens to send some Authorization header."""
    monkeypatch.delenv("CYBER_AI_API_KEY", raising=False)
    response = _send(method, path, body, headers={"Authorization": "Bearer anything"})
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Valid key: existing behavior is unchanged.
# ---------------------------------------------------------------------------


def test_analyze_with_valid_key_behaves_as_before(monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    with patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=FAKE_FRAGMENT):
        response = client.post(
            "/analyze",
            json={"query": "Explain phishing attacks and mitigation"},
            headers={"Authorization": f"Bearer {TEST_KEY}"},
        )
    assert response.status_code == 200
    assert response.json()["status"] == "analyzed"


def test_classify_with_valid_key_behaves_as_before(monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    response = client.post(
        "/classify",
        json=VALID_CLASSIFY_PAYLOAD,
        headers={"Authorization": f"Bearer {TEST_KEY}"},
    )
    assert response.status_code == 200
    assert response.json()["prediction"] in ("BENIGN", "DDoS")


def test_feature_importance_with_valid_key_behaves_as_before(monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    response = client.get("/ml/feature-importance", headers={"Authorization": f"Bearer {TEST_KEY}"})
    assert response.status_code == 200
    assert len(response.json()) > 0


def test_analyze_classification_with_valid_key_behaves_as_before(monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    response = client.post(
        "/analyze/classification",
        json={"prediction": "BENIGN"},
        headers={"Authorization": f"Bearer {TEST_KEY}"},
    )
    assert response.status_code == 200
    assert response.json()["analysis"] is None


# ---------------------------------------------------------------------------
# The configured key must never be echoed back anywhere.
# ---------------------------------------------------------------------------


def test_key_never_appears_in_401_response_body(monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    response = client.post(
        "/analyze",
        json={"query": "test"},
        headers={"Authorization": "Bearer wrong-key"},
    )
    assert TEST_KEY not in response.text


def test_key_never_appears_in_openapi_schema(monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", TEST_KEY)
    response = client.get("/openapi.json")
    assert TEST_KEY not in response.text
