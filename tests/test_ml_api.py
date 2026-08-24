from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.ml.config import FEATURE_COLUMNS
from backend.security import require_api_key

client = TestClient(app)


@pytest.fixture(autouse=True)
def _bypass_auth():
    """This file tests classifier/business logic, not auth (see tests/test_auth.py
    for that) -- FastAPI's dependency_overrides is the standard way to isolate the two."""
    app.dependency_overrides[require_api_key] = lambda: None
    yield
    app.dependency_overrides.pop(require_api_key, None)

VALID_PAYLOAD = {column: 1000.0 for column in FEATURE_COLUMNS}


def test_valid_classification_request_returns_200():
    response = client.post("/classify", json=VALID_PAYLOAD)
    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] in ("BENIGN", "DDoS")
    assert body["model"] == "random_forest"
    assert body["probability"] is None or 0.0 <= body["probability"] <= 1.0


def test_missing_feature_returns_422():
    payload = dict(VALID_PAYLOAD)
    del payload["Flow Duration"]
    response = client.post("/classify", json=payload)
    assert response.status_code == 422


def test_invalid_feature_type_returns_422():
    payload = dict(VALID_PAYLOAD)
    payload["Flow Duration"] = "not-a-number"
    response = client.post("/classify", json=payload)
    assert response.status_code == 422


def test_unexpected_extra_field_returns_422():
    payload = dict(VALID_PAYLOAD)
    payload["totally_made_up_feature"] = 1.0
    response = client.post("/classify", json=payload)
    assert response.status_code == 422


def test_model_unavailable_returns_503():
    with patch("backend.main.model_available", return_value=False):
        response = client.post("/classify", json=VALID_PAYLOAD)
    assert response.status_code == 503


def test_feature_importance_endpoint_returns_200():
    response = client.get("/ml/feature-importance")
    assert response.status_code == 200
    body = response.json()
    assert len(body) > 0
    assert all("feature" in item and "importance" in item for item in body)
