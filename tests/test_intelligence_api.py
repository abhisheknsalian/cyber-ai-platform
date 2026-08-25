"""Tests for the Phase 9 /intelligence/* endpoints: response shapes, public vs
protected access, rate limiting, and error-envelope conventions -- following the same
patterns already established in tests/test_api.py and tests/test_rate_limit.py.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.rate_limit import AI_RATE_LIMIT
from backend.security import require_auth

client = TestClient(app)


@pytest.fixture(autouse=True)
def _bypass_auth():
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)


# --- GET /intelligence/entities (public) -----------------------------------------


def test_entities_endpoint_is_public_no_auth_required():
    app.dependency_overrides.pop(require_auth, None)
    try:
        response = client.get("/intelligence/entities")
        assert response.status_code == 200
    finally:
        app.dependency_overrides[require_auth] = lambda: None


def test_entities_endpoint_returns_all_entity_types():
    response = client.get("/intelligence/entities")
    assert response.status_code == 200
    body = response.json()
    types_present = {item["type"] for item in body}
    assert types_present == {"threat", "technique", "indicator", "mitigation", "source"}


def test_entities_endpoint_filters_by_type():
    response = client.get("/intelligence/entities?entity_type=threat")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 5
    assert all(item["type"] == "threat" for item in body)


def test_entities_endpoint_response_shape():
    response = client.get("/intelligence/entities?entity_type=threat")
    for item in response.json():
        assert {"id", "type", "name"} <= item.keys()


# --- GET /intelligence/graph/{threat_id} (public) ---------------------------------


def test_graph_endpoint_is_public_no_auth_required():
    app.dependency_overrides.pop(require_auth, None)
    try:
        response = client.get("/intelligence/graph/ddos_attack")
        assert response.status_code == 200
    finally:
        app.dependency_overrides[require_auth] = lambda: None


def test_graph_endpoint_returns_threat_and_relations():
    response = client.get("/intelligence/graph/ddos_attack")
    assert response.status_code == 200
    body = response.json()
    assert body["threat"]["name"] == "DDoS Attack"
    assert len(body["relations"]) > 0
    assert {"relation", "target", "reference"} <= body["relations"][0].keys()


def test_graph_endpoint_returns_404_for_unknown_threat():
    response = client.get("/intelligence/graph/not_a_real_threat")
    assert response.status_code == 404
    assert "request_id" in response.json()


# --- POST /intelligence/search (protected + rate-limited) -------------------------


def test_search_endpoint_requires_authentication():
    app.dependency_overrides.pop(require_auth, None)
    try:
        response = client.post("/intelligence/search", json={"query": "DDoS mitigation"})
        assert response.status_code == 401
    finally:
        app.dependency_overrides[require_auth] = lambda: None


def test_search_endpoint_returns_results_enriched_with_graph_relations():
    response = client.post("/intelligence/search", json={"query": "How can DDoS attacks be mitigated?"})
    assert response.status_code == 200
    body = response.json()
    assert len(body) > 0
    for item in body:
        assert {"source", "threat_type", "chunk_index", "score", "graph_relations"} <= item.keys()


def test_search_endpoint_rejects_blank_query():
    response = client.post("/intelligence/search", json={"query": "   "})
    assert response.status_code == 422


def test_search_endpoint_is_rate_limited():
    AI_RATE_LIMIT.limit = 2
    try:
        for _ in range(2):
            client.post("/intelligence/search", json={"query": "DDoS mitigation"})
        response = client.post("/intelligence/search", json={"query": "DDoS mitigation"})
        assert response.status_code == 429
        assert "Retry-After" in response.headers
    finally:
        AI_RATE_LIMIT.limit = 20
        AI_RATE_LIMIT.reset()


def test_search_endpoint_shares_ai_rate_limit_budget_with_analyze():
    # Consistent with /analyze, /classify, /analyze/classification already sharing one
    # budget (backend/rate_limit.py) -- /intelligence/search draws from the same pool.
    AI_RATE_LIMIT.limit = 1
    try:
        client.post("/analyze", json={"query": "Explain phishing"})
        response = client.post("/intelligence/search", json={"query": "DDoS mitigation"})
        assert response.status_code == 429
    finally:
        AI_RATE_LIMIT.limit = 20
        AI_RATE_LIMIT.reset()
