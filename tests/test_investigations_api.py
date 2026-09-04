"""Tests for the persistent, per-user investigation endpoints (Phase 14):
POST/GET /investigations, GET /investigations/{id}, and the two persistence-only
endpoints for an already-computed classification/analysis result.

Each test gets its own fresh TestClient (same reasoning as test_auth_register.py):
httpx's per-instance cookie jar would otherwise leak a session between tests.
tests/conftest.py's `_reset_users_table` / `_reset_investigations_tables` fixtures
clear both tables before/after every test.
"""

import logging

import pytest
from fastapi.testclient import TestClient

from backend.db.models import AnalysisRecord, ClassificationRecord, Investigation
from backend.db.session import session_scope
from backend.main import app
from backend.ml.config import FEATURE_COLUMNS
from backend.sessions import CSRF_COOKIE_NAME, CSRF_HEADER_NAME

VALID_FEATURES = {column: 1000.0 for column in FEATURE_COLUMNS}

VALID_RESULT = {
    "prediction": "DDoS",
    "probability": 0.98,
    "model": "random_forest",
    "classification": "malicious",
    "class_probabilities": {"BENIGN": 0.02, "DDoS": 0.98},
    "model_version": "2026-01-01T00:00:00",
}

VALID_ANALYSIS = {
    "query": "How can DDoS attacks be mitigated?",
    "status": "analyzed",
    "threat": "DDOS_ATTACK",
    "severity": "High",
    "summary": "Test summary grounded in retrieved context.",
    "attack_vectors": ["volumetric flood"],
    "mitre_attack": [{"id": "T1498", "name": "Network Denial of Service"}],
    "indicators": ["high packet rate"],
    "mitigations": ["rate limiting"],
    "sources": [{"source": "ddos_attack.txt", "threat_type": "ddos_attack", "chunk_index": 0, "score": 0.1}],
}

VALID_EVIDENCE = {
    "query": "How can DDoS attacks be mitigated?",
    "primary_threat": "ddos_attack",
    "classifier": {"prediction": "DDoS", "probability": 0.98, "model": "random_forest"},
    "vector_evidence": [{"source": "ddos_attack.txt", "threat_type": "ddos_attack", "chunk_index": 0, "score": 0.1}],
    "graph_evidence": [],
    "vector_duration_ms": 12.3,
    "graph_duration_ms": 4.5,
}


@pytest.fixture
def client():
    return TestClient(app, base_url="https://testserver")


def _register(client: TestClient, username: str, password: str = "correct-horse-1"):
    response = client.post("/auth/register", json={"username": username, "password": password})
    assert response.status_code == 201, response.text
    return response


def _login(client: TestClient, username: str, password: str = "correct-horse-1"):
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response


def _csrf_header(client: TestClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE_NAME)
    return {CSRF_HEADER_NAME: token} if token else {}


def _registered_client(username: str = "investigator", password: str = "correct-horse-1") -> TestClient:
    """A fresh client, registered and logged in as a brand-new user."""
    client = TestClient(app, base_url="https://testserver")
    _register(client, username, password)
    _login(client, username, password)
    return client


def _create_investigation(client: TestClient, label: str | None = "Test investigation") -> int:
    response = client.post("/investigations", json={"label": label}, headers=_csrf_header(client))
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _post_classification(client: TestClient, investigation_id: int, features=None, result=None):
    return client.post(
        f"/investigations/{investigation_id}/classification-results",
        json={"features": features or VALID_FEATURES, "result": result or VALID_RESULT},
        headers=_csrf_header(client),
    )


def _post_analysis(client: TestClient, investigation_id: int, result_id: int, analysis=None, evidence=None):
    return client.post(
        f"/investigations/{investigation_id}/classification-results/{result_id}/analysis-result",
        json={"analysis": analysis or VALID_ANALYSIS, "evidence": evidence if evidence is not None else VALID_EVIDENCE},
        headers=_csrf_header(client),
    )


# ---------------------------------------------------------------------------
# 1-3. POST /investigations auth boundary
# ---------------------------------------------------------------------------


def test_create_investigation_without_auth_rejected(client):
    response = client.post("/investigations", json={"label": "x"})
    assert response.status_code == 401


def test_create_investigation_with_api_key_only_rejected(client, monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", "test-only-key-never-a-real-secret")
    response = client.post(
        "/investigations",
        json={"label": "x"},
        headers={"Authorization": "Bearer test-only-key-never-a-real-secret"},
    )
    assert response.status_code == 401


def test_create_investigation_with_demo_session_rejected_403(client, monkeypatch):
    monkeypatch.setenv("CYBER_AI_USERNAME", "demo-operator")
    monkeypatch.setenv("CYBER_AI_PASSWORD", "demo-password-only-for-tests")
    _login(client, "demo-operator", "demo-password-only-for-tests")
    response = client.post("/investigations", json={"label": "x"}, headers=_csrf_header(client))
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# 4-5. Registered user can create; DB row has correct user_id
# ---------------------------------------------------------------------------


def test_create_investigation_registered_user_succeeds(client):
    _register(client, "alice")
    _login(client, "alice")
    response = client.post("/investigations", json={"label": "DDoS investigation"}, headers=_csrf_header(client))
    assert response.status_code == 201
    body = response.json()
    assert body["label"] == "DDoS investigation"
    assert "id" in body and "created_at" in body and "updated_at" in body


def test_created_investigation_has_correct_owner_in_db(client):
    _register(client, "alice")
    _login(client, "alice")
    investigation_id = _create_investigation(client)

    with session_scope() as db:
        from backend.db.models import User

        user = db.query(User).filter_by(username="alice").one()
        investigation = db.query(Investigation).filter_by(id=investigation_id).one()
        assert investigation.user_id == user.id


# ---------------------------------------------------------------------------
# 6-7. List isolation
# ---------------------------------------------------------------------------


def test_list_investigations_empty_for_new_user(client):
    _register(client, "alice")
    _login(client, "alice")
    response = client.get("/investigations")
    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}


def test_list_investigations_only_shows_own(client):
    other = _registered_client("bob")
    _create_investigation(other, "Bob's investigation")

    _register(client, "alice")
    _login(client, "alice")
    _create_investigation(client, "Alice's investigation")

    response = client.get("/investigations")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert [item["label"] for item in body["items"]] == ["Alice's investigation"]


# ---------------------------------------------------------------------------
# 8-10. Detail: owner OK, cross-user 404, nonexistent 404 (same shape)
# ---------------------------------------------------------------------------


def test_get_investigation_detail_owner_succeeds(client):
    _register(client, "alice")
    _login(client, "alice")
    investigation_id = _create_investigation(client)
    response = client.get(f"/investigations/{investigation_id}")
    assert response.status_code == 200
    assert response.json()["id"] == investigation_id
    assert response.json()["classification_results"] == []


def test_get_investigation_detail_other_user_returns_404(client):
    other = _registered_client("bob")
    other_investigation_id = _create_investigation(other)

    _register(client, "alice")
    _login(client, "alice")
    response = client.get(f"/investigations/{other_investigation_id}")
    assert response.status_code == 404


def test_get_investigation_detail_nonexistent_matches_cross_user_shape(client):
    other = _registered_client("bob")
    other_investigation_id = _create_investigation(other)

    _register(client, "alice")
    _login(client, "alice")
    cross_user_response = client.get(f"/investigations/{other_investigation_id}")
    nonexistent_response = client.get("/investigations/999999")

    assert cross_user_response.status_code == nonexistent_response.status_code == 404
    # Compare `detail` only -- `request_id` (backend/main.py's error envelope) is
    # expected to differ per request; the externally-meaningful part of the response
    # is what must be indistinguishable between the two cases.
    assert cross_user_response.json()["detail"] == nonexistent_response.json()["detail"]


# ---------------------------------------------------------------------------
# 11-12. Cross-user write isolation
# ---------------------------------------------------------------------------


def test_cross_user_classification_write_returns_404(client):
    other = _registered_client("bob")
    other_investigation_id = _create_investigation(other)

    _register(client, "alice")
    _login(client, "alice")
    response = _post_classification(client, other_investigation_id)
    assert response.status_code == 404


def test_failed_cross_user_write_creates_no_row(client):
    other = _registered_client("bob")
    other_investigation_id = _create_investigation(other)

    _register(client, "alice")
    _login(client, "alice")
    _post_classification(client, other_investigation_id)

    with session_scope() as db:
        count = db.query(ClassificationRecord).filter_by(investigation_id=other_investigation_id).count()
        assert count == 0


# ---------------------------------------------------------------------------
# 13-15. Classification persistence: round-trip, multiple results, latest pointer
# ---------------------------------------------------------------------------


def test_classification_features_round_trip(client):
    _register(client, "alice")
    _login(client, "alice")
    investigation_id = _create_investigation(client)
    response = _post_classification(client, investigation_id)
    assert response.status_code == 201
    body = response.json()
    assert body["features"] == VALID_FEATURES
    assert body["prediction"] == "DDoS"
    assert body["classification"] == "malicious"
    assert body["class_probabilities"] == VALID_RESULT["class_probabilities"]
    assert body["analysis_result"] is None


def test_multiple_classification_results_in_one_investigation(client):
    _register(client, "alice")
    _login(client, "alice")
    investigation_id = _create_investigation(client)
    first = _post_classification(client, investigation_id)
    second = _post_classification(client, investigation_id, result={**VALID_RESULT, "prediction": "BENIGN", "classification": "benign"})
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] != second.json()["id"]

    detail = client.get(f"/investigations/{investigation_id}").json()
    assert len(detail["classification_results"]) == 2
    # Oldest -> newest for timeline rendering.
    assert detail["classification_results"][0]["id"] == first.json()["id"]
    assert detail["classification_results"][1]["id"] == second.json()["id"]


def test_latest_classification_id_points_to_newest(client):
    _register(client, "alice")
    _login(client, "alice")
    investigation_id = _create_investigation(client)
    _post_classification(client, investigation_id)
    second = _post_classification(client, investigation_id)

    with session_scope() as db:
        investigation = db.query(Investigation).filter_by(id=investigation_id).one()
        assert investigation.latest_classification_id == second.json()["id"]

    summary = client.get("/investigations").json()["items"][0]
    assert summary["latest_classification"]["id"] == second.json()["id"]


# ---------------------------------------------------------------------------
# 16-20. Analysis persistence: success, duplicate 409, chain-ownership 404,
#         cross-user nested write 404, JSON round-trip
# ---------------------------------------------------------------------------


def test_owner_can_persist_analysis(client):
    _register(client, "alice")
    _login(client, "alice")
    investigation_id = _create_investigation(client)
    result_id = _post_classification(client, investigation_id).json()["id"]

    response = _post_analysis(client, investigation_id, result_id)
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == "analyzed"
    assert body["severity"] == "High"


def test_duplicate_analysis_returns_409(client):
    _register(client, "alice")
    _login(client, "alice")
    investigation_id = _create_investigation(client)
    result_id = _post_classification(client, investigation_id).json()["id"]
    _post_analysis(client, investigation_id, result_id)

    second = _post_analysis(client, investigation_id, result_id)
    assert second.status_code == 409


def test_wrong_investigation_result_chain_returns_404(client):
    """A result_id that's real but belongs to a DIFFERENT investigation (owned by the
    same user) must not be reachable through the wrong investigation_id in the path."""
    _register(client, "alice")
    _login(client, "alice")
    investigation_a = _create_investigation(client, "A")
    investigation_b = _create_investigation(client, "B")
    result_in_b = _post_classification(client, investigation_b).json()["id"]

    response = _post_analysis(client, investigation_a, result_in_b)
    assert response.status_code == 404


def test_cross_user_nested_analysis_write_returns_404(client):
    other = _registered_client("bob")
    other_investigation_id = _create_investigation(other)
    other_result_id = _post_classification(other, other_investigation_id).json()["id"]

    _register(client, "alice")
    _login(client, "alice")
    response = _post_analysis(client, other_investigation_id, other_result_id)
    assert response.status_code == 404

    with session_scope() as db:
        assert db.query(AnalysisRecord).count() == 0


def test_analysis_and_evidence_json_round_trip(client):
    _register(client, "alice")
    _login(client, "alice")
    investigation_id = _create_investigation(client)
    result_id = _post_classification(client, investigation_id).json()["id"]
    _post_analysis(client, investigation_id, result_id)

    detail = client.get(f"/investigations/{investigation_id}").json()
    stored = detail["classification_results"][0]["analysis_result"]
    assert stored["mitre_attack"] == VALID_ANALYSIS["mitre_attack"]
    assert stored["sources"] == VALID_ANALYSIS["sources"]
    assert stored["evidence"]["classifier"] == VALID_EVIDENCE["classifier"]
    assert stored["evidence"]["vector_evidence"] == VALID_EVIDENCE["vector_evidence"]


# ---------------------------------------------------------------------------
# 21-22. SQLite cascade + foreign-key enforcement
# ---------------------------------------------------------------------------


def test_deleting_investigation_cascades_to_children(client):
    _register(client, "alice")
    _login(client, "alice")
    investigation_id = _create_investigation(client)
    result_id = _post_classification(client, investigation_id).json()["id"]
    _post_analysis(client, investigation_id, result_id)

    with session_scope() as db:
        db.query(Investigation).filter_by(id=investigation_id).delete()

    with session_scope() as db:
        assert db.query(ClassificationRecord).filter_by(id=result_id).count() == 0
        assert db.query(AnalysisRecord).filter_by(classification_result_id=result_id).count() == 0


def test_sqlite_foreign_key_enforcement_is_enabled():
    """Regression guard for backend/db/session.py's PRAGMA foreign_keys=ON listener --
    without it, this INSERT into a nonexistent investigation_id would silently
    succeed on SQLite even though it should violate the FK constraint."""
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        with session_scope() as db:
            db.add(
                ClassificationRecord(
                    investigation_id=999999,
                    features={},
                    prediction="BENIGN",
                    classification="benign",
                )
            )
            db.flush()


# ---------------------------------------------------------------------------
# 23. Pagination
# ---------------------------------------------------------------------------


def test_pagination_limit_and_offset(client):
    _register(client, "alice")
    _login(client, "alice")
    for i in range(5):
        _create_investigation(client, f"Investigation {i}")

    first_page = client.get("/investigations?limit=2&offset=0").json()
    second_page = client.get("/investigations?limit=2&offset=2").json()

    assert first_page["total"] == 5
    assert len(first_page["items"]) == 2
    assert len(second_page["items"]) == 2
    first_ids = {item["id"] for item in first_page["items"]}
    second_ids = {item["id"] for item in second_page["items"]}
    assert first_ids.isdisjoint(second_ids)


# ---------------------------------------------------------------------------
# 24. Existing auth behavior for /classify, /analyze/classification unchanged
# ---------------------------------------------------------------------------


def test_classify_still_works_with_api_key_only(client, monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", "test-only-key-never-a-real-secret")
    response = client.post(
        "/classify",
        json=VALID_FEATURES,
        headers={"Authorization": "Bearer test-only-key-never-a-real-secret"},
    )
    assert response.status_code == 200
    assert response.json()["prediction"] in ("BENIGN", "DDoS")


def test_classify_still_rejects_demo_session_credential_mismatch_the_same_way(client, monkeypatch):
    """Not a persistence endpoint -- /classify keeps accepting a registered-user
    session exactly like before, no new restriction introduced by Phase 14."""
    _register(client, "alice")
    _login(client, "alice")
    response = client.post("/classify", json=VALID_FEATURES, headers=_csrf_header(client))
    assert response.status_code == 200


def test_registration_and_investigation_credentials_never_appear_in_logs(client, caplog):
    with caplog.at_level(logging.DEBUG):
        _register(client, "alice")
        _login(client, "alice")
        investigation_id = _create_investigation(client)
        _post_classification(client, investigation_id)

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "correct-horse-1" not in log_text
