"""Tests for Phase 15 observability: structured event content across the pipeline
(ML/RAG/graph/LLM/investigation persistence), sensitive-data exclusion, the
user-identity log enrichment added in backend/security.py + backend/middleware.py,
and the /metrics endpoint.

Request ID generation/propagation/sanitization and basic log correlation are Phase 8
behavior, already fully covered by tests/test_request_id.py -- NOT re-tested here.
Traceback/500-response safety is already covered by tests/test_error_handling.py.
"""

import logging
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend import metrics
from backend.logging_config import JsonFormatter
from backend.main import app
from backend.ml.config import FEATURE_COLUMNS
from backend.ml.predictor import ModelUnavailableError
from backend.models.schemas import LLMAnalysisFragment
from backend.security import require_auth
from backend.sessions import CSRF_COOKIE_NAME, CSRF_HEADER_NAME

VALID_FEATURES = {column: 1000.0 for column in FEATURE_COLUMNS}

FAKE_FRAGMENT = LLMAnalysisFragment(
    severity="High",
    summary="Test summary grounded in retrieved context.",
    attack_vectors=["test vector"],
    indicators=["test indicator"],
    mitigations=["test mitigation"],
    insufficient_context=False,
)

FAKE_OLLAMA_RESPONSE = {
    "message": {"content": FAKE_FRAGMENT.model_dump_json()},
    "prompt_eval_count": 123,
    "eval_count": 45,
}

# Every field backend/middleware.py's request_received/request_completed/
# request_failed events are allowed to carry -- a closed set, so a test below can
# prove by construction (not by string-searching) that nothing else -- a header, a
# cookie, a request body -- ever leaks into them. `request_id` is added uniformly to
# every log record by backend/logging_config.py's _RequestIdFilter (not by these
# events themselves), so it's expected on all of them too.
_ALLOWED_REQUEST_LOG_FIELDS = {
    "event",
    "method",
    "path",
    "status_code",
    "duration_ms",
    "user_id",
    "auth_method",
    "request_id",
}


@pytest.fixture(autouse=True)
def _reset_metrics():
    metrics.reset()
    yield
    metrics.reset()


@pytest.fixture
def client():
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def bypass_auth():
    """For pure ML/RAG/graph/LLM instrumentation tests, which don't care which
    credential path was used -- same pattern as tests/test_ml_api.py."""
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)


def _register_and_login(client: TestClient, username: str = "obs-tester", password: str = "correct-horse-1"):
    client.post("/auth/register", json={"username": username, "password": password})
    return client.post("/auth/login", json={"username": username, "password": password})


def _csrf_header(client: TestClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE_NAME)
    return {CSRF_HEADER_NAME: token} if token else {}


def _events(caplog, name: str):
    return [r for r in caplog.records if getattr(r, "event", None) == name]


# ---------------------------------------------------------------------------
# HTTP-level: duration + user-identity enrichment (new in Phase 15)
# ---------------------------------------------------------------------------


def test_request_completed_log_includes_duration(caplog):
    with caplog.at_level(logging.INFO):
        TestClient(app).get("/health")
    events = _events(caplog, "request_completed")
    assert events
    assert isinstance(events[-1].duration_ms, float)


def test_request_completed_log_includes_user_id_for_authenticated_session(client, caplog):
    login_response = _register_and_login(client)
    user_id = login_response.json()["user_id"]

    with caplog.at_level(logging.INFO):
        client.get("/investigations")

    events = [r for r in _events(caplog, "request_completed") if r.path == "/investigations"]
    assert events
    assert events[-1].user_id == user_id
    assert events[-1].auth_method == "session"


def test_request_completed_log_omits_user_id_for_public_endpoint(caplog):
    with caplog.at_level(logging.INFO):
        TestClient(app).get("/health")
    events = _events(caplog, "request_completed")
    assert events
    assert not hasattr(events[-1], "user_id")
    assert not hasattr(events[-1], "auth_method")


def test_request_log_events_never_carry_unexpected_fields(client, caplog):
    """Structural proof (not string-searching) that headers/cookies/bodies never
    reach request_received/request_completed: every non-standard field a record
    carries is in the documented allow-list, for every such event across a real
    authenticated POST (the case most likely to leak a body/header if it ever
    would)."""
    from backend.logging_config import _STANDARD_RECORD_ATTRS

    _register_and_login(client)
    with caplog.at_level(logging.INFO):
        client.post("/classify", json=VALID_FEATURES, headers=_csrf_header(client))

    checked_any = False
    for record in caplog.records:
        if getattr(record, "event", None) in ("request_received", "request_completed", "request_failed"):
            checked_any = True
            extra_fields = {key for key in vars(record) if key not in _STANDARD_RECORD_ATTRS}
            assert extra_fields <= _ALLOWED_REQUEST_LOG_FIELDS
    assert checked_any


# ---------------------------------------------------------------------------
# Sensitive-data exclusion
# ---------------------------------------------------------------------------


def test_no_sensitive_data_in_logs_across_a_realistic_authenticated_flow(client, caplog, monkeypatch):
    password = "correct-horse-1"
    wrong_password = "definitely-the-wrong-password-9"
    api_key = "test-only-api-key-never-a-real-secret"
    monkeypatch.setenv("CYBER_AI_API_KEY", api_key)

    with caplog.at_level(logging.DEBUG):
        _register_and_login(client, username="sensitive-check", password=password)
        client.post("/auth/login", json={"username": "sensitive-check", "password": wrong_password})
        session_cookie = client.cookies.get("cyber_ai_session")
        csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
        client.post("/classify", json=VALID_FEATURES, headers=_csrf_header(client))
        client.post("/classify", json=VALID_FEATURES, headers={"Authorization": f"Bearer {api_key}"})

    formatter = JsonFormatter()
    rendered = "\n".join(formatter.format(record) for record in caplog.records)

    assert password not in rendered
    assert wrong_password not in rendered
    assert api_key not in rendered
    assert session_cookie and session_cookie not in rendered
    assert csrf_token and csrf_token not in rendered


def test_classifier_inference_event_has_no_feature_vector_keys(bypass_auth, caplog):
    with caplog.at_level(logging.INFO):
        TestClient(app).post("/classify", json=VALID_FEATURES)

    events = _events(caplog, "classifier_inference")
    assert events
    record = events[-1]
    assert hasattr(record, "prediction")
    assert hasattr(record, "duration_ms")
    assert hasattr(record, "model_version")
    # None of the 78 CICFlowMeter feature names ever became a log field.
    for feature_name in FEATURE_COLUMNS:
        assert not hasattr(record, feature_name)


# ---------------------------------------------------------------------------
# ML instrumentation
# ---------------------------------------------------------------------------


def test_ml_classification_success_metadata(bypass_auth, caplog):
    with caplog.at_level(logging.INFO):
        response = TestClient(app).post("/classify", json=VALID_FEATURES)
    assert response.status_code == 200

    record = _events(caplog, "classifier_inference")[-1]
    assert record.prediction in ("BENIGN", "DDoS")
    assert record.classification in ("malicious", "benign")
    assert isinstance(record.duration_ms, float)


def test_ml_classifier_unavailable_logs_safe_error_no_traceback(bypass_auth, caplog):
    # model_available() (the route's own up-front gate) stays True here -- this
    # exercises the *other* unavailable path, predict() itself raising
    # ModelUnavailableError, which is the one that actually logs the warning event.
    with caplog.at_level(logging.WARNING), patch("backend.main.predict", side_effect=ModelUnavailableError("gone")):
        response = TestClient(app).post("/classify", json=VALID_FEATURES)
    assert response.status_code == 503
    events = _events(caplog, "classifier_unavailable")
    assert events
    assert "Traceback" not in caplog.text


# ---------------------------------------------------------------------------
# RAG + threat graph instrumentation
#
# /analyze uses backend/services/threat_analysis.py's own pre-existing, separate
# retrieval instrumentation (event="rag_retrieval"/"rag_threat_selected", Phase 9,
# untouched by this phase). The events below are specific to
# backend/intelligence/hybrid_retrieval.py::gather_hybrid_evidence() -- the
# classify -> analyze investigation pipeline this phase's diagram actually names --
# which POST /analyze/classification calls (in addition to its own internal
# analyze_query() call); exercised via that endpoint, not /analyze.
# ---------------------------------------------------------------------------


def test_rag_retrieval_event_has_counts_not_document_content(bypass_auth, caplog):
    with (
        caplog.at_level(logging.INFO),
        patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=FAKE_FRAGMENT),
    ):
        response = TestClient(app).post("/analyze/classification", json={"prediction": "DDoS", "probability": 0.9})
    assert response.status_code == 200

    record = _events(caplog, "rag_retrieval_completed")[-1]
    assert isinstance(record.retrieved_count, int)
    assert record.collection
    assert isinstance(record.duration_ms, float)
    assert record.success is True
    assert not hasattr(record, "documents")
    assert not hasattr(record, "content")
    assert not hasattr(record, "chunks")


def test_graph_retrieval_event_has_counts_not_full_graph(bypass_auth, caplog):
    with (
        caplog.at_level(logging.INFO),
        patch("backend.services.threat_analysis.generate_analysis_fragment", return_value=FAKE_FRAGMENT),
    ):
        response = TestClient(app).post("/analyze/classification", json={"prediction": "DDoS", "probability": 0.9})
    assert response.status_code == 200

    record = _events(caplog, "graph_retrieval_completed")[-1]
    assert isinstance(record.entity_count, int)
    assert isinstance(record.relationship_count, int)
    assert isinstance(record.duration_ms, float)
    assert not hasattr(record, "entities")
    assert not hasattr(record, "relationships")
    assert not hasattr(record, "graph")


# ---------------------------------------------------------------------------
# LLM instrumentation
# ---------------------------------------------------------------------------


def test_llm_invocation_event_has_model_and_timing_not_prompt_or_response(bypass_auth, caplog):
    with (
        caplog.at_level(logging.INFO),
        patch("backend.services.llm.ollama.chat", return_value=FAKE_OLLAMA_RESPONSE),
    ):
        response = TestClient(app).post("/analyze", json={"query": "Explain phishing attacks and mitigation"})
    assert response.status_code == 200

    events = [r for r in _events(caplog, "llm_invocation") if getattr(r, "success", None) is True]
    assert events
    record = events[-1]
    assert record.model
    assert isinstance(record.duration_ms, float)
    assert record.prompt_eval_count == 123
    assert record.eval_count == 45
    assert not hasattr(record, "prompt")
    assert not hasattr(record, "content")
    assert not hasattr(record, "summary")
    assert FAKE_FRAGMENT.summary not in caplog.text


def test_llm_invocation_failure_logs_safely(bypass_auth, caplog):
    with caplog.at_level(logging.WARNING), patch(
        "backend.services.llm.ollama.chat", side_effect=RuntimeError("connection refused")
    ):
        response = TestClient(app).post("/analyze", json={"query": "Explain phishing attacks and mitigation"})
    assert response.status_code == 503
    events = [r for r in _events(caplog, "llm_invocation") if getattr(r, "success", None) is False]
    assert events


# ---------------------------------------------------------------------------
# Investigation persistence instrumentation (Phase 14 gap this phase fills)
# ---------------------------------------------------------------------------


def test_investigation_created_event_contains_investigation_id_and_user(client, caplog):
    login_response = _register_and_login(client)
    # AuthStatusResponse.user_id is a str (backend/models/schemas.py); the
    # investigations service layer works in the underlying int users.id
    # (backend/security.py::require_user_id's return type) -- same identity, two
    # legitimately different representations at these two layers.
    user_id = int(login_response.json()["user_id"])

    with caplog.at_level(logging.INFO):
        response = client.post("/investigations", json={"label": "obs test"}, headers=_csrf_header(client))
    investigation_id = response.json()["id"]

    record = _events(caplog, "investigation_created")[-1]
    assert record.investigation_id == investigation_id
    assert record.user_id == user_id
    assert isinstance(record.duration_ms, float)


def test_classification_result_persisted_event_has_metadata_not_features(client, caplog):
    _register_and_login(client)
    investigation_id = client.post("/investigations", json={"label": "x"}, headers=_csrf_header(client)).json()["id"]
    classify_result = client.post("/classify", json=VALID_FEATURES, headers=_csrf_header(client)).json()

    with caplog.at_level(logging.INFO):
        response = client.post(
            f"/investigations/{investigation_id}/classification-results",
            json={"features": VALID_FEATURES, "result": classify_result},
            headers=_csrf_header(client),
        )
    result_id = response.json()["id"]

    record = _events(caplog, "classification_result_persisted")[-1]
    assert record.investigation_id == investigation_id
    assert record.classification_result_id == result_id
    assert record.prediction == classify_result["prediction"]
    assert not hasattr(record, "features")


def test_analysis_result_persisted_event_contains_ids_not_report_content(client, caplog):
    _register_and_login(client)
    investigation_id = client.post("/investigations", json={"label": "x"}, headers=_csrf_header(client)).json()["id"]
    ddos_result = {
        "prediction": "DDoS",
        "probability": 0.98,
        "model": "random_forest",
        "classification": "malicious",
        "class_probabilities": {"BENIGN": 0.02, "DDoS": 0.98},
        "model_version": None,
    }
    result_id = client.post(
        f"/investigations/{investigation_id}/classification-results",
        json={"features": VALID_FEATURES, "result": ddos_result},
        headers=_csrf_header(client),
    ).json()["id"]

    analysis_payload = {
        "analysis": {
            "query": "How can DDoS attacks be mitigated?",
            "status": "analyzed",
            "threat": "DDOS_ATTACK",
            "severity": "High",
            "summary": "Sensitive narrative text that must not appear in logs.",
            "attack_vectors": ["flood"],
            "mitre_attack": [{"id": "T1498", "name": "Network Denial of Service"}],
            "indicators": ["high packet rate"],
            "mitigations": ["rate limiting"],
            "sources": [{"source": "ddos_attack.txt", "threat_type": "ddos_attack", "chunk_index": 0, "score": 0.1}],
        },
        "evidence": None,
    }

    with caplog.at_level(logging.INFO):
        client.post(
            f"/investigations/{investigation_id}/classification-results/{result_id}/analysis-result",
            json=analysis_payload,
            headers=_csrf_header(client),
        )

    record = _events(caplog, "analysis_result_persisted")[-1]
    assert record.investigation_id == investigation_id
    assert record.classification_result_id == result_id
    assert record.severity == "High"
    assert not hasattr(record, "summary")
    formatter = JsonFormatter()
    rendered = "\n".join(formatter.format(r) for r in caplog.records)
    assert "Sensitive narrative text" not in rendered


def test_cross_user_investigation_access_logs_denied_audit_event(caplog):
    owner = TestClient(app, base_url="https://testserver")
    owner.post("/auth/register", json={"username": "obs-owner", "password": "correct-horse-1"})
    owner.post("/auth/login", json={"username": "obs-owner", "password": "correct-horse-1"})
    investigation_id = owner.post(
        "/investigations", json={"label": "x"}, headers=_csrf_header(owner)
    ).json()["id"]

    other = TestClient(app, base_url="https://testserver")
    other.post("/auth/register", json={"username": "obs-other", "password": "correct-horse-1"})
    other_login = other.post("/auth/login", json={"username": "obs-other", "password": "correct-horse-1"})
    other_user_id = int(other_login.json()["user_id"])

    with caplog.at_level(logging.WARNING):
        response = other.get(f"/investigations/{investigation_id}")
    assert response.status_code == 404

    events = _events(caplog, "investigation_access_denied")
    assert events
    assert events[-1].investigation_id == investigation_id
    assert events[-1].user_id == other_user_id


# ---------------------------------------------------------------------------
# Auth audit events
# ---------------------------------------------------------------------------


def test_logout_logs_audit_event_with_user_id(client, caplog):
    login_response = _register_and_login(client)
    user_id = login_response.json()["user_id"]

    with caplog.at_level(logging.INFO):
        client.post("/auth/logout", headers=_csrf_header(client))

    events = _events(caplog, "logout")
    assert events
    assert events[-1].user_id == user_id


# ---------------------------------------------------------------------------
# Metrics endpoint
# ---------------------------------------------------------------------------


def test_metrics_endpoint_reflects_recorded_activity(bypass_auth):
    client_ = TestClient(app)
    client_.post("/classify", json=VALID_FEATURES)

    response = client_.get("/metrics")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "ml_classifications_total" in response.text
    assert "http_requests_total" in response.text
    assert "# TYPE" in response.text


def test_metrics_endpoint_never_exposes_request_scoped_data(bypass_auth):
    client_ = TestClient(app)
    client_.post("/classify", json=VALID_FEATURES)
    response = client_.get("/metrics")
    for forbidden in ("Authorization", "cookie", "password", "session"):
        assert forbidden not in response.text


# ---------------------------------------------------------------------------
# CORS: the frontend must be able to read X-Request-ID cross-origin
# ---------------------------------------------------------------------------


def test_cors_exposes_request_id_header_to_browser_js():
    # Access-Control-Expose-Headers is sent on the actual response, not the OPTIONS
    # preflight -- without it, frontend/src/services/api.ts's
    # response.headers.get("X-Request-ID") fallback would silently return null on
    # every real cross-origin request this app ever makes (frontend:8080 <->
    # backend:8000 are always different origins in this architecture).
    response = TestClient(app).get("/health", headers={"Origin": "http://localhost:5173"})
    exposed = response.headers.get("access-control-expose-headers", "")
    assert "x-request-id" in exposed.lower()


# ---------------------------------------------------------------------------
# No regressions: health stays functional and public
# ---------------------------------------------------------------------------


def test_health_endpoint_still_functional_after_observability_changes():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
