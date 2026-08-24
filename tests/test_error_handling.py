"""Tests for the Phase 8 error-response envelope (backend/main.py exception handlers).

No response body -- for any error type -- should ever contain a Python traceback,
a filesystem path, an environment variable value, or a secret. Every error response
should carry a request_id, and existing `detail`-based frontend error parsing
(frontend/src/services/api.ts) must keep working unmodified.
"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.security import require_auth

FORBIDDEN_SUBSTRINGS = ["Traceback", "site-packages", "/Users/", "raise ", ".py\", line"]


@pytest.fixture(autouse=True)
def _bypass_auth():
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)


# raise_server_exceptions=False: Starlette's TestClient re-raises an unhandled
# exception into the *test process* by default (so developers notice bugs during
# testing), even when the app's own global exception handler already converted it
# into a safe response. These tests are specifically about what a real deployed
# server sends over HTTP for an unhandled exception, so that re-raise needs to be
# disabled -- otherwise the mocked RuntimeError/ValueError below would blow up the
# test itself instead of producing a response to assert on.
client = TestClient(app, raise_server_exceptions=False)


def test_validation_error_has_no_traceback_and_has_request_id():
    response = client.post("/analyze", json={"query": ""})
    assert response.status_code == 422
    text = response.text
    for forbidden in FORBIDDEN_SUBSTRINGS:
        assert forbidden not in text
    assert response.json()["request_id"]


def test_known_http_exception_preserves_detail_and_adds_request_id():
    # A deliberately-raised HTTPException (e.g. vector store unavailable) must keep
    # its existing string `detail` -- the frontend parses this directly -- with
    # request_id added alongside it, not in place of it.
    with patch("backend.services.threat_analysis.vector_store_available", return_value=False):
        response = client.post("/analyze", json={"query": "Explain phishing"})
    assert response.status_code == 503
    body = response.json()
    assert isinstance(body["detail"], str)
    assert "uv run python -m backend.rag.ingestion" in body["detail"]
    assert body["request_id"]


def test_unhandled_exception_returns_generic_500_without_internals(caplog):
    # /threats currently has no try/except of its own -- exercise the catch-all
    # handler directly by forcing list_threat_categories() to blow up.
    with patch("backend.main.list_threat_categories", side_effect=RuntimeError("disk exploded at /secret/path")):
        response = client.get("/threats")

    assert response.status_code == 500
    body = response.json()
    assert body["detail"] == "An unexpected error occurred."
    assert "/secret/path" not in response.text
    assert "RuntimeError" not in response.text
    assert body["request_id"]


def test_unhandled_exception_is_logged_server_side_with_full_detail(caplog):
    import logging

    with caplog.at_level(logging.ERROR):
        with patch(
            "backend.main.list_threat_categories",
            side_effect=RuntimeError("disk exploded at /secret/path"),
        ):
            client.get("/threats")

    # The detail that must never reach the client is expected to appear in the
    # server-side log -- that's the whole point of keeping it there instead.
    log_text = "\n".join(r.getMessage() + str(getattr(r, "exc_info", "")) for r in caplog.records)
    assert any("disk exploded" in r.getMessage() or (r.exc_text and "disk exploded" in r.exc_text) for r in caplog.records)


def test_500_response_has_no_python_internals_leaked():
    with patch("backend.main.list_threat_categories", side_effect=ValueError("boom")):
        response = client.get("/threats")
    for forbidden in FORBIDDEN_SUBSTRINGS:
        assert forbidden not in response.text


def test_error_responses_never_contain_configured_secrets(monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", "super-secret-test-key-value")
    with patch("backend.main.list_threat_categories", side_effect=RuntimeError("boom")):
        response = client.get("/threats")
    assert "super-secret-test-key-value" not in response.text
