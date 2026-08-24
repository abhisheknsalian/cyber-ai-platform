"""Tests for the Phase 8 request/correlation ID middleware (backend/middleware.py)."""

import logging

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.middleware import REQUEST_ID_HEADER
from backend.security import require_auth


@pytest.fixture(autouse=True)
def _bypass_auth():
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)


client = TestClient(app)


def test_every_response_has_a_request_id_header():
    response = client.get("/health")
    assert response.headers.get(REQUEST_ID_HEADER)


def test_generated_request_ids_are_unique():
    first = client.get("/health").headers[REQUEST_ID_HEADER]
    second = client.get("/health").headers[REQUEST_ID_HEADER]
    assert first != second


def test_supplied_request_id_is_echoed_back():
    response = client.get("/health", headers={REQUEST_ID_HEADER: "caller-supplied-id-123"})
    assert response.headers[REQUEST_ID_HEADER] == "caller-supplied-id-123"


def test_oversized_supplied_request_id_is_replaced_not_trusted():
    huge_id = "a" * 500
    response = client.get("/health", headers={REQUEST_ID_HEADER: huge_id})
    returned = response.headers[REQUEST_ID_HEADER]
    assert returned != huge_id
    assert len(returned) < 200


def test_supplied_request_id_with_unsafe_characters_is_replaced():
    # Newlines/control characters could otherwise be used to inject fake log lines.
    unsafe_id = "abc\ndef\r\x00"
    response = client.get("/health", headers={REQUEST_ID_HEADER: unsafe_id})
    returned = response.headers[REQUEST_ID_HEADER]
    assert returned != unsafe_id
    assert "\n" not in returned and "\r" not in returned


def test_request_id_is_never_treated_as_authentication():
    # A request ID -- even a syntactically valid one -- must never substitute for a
    # real credential. Without dependency_overrides bypassing auth, a protected
    # endpoint must still reject the call regardless of what X-Request-ID is sent.
    app.dependency_overrides.pop(require_auth, None)
    try:
        response = client.post(
            "/classify",
            json={},
            headers={REQUEST_ID_HEADER: "totally-legitimate-looking-id"},
        )
        assert response.status_code == 401
    finally:
        app.dependency_overrides[require_auth] = lambda: None


def test_request_id_appears_in_logs(caplog):
    with caplog.at_level(logging.INFO):
        response = client.get("/health", headers={REQUEST_ID_HEADER: "log-context-check-id"})

    request_id = response.headers[REQUEST_ID_HEADER]
    assert request_id == "log-context-check-id"
    matching = [r for r in caplog.records if getattr(r, "request_id", None) == request_id]
    assert matching, "expected at least one log record tagged with the request ID"


def test_error_response_body_includes_request_id():
    response = client.post("/analyze", json={"query": ""})
    assert response.status_code == 422
    body = response.json()
    assert body["request_id"] == response.headers[REQUEST_ID_HEADER]
