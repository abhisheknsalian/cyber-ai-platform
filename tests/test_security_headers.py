"""Tests for the Phase 8 security response headers (backend/middleware.py)."""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.security import require_auth


@pytest.fixture(autouse=True)
def _bypass_auth():
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)


client = TestClient(app)


@pytest.mark.parametrize("path", ["/", "/health", "/ready", "/threats"])
def test_baseline_security_headers_present_on_every_response(path):
    response = client.get(path)
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_strict_csp_applied_to_json_api_responses():
    response = client.get("/health")
    assert response.headers.get("Content-Security-Policy") == "default-src 'none'; frame-ancestors 'none'"


def test_csp_does_not_break_the_docs_page():
    # Swagger UI loads its JS/CSS from a CDN via inline scripts -- the strict JSON-API
    # CSP would break it, so /docs is deliberately excluded.
    response = client.get("/docs")
    assert response.status_code == 200
    assert "Content-Security-Policy" not in response.headers


def test_auth_endpoints_are_never_cached():
    for response in (
        client.get("/auth/me"),
        client.post("/auth/logout"),
    ):
        assert response.headers.get("Cache-Control") == "no-store"


def test_non_auth_endpoints_do_not_get_the_auth_cache_control():
    response = client.get("/health")
    assert response.headers.get("Cache-Control") != "no-store"


def test_cors_is_not_weakened_by_security_headers():
    # The security-headers middleware must never set an Access-Control-Allow-Origin
    # itself -- that stays exclusively CORSMiddleware's job with its explicit
    # allowlist. A cross-origin preflight from an origin not on that list must still
    # be rejected.
    response = client.options(
        "/analyze",
        headers={
            "Origin": "http://evil.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert "access-control-allow-origin" not in {h.lower() for h in response.headers}


def test_security_headers_do_not_break_existing_functionality():
    response = client.get("/threats")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
