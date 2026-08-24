"""Tests for the Phase 8 in-memory rate limiter (backend/rate_limit.py) and its
application to POST /auth/login, /analyze, /classify, /analyze/classification.

tests/conftest.py's autouse `_reset_rate_limiters` fixture clears both limiters
before/after every test in the whole suite, so these tests (and every other test file
that happens to call a rate-limited endpoint) never see state left over from another
test.
"""

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.ml.config import FEATURE_COLUMNS
from backend.rate_limit import AI_RATE_LIMIT, LOGIN_RATE_LIMIT, RateLimiter
from backend.security import require_auth

VALID_CLASSIFY_PAYLOAD = {column: 1000.0 for column in FEATURE_COLUMNS}


@pytest.fixture(autouse=True)
def _bypass_auth():
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)


client = TestClient(app)


# --- Unit tests on the limiter itself (fast, deterministic, no HTTP) -------------


def test_requests_under_the_limit_are_allowed():
    limiter = RateLimiter(limit=3, window_seconds=60)
    for _ in range(3):
        allowed, _ = limiter.check("k")
        assert allowed is True


def test_request_over_the_limit_is_rejected_with_retry_after():
    limiter = RateLimiter(limit=2, window_seconds=60)
    limiter.check("k")
    limiter.check("k")
    allowed, retry_after = limiter.check("k")
    assert allowed is False
    assert retry_after > 0


def test_different_keys_have_independent_limits():
    limiter = RateLimiter(limit=1, window_seconds=60)
    assert limiter.check("a")[0] is True
    assert limiter.check("b")[0] is True  # a different key, unaffected by a's usage
    assert limiter.check("a")[0] is False  # a is now over its own limit


def test_reset_clears_all_state():
    limiter = RateLimiter(limit=1, window_seconds=60)
    limiter.check("k")
    assert limiter.check("k")[0] is False
    limiter.reset()
    assert limiter.check("k")[0] is True


# --- HTTP-level tests: the endpoints actually enforce their limiter --------------


def test_login_endpoint_is_protected_by_rate_limiting():
    LOGIN_RATE_LIMIT.limit = 3
    try:
        for _ in range(3):
            response = client.post("/auth/login", json={"username": "x", "password": "y"})
            assert response.status_code == 401  # wrong credentials, but not yet rate-limited

        response = client.post("/auth/login", json={"username": "x", "password": "y"})
        assert response.status_code == 429
        assert "Retry-After" in response.headers
    finally:
        LOGIN_RATE_LIMIT.limit = 5
        LOGIN_RATE_LIMIT.reset()


def test_rate_limited_login_response_has_no_secrets_and_is_generic():
    # Deliberately not single letters like "x"/"y" -- those can trivially appear as
    # substrings of ordinary English words in the generic message ("try" contains
    # "y"), which would make this assertion meaningless.
    username, password = "attempted-user", "attempted-password-value"
    LOGIN_RATE_LIMIT.limit = 1
    try:
        client.post("/auth/login", json={"username": username, "password": password})
        response = client.post("/auth/login", json={"username": username, "password": password})
        assert response.status_code == 429
        body = response.json()
        assert username not in body["detail"]
        assert password not in body["detail"]
    finally:
        LOGIN_RATE_LIMIT.limit = 5
        LOGIN_RATE_LIMIT.reset()


def test_analyze_endpoint_is_protected_by_rate_limiting():
    AI_RATE_LIMIT.limit = 2
    try:
        for _ in range(2):
            client.post("/analyze", json={"query": "Explain phishing"})
        response = client.post("/analyze", json={"query": "Explain phishing"})
        assert response.status_code == 429
        assert "Retry-After" in response.headers
    finally:
        AI_RATE_LIMIT.limit = 20
        AI_RATE_LIMIT.reset()


def test_classify_and_analyze_classification_share_one_ai_budget():
    # By design (see backend/rate_limit.py): one shared limiter across all three AI
    # endpoints, so a caller can't multiply their quota by switching endpoints.
    AI_RATE_LIMIT.limit = 2
    try:
        client.post("/classify", json=VALID_CLASSIFY_PAYLOAD)
        client.post("/classify", json=VALID_CLASSIFY_PAYLOAD)
        response = client.post("/analyze/classification", json={"prediction": "BENIGN"})
        assert response.status_code == 429
    finally:
        AI_RATE_LIMIT.limit = 20
        AI_RATE_LIMIT.reset()


def test_public_health_endpoints_are_never_rate_limited():
    AI_RATE_LIMIT.limit = 1
    LOGIN_RATE_LIMIT.limit = 1
    try:
        for _ in range(10):
            assert client.get("/health").status_code == 200
            assert client.get("/ready").status_code in (200, 503)
            assert client.get("/").status_code == 200
    finally:
        AI_RATE_LIMIT.limit = 20
        LOGIN_RATE_LIMIT.limit = 5
        AI_RATE_LIMIT.reset()
        LOGIN_RATE_LIMIT.reset()


def test_rate_limit_response_does_not_expose_internal_state():
    AI_RATE_LIMIT.limit = 1
    try:
        client.post("/analyze", json={"query": "Explain phishing"})
        response = client.post("/analyze", json={"query": "Explain phishing"})
        body = response.json()
        # Only a human-readable message, a request_id, and the standard Retry-After
        # header -- no hit counts, no internal key, no other clients' data.
        assert set(body.keys()) == {"detail", "request_id"}
    finally:
        AI_RATE_LIMIT.limit = 20
        AI_RATE_LIMIT.reset()
