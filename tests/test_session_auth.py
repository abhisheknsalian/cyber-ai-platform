"""Tests for browser session authentication (POST /auth/login, /auth/logout,
GET /auth/me) and its interaction with require_auth().

Each test gets its own fresh TestClient (not a shared module-level one, unlike the
other test files) because httpx's TestClient keeps a real cookie jar per instance --
sharing one across tests would leak a logged-in session between them.
"""

import logging

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.ml.config import FEATURE_COLUMNS
from backend.sessions import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, SESSION_COOKIE_NAME

USERNAME = "test-admin"
PASSWORD = "test-only-password-never-a-real-secret"

VALID_CLASSIFY_PAYLOAD = {column: 1000.0 for column in FEATURE_COLUMNS}


@pytest.fixture
def client():
    # https:// base_url (not the TestClient default http://testserver) so httpx's
    # cookie jar actually attaches our Secure cookies to subsequent requests --
    # matching how a real browser treats https:// (or http://localhost) as trustworthy.
    return TestClient(app, base_url="https://testserver")


@pytest.fixture(autouse=True)
def _configure_credentials(monkeypatch):
    monkeypatch.setenv("CYBER_AI_USERNAME", USERNAME)
    monkeypatch.setenv("CYBER_AI_PASSWORD", PASSWORD)


def _login(client: TestClient, username: str = USERNAME, password: str = PASSWORD):
    return client.post("/auth/login", json={"username": username, "password": password})


def _csrf_header(client: TestClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE_NAME)
    return {CSRF_HEADER_NAME: token} if token else {}


# ---------------------------------------------------------------------------
# Authentication: login / logout / me
# ---------------------------------------------------------------------------


def test_login_success(client):
    response = _login(client)
    assert response.status_code == 200
    body = response.json()
    # Phase 13: the demo/bootstrap credential path (backend/services/auth.py) always
    # reports the "demo" sentinel user_id -- it's never backed by a real database row.
    assert body == {"authenticated": True, "username": USERNAME, "user_id": "demo"}
    assert SESSION_COOKIE_NAME in client.cookies
    assert CSRF_COOKIE_NAME in client.cookies


def test_login_invalid_username_returns_401(client):
    response = _login(client, username="not-the-real-user")
    assert response.status_code == 401
    assert SESSION_COOKIE_NAME not in client.cookies


def test_login_invalid_password_returns_401(client):
    response = _login(client, password="not-the-real-password")
    assert response.status_code == 401
    assert SESSION_COOKIE_NAME not in client.cookies


def test_login_missing_credentials_returns_422(client):
    assert client.post("/auth/login", json={"username": USERNAME}).status_code == 422
    assert client.post("/auth/login", json={"password": PASSWORD}).status_code == 422
    assert client.post("/auth/login", json={}).status_code == 422


def test_logout_destroys_session(client):
    _login(client)
    session_cookie_before = client.cookies.get(SESSION_COOKIE_NAME)
    assert session_cookie_before

    logout_response = client.post("/auth/logout", headers=_csrf_header(client))
    assert logout_response.status_code == 200
    assert logout_response.json() == {"authenticated": False, "username": None, "user_id": None}

    # The old session token must no longer work even if a client kept it around.
    client.cookies.set(SESSION_COOKIE_NAME, session_cookie_before)
    response = client.post("/classify", json=VALID_CLASSIFY_PAYLOAD)
    assert response.status_code == 401


def test_logout_without_a_session_is_a_safe_no_op(client):
    response = client.post("/auth/logout")
    assert response.status_code == 200
    assert response.json()["authenticated"] is False


def test_auth_me_unauthenticated(client):
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json() == {"authenticated": False, "username": None, "user_id": None}


def test_auth_me_authenticated(client):
    _login(client)
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json() == {"authenticated": True, "username": USERNAME, "user_id": "demo"}


# ---------------------------------------------------------------------------
# Session-based access to protected endpoints
# ---------------------------------------------------------------------------


def test_protected_endpoint_with_valid_session_succeeds(client):
    _login(client)
    response = client.post("/classify", json=VALID_CLASSIFY_PAYLOAD, headers=_csrf_header(client))
    assert response.status_code == 200
    assert response.json()["prediction"] in ("BENIGN", "DDoS")


def test_protected_endpoint_without_session_returns_401(client):
    response = client.post("/classify", json=VALID_CLASSIFY_PAYLOAD)
    assert response.status_code == 401


def test_protected_get_endpoint_with_valid_session_succeeds_without_csrf_header(client):
    """GET is a safe method -- no state change, so no CSRF header is required."""
    _login(client)
    response = client.get("/ml/feature-importance")
    assert response.status_code == 200


def test_protected_post_endpoint_with_session_but_missing_csrf_header_returns_401(client):
    _login(client)
    response = client.post("/classify", json=VALID_CLASSIFY_PAYLOAD)  # no X-CSRF-Token
    assert response.status_code == 401


def test_protected_post_endpoint_with_session_but_wrong_csrf_token_returns_401(client):
    _login(client)
    response = client.post(
        "/classify", json=VALID_CLASSIFY_PAYLOAD, headers={CSRF_HEADER_NAME: "the-wrong-token"}
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Security properties
# ---------------------------------------------------------------------------


def test_session_cookie_is_httponly(client):
    response = _login(client)
    set_cookie_headers = response.headers.get_list("set-cookie")
    session_header = next(h for h in set_cookie_headers if h.startswith(f"{SESSION_COOKIE_NAME}="))
    assert "httponly" in session_header.lower()
    assert "samesite=none" in session_header.lower()
    assert "secure" in session_header.lower()


def test_csrf_cookie_is_not_httponly(client):
    """The CSRF cookie must be readable by frontend JS -- that's the whole point of
    the double-submit pattern -- so it must NOT be HttpOnly."""
    response = _login(client)
    set_cookie_headers = response.headers.get_list("set-cookie")
    csrf_header = next(h for h in set_cookie_headers if h.startswith(f"{CSRF_COOKIE_NAME}="))
    assert "httponly" not in csrf_header.lower()


def test_login_response_never_contains_password(client):
    response = _login(client)
    assert PASSWORD not in response.text


def test_login_response_never_contains_session_or_csrf_token_values(client):
    response = _login(client)
    session_token = client.cookies.get(SESSION_COOKIE_NAME)
    csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
    assert session_token not in response.text
    assert csrf_token not in response.text


def test_auth_me_response_never_contains_session_token(client):
    _login(client)
    session_token = client.cookies.get(SESSION_COOKIE_NAME)
    response = client.get("/auth/me")
    assert session_token not in response.text


def test_credentials_never_appear_in_logs(client, caplog):
    with caplog.at_level(logging.DEBUG):
        _login(client)  # success
        _login(client, password="a-completely-wrong-password")  # failure

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert PASSWORD not in log_text
    assert "a-completely-wrong-password" not in log_text


def test_session_token_never_appears_in_logs(client, caplog):
    with caplog.at_level(logging.DEBUG):
        _login(client)
        session_token = client.cookies.get(SESSION_COOKIE_NAME)
        client.post("/classify", json=VALID_CLASSIFY_PAYLOAD, headers=_csrf_header(client))

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert session_token not in log_text
