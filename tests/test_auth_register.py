"""Tests for POST /auth/register and DB-backed POST /auth/login (Phase 13).

Each test gets its own fresh TestClient (not shared module-level, like
test_session_auth.py) so httpx's per-instance cookie jar never leaks a session
between tests. tests/conftest.py's `_reset_users_table` fixture clears the `users`
table before/after every test, so tests never see another test's registered account.
"""

import logging

import pytest
from fastapi.testclient import TestClient

from backend.db.models import User
from backend.db.session import session_scope
from backend.main import app
from backend.ml.config import FEATURE_COLUMNS
from backend.sessions import CSRF_COOKIE_NAME, CSRF_HEADER_NAME

VALID_CLASSIFY_PAYLOAD = {column: 1000.0 for column in FEATURE_COLUMNS}


@pytest.fixture
def client():
    return TestClient(app, base_url="https://testserver")


def _register(client: TestClient, username: str = "new-analyst", password: str = "correct-horse-1"):
    return client.post("/auth/register", json={"username": username, "password": password})


def _login(client: TestClient, username: str = "new-analyst", password: str = "correct-horse-1"):
    return client.post("/auth/login", json={"username": username, "password": password})


def _csrf_header(client: TestClient) -> dict[str, str]:
    token = client.cookies.get(CSRF_COOKIE_NAME)
    return {CSRF_HEADER_NAME: token} if token else {}


# ---------------------------------------------------------------------------
# 1. Register valid user -> success
# ---------------------------------------------------------------------------


def test_register_valid_user_succeeds(client):
    response = _register(client)
    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "new-analyst"
    assert "id" in body and body["id"]
    assert "created_at" in body
    assert "password" not in body
    assert "password_hash" not in body


# ---------------------------------------------------------------------------
# 2. Register duplicate user -> rejected
# ---------------------------------------------------------------------------


def test_register_duplicate_username_returns_409(client):
    assert _register(client).status_code == 201
    response = _register(client, password="a-different-password-2")
    assert response.status_code == 409


# ---------------------------------------------------------------------------
# 3. Register invalid input -> rejected
# ---------------------------------------------------------------------------


def test_register_missing_fields_returns_422(client):
    assert client.post("/auth/register", json={"username": "someone"}).status_code == 422
    assert client.post("/auth/register", json={"password": "correct-horse-1"}).status_code == 422
    assert client.post("/auth/register", json={}).status_code == 422


@pytest.mark.parametrize(
    "username,password",
    [
        ("ab", "correct-horse-1"),  # username too short
        ("has a space", "correct-horse-1"),  # invalid characters
        ("valid-user", "short1"),  # password too short
        ("valid-user-2", "alllettersnodigits"),  # password missing a digit
        ("valid-user-3", "12345678"),  # password missing a letter
    ],
)
def test_register_invalid_input_returns_422(client, username, password):
    response = client.post("/auth/register", json={"username": username, "password": password})
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 4. Password is hashed and never stored plaintext
# ---------------------------------------------------------------------------


def test_password_is_hashed_and_never_stored_plaintext(client):
    password = "correct-horse-1"
    response = _register(client, password=password)
    assert password not in response.text

    with session_scope() as db:
        user = db.query(User).filter_by(username="new-analyst").one()
        assert user.password_hash != password
        assert password not in user.password_hash
        # argon2's encoded hash format, confirming a real KDF ran (not a placeholder).
        assert user.password_hash.startswith("$argon2id$")


# ---------------------------------------------------------------------------
# 5-7. Login: correct credentials, wrong password, unknown user
# ---------------------------------------------------------------------------


def test_login_with_registered_user_succeeds(client):
    _register(client)
    response = _login(client)
    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["username"] == "new-analyst"
    assert body["user_id"] and body["user_id"] != "demo"


def test_login_with_incorrect_password_returns_401(client):
    _register(client)
    response = _login(client, password="the-wrong-password-9")
    assert response.status_code == 401


def test_login_with_unknown_user_returns_401(client):
    response = _login(client, username="nobody-registered", password="whatever-password-1")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 8-9. Protected endpoint without / with authentication
# ---------------------------------------------------------------------------


def test_protected_endpoint_without_authentication_rejected(client):
    response = client.post("/classify", json=VALID_CLASSIFY_PAYLOAD)
    assert response.status_code == 401


def test_protected_endpoint_with_registered_user_session_allowed(client):
    _register(client)
    _login(client)
    response = client.post("/classify", json=VALID_CLASSIFY_PAYLOAD, headers=_csrf_header(client))
    assert response.status_code == 200
    assert response.json()["prediction"] in ("BENIGN", "DDoS")


# ---------------------------------------------------------------------------
# 10. Invalid/tampered session token -> rejected
# ---------------------------------------------------------------------------


def test_tampered_session_cookie_returns_401(client):
    _register(client)
    _login(client)
    client.cookies.set("cyber_ai_session", "not-a-real-session-token")
    response = client.post("/classify", json=VALID_CLASSIFY_PAYLOAD, headers=_csrf_header(client))
    assert response.status_code == 401


def test_expired_session_returns_401(client, monkeypatch):
    import backend.sessions as sessions_module

    _register(client)
    _login(client)

    # Force every existing session to already be expired, rather than sleeping in a
    # test -- same technique this file uses nowhere else needed, since
    # test_session_auth.py's TTL is otherwise never exercised directly.
    for session in sessions_module._sessions.values():
        session.expires_at = 0.0

    response = client.get("/ml/feature-importance")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 11. Demo/bootstrap authentication still works alongside registered users
# ---------------------------------------------------------------------------


def test_demo_login_survives_a_database_outage(client, monkeypatch):
    """The demo/bootstrap path (README "Docker Backend" -- `docker run` without the
    `db` service) must keep working even if the database itself is unreachable."""
    from sqlalchemy.exc import OperationalError

    import backend.services.auth as auth_module

    monkeypatch.setenv("CYBER_AI_USERNAME", "demo-operator")
    monkeypatch.setenv("CYBER_AI_PASSWORD", "demo-password-only-for-tests")

    def _raise(*args, **kwargs):
        raise OperationalError("statement", {}, Exception("unable to open database file"))

    monkeypatch.setattr(auth_module.users_service, "authenticate", _raise)

    response = _login(client, username="demo-operator", password="demo-password-only-for-tests")
    assert response.status_code == 200
    assert response.json()["user_id"] == "demo"


def test_demo_login_still_works_alongside_registered_users(client, monkeypatch):
    monkeypatch.setenv("CYBER_AI_USERNAME", "demo-operator")
    monkeypatch.setenv("CYBER_AI_PASSWORD", "demo-password-only-for-tests")

    _register(client, username="a-real-registered-user")

    demo_response = _login(client, username="demo-operator", password="demo-password-only-for-tests")
    assert demo_response.status_code == 200
    assert demo_response.json()["user_id"] == "demo"


# ---------------------------------------------------------------------------
# Safety properties
# ---------------------------------------------------------------------------


def test_registration_credentials_never_appear_in_logs(client, caplog):
    with caplog.at_level(logging.DEBUG):
        _register(client, password="correct-horse-1")

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "correct-horse-1" not in log_text
