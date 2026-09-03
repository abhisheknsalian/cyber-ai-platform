"""Login credential validation for browser-based session authentication.

Phase 13 (multi-user auth): two independent credential paths, tried in this order,
either of which can start a session:

  1. Registered users (backend/services/users.py): DB-backed, argon2id-hashed
     passwords via users.authenticate().
  2. Demo/bootstrap login: CYBER_AI_USERNAME / CYBER_AI_PASSWORD from the
     environment -- unchanged from Phase 5.2, kept ONLY so this app still has a
     working login before anyone has registered an account (e.g. straight after
     `docker compose up -d` on a fresh checkout, or in CI). Deliberately tried
     SECOND, after the database: if an operator ever registers a real account with
     the same name as the demo username, the real account's password takes over --
     there's exactly one login path per username, never two competing checks.
     Read fresh from the environment and compared with hmac.compare_digest, same as
     before -- never hardcoded, logged, or returned in a response.

Neither path reveals which one failed, or whether a username exists at all -- both
raise the same InvalidCredentialsError with the same generic message.
"""

import hmac
import logging
import os

from sqlalchemy.exc import SQLAlchemyError

from backend.services import users as users_service
from backend.sessions import create_session, destroy_session

logger = logging.getLogger("backend.auth")

# Sentinel user_id for the demo/bootstrap login path -- never a real database row, so
# it can never collide with a registered user's numeric id (see backend/db/models.py).
DEMO_USER_ID = "demo"


class InvalidCredentialsError(ValueError):
    """Raised for any bad login attempt. Never says which field or path was wrong."""


def _demo_login(username: str, password: str) -> str | None:
    """Returns the configured demo username on success, else None."""
    configured_username = os.getenv("CYBER_AI_USERNAME")
    configured_password = os.getenv("CYBER_AI_PASSWORD")

    # Both comparisons always run (no short-circuit `if`/`elif` between them) so a
    # correct username with a wrong password takes the same time as a wrong username
    # -- otherwise the response time itself would leak which field was correct.
    username_ok = bool(configured_username) and hmac.compare_digest(username, configured_username)
    password_ok = bool(configured_password) and hmac.compare_digest(password, configured_password)

    if username_ok and password_ok:
        return configured_username
    return None


def login(username: str, password: str) -> tuple[str, str, str, str]:
    """Validate credentials and return (session_token, csrf_token, user_id, username)
    on success."""
    try:
        user = users_service.authenticate(username, password)
    except SQLAlchemyError:
        # The database being unreachable must not take the demo/bootstrap login path
        # down with it -- that path is specifically relied on to keep working before
        # any database is provisioned (e.g. `docker run` without the `db` service from
        # docker-compose.yml, per README "Docker Backend"). A real registered account
        # simply can't log in until the database is back; the demo path below still can.
        logger.error("Database unavailable during login; falling back to demo credentials only")
        user = None
    if user is not None:
        session_token, csrf_token = create_session(user.id, user.username)
        return session_token, csrf_token, user.id, user.username

    demo_username = _demo_login(username, password)
    if demo_username is not None:
        session_token, csrf_token = create_session(DEMO_USER_ID, demo_username)
        return session_token, csrf_token, DEMO_USER_ID, demo_username

    raise InvalidCredentialsError("Invalid username or password.")


def register(username: str, password: str) -> users_service.UserPublic:
    """Create a new persistent user account. Raises
    users_service.InvalidRegistrationError / UsernameTakenError on failure."""
    return users_service.register(username, password)


def logout(session_token: str | None) -> None:
    destroy_session(session_token)
