"""In-memory server-side session store for browser cookie-based authentication.

Appropriate for this single-process local application (Phase 5.2 scope, per README
"Authentication"): sessions live only in this process's memory and are cleared on
restart. The session cookie only ever carries an opaque, cryptographically random
token -- no username, password, password hash, or the API key is ever encoded in it,
so nothing sensitive is exposed even if a cookie were somehow read.

A second, non-HttpOnly cookie carries a CSRF token tied to the same session (the
"double-submit cookie" pattern): the frontend echoes its value back in an
X-CSRF-Token header on state-changing requests, and require_auth() (backend/security.py)
verifies it matches. This is needed because the session cookie must use
SameSite=None (the frontend and backend run on different localhost ports, i.e.
different origins, so a stricter SameSite would simply never be sent) which removes
the browser's own cross-site request forgery mitigation.

Phase 13 (multi-user auth): a session now also carries which user it belongs to
(user_id, username) instead of being anonymous/singular. Deliberately still an
opaque random token backed by this in-memory store rather than a self-contained
token (e.g. JWT): that's what makes POST /auth/logout able to actually revoke a
session server-side (tests/test_session_auth.py::test_logout_destroys_session
depends on this) -- a stateless signed token can't be invalidated before its
expiry without a separate revocation list, which would just reintroduce the
server-side state this avoids. See README "Database Architecture" /
"Authentication" for the full tradeoff.
"""

import secrets
import time

SESSION_COOKIE_NAME = "cyber_ai_session"
CSRF_COOKIE_NAME = "cyber_ai_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
# Short-lived per Phase 13's authentication requirements (was 12h pre-Phase-13).
# There's no refresh-token flow in this scope -- a session simply expires and the
# user logs in again -- so this is a straight availability/security tradeoff, not
# tuned to a measured attack window.
SESSION_TTL_SECONDS = 60 * 60  # 1 hour


class _Session:
    __slots__ = ("user_id", "username", "csrf_token", "expires_at")

    def __init__(self, user_id: str, username: str, csrf_token: str, expires_at: float):
        self.user_id = user_id
        self.username = username
        self.csrf_token = csrf_token
        self.expires_at = expires_at


_sessions: dict[str, _Session] = {}


def create_session(user_id: str, username: str) -> tuple[str, str]:
    """Create a new session for the given user and return (session_token, csrf_token)."""
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    _sessions[session_token] = _Session(user_id, username, csrf_token, time.time() + SESSION_TTL_SECONDS)
    return session_token, csrf_token


def _get_active(session_token: str | None) -> _Session | None:
    if not session_token:
        return None
    session = _sessions.get(session_token)
    if session is None:
        return None
    if time.time() > session.expires_at:
        _sessions.pop(session_token, None)
        return None
    return session


def is_valid_session(session_token: str | None) -> bool:
    return _get_active(session_token) is not None


def csrf_token_for(session_token: str | None) -> str | None:
    session = _get_active(session_token)
    return session.csrf_token if session else None


def session_identity(session_token: str | None) -> tuple[str, str] | None:
    """Returns (user_id, username) for a valid session, else None. Used by
    GET /auth/me to report who's actually logged in."""
    session = _get_active(session_token)
    return (session.user_id, session.username) if session else None


def destroy_session(session_token: str | None) -> None:
    if session_token:
        _sessions.pop(session_token, None)
