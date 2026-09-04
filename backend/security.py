"""Authentication for the protected application endpoints.

Two independent credential paths, either of which satisfies require_auth():

  1. Direct API clients: `Authorization: Bearer <CYBER_AI_API_KEY>` (unchanged from
     Phase 5.1 -- read fresh from the environment, compared with hmac.compare_digest).
  2. Browsers: an HttpOnly session cookie set by POST /auth/login (backend/main.py,
     backend/sessions.py), plus a matching X-CSRF-Token header on state-changing
     requests (double-submit CSRF check -- see backend/sessions.py for why).

Neither path is ever logged, echoed in a response body, or exposed in the OpenAPI
schema. Fails closed: if neither credential is present and valid, every protected
endpoint returns 401.

Phase 14 adds require_user_id() below -- a deliberately NARROWER dependency for the
new persistent-investigation endpoints, which need a real users.id to own a foreign
key. It reuses _valid_session_request()'s exact session+CSRF check (not a second
implementation) but, unlike require_auth(), never accepts an API key and never
accepts the demo/bootstrap session -- see its docstring for why.

Phase 15 (observability): both dependencies below now also record the resolved
identity on `request.state` (`user_id`, `auth_method`) on the SUCCESS path only --
never on failure, since there's no identity to attach to a failed attempt anyway, and
doing so would risk logging a caller-supplied username/credential guess. This is pure
logging enrichment, not a new auth mechanism: nothing here changes what is or isn't
accepted as a credential, and backend/middleware.py (the only reader of these fields)
never uses them for anything but the request-completion log line.
"""

import hmac
import logging
import os

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.services.auth import DEMO_USER_ID
from backend.sessions import CSRF_HEADER_NAME, SESSION_COOKIE_NAME, csrf_token_for, is_valid_session, session_identity

logger = logging.getLogger("backend.auth")

# auto_error=False so we control the status code ourselves -- FastAPI's default
# HTTPBearer raises 403 on a missing/malformed header, but the spec here requires 401
# for every failure mode (missing, malformed, and invalid).
_bearer_scheme = HTTPBearer(auto_error=False)

_UNAUTHORIZED_DETAIL = "Authentication required."
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _valid_api_key(credentials: HTTPAuthorizationCredentials | None) -> bool:
    if credentials is None or not credentials.credentials:
        return False
    configured_key = os.getenv("CYBER_AI_API_KEY")
    # hmac.compare_digest for constant-time comparison -- a plain `==` would leak
    # timing information about how many leading characters of the key are correct.
    return bool(configured_key) and hmac.compare_digest(credentials.credentials, configured_key)


def _valid_session_request(request: Request) -> bool:
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not is_valid_session(session_token):
        return False
    if request.method.upper() in _SAFE_METHODS:
        return True
    # Double-submit CSRF check for state-changing requests authenticated by cookie.
    # API-key requests skip this entirely -- there's no ambient browser credential
    # involved, so there's nothing for a third-party site to forge.
    expected_csrf = csrf_token_for(session_token)
    provided_csrf = request.headers.get(CSRF_HEADER_NAME)
    return bool(expected_csrf) and bool(provided_csrf) and hmac.compare_digest(provided_csrf, expected_csrf)


def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer_scheme),
) -> None:
    """FastAPI dependency for the protected application endpoints.

    Accepts EITHER a valid API key (direct clients) OR a valid session + CSRF pair
    (browser). Fails closed to 401 if neither is present/valid -- including when
    CYBER_AI_API_KEY simply isn't configured, so a misconfigured deployment never
    accidentally runs open.
    """
    if _valid_api_key(credentials):
        request.state.auth_method = "api_key"
        logger.info("Authentication succeeded", extra={"event": "auth_success", "method": "api_key"})
        return
    if _valid_session_request(request):
        request.state.auth_method = "session"
        identity = session_identity(request.cookies.get(SESSION_COOKIE_NAME))
        if identity is not None:
            request.state.user_id = identity[0]
        logger.info("Authentication succeeded", extra={"event": "auth_success", "method": "session"})
        return
    logger.warning(
        "Authentication failed",
        extra={"event": "auth_failure", "path": request.url.path},
    )
    raise HTTPException(
        status_code=401,
        detail=_UNAUTHORIZED_DETAIL,
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_user_id(request: Request) -> int:
    """FastAPI dependency for endpoints that persist data owned by a real registered
    user (investigations -- see backend/services/investigations.py).

    Narrower than require_auth() by design, on two axes:

      - No API-key path at all. A bare API key (backend/services/auth.py's other
        credential path) has no associated row in `users` -- there is nothing for it
        to own, so it isn't even considered here, regardless of whether one is
        configured or supplied.
      - The demo/bootstrap session (backend/services/auth.py's DEMO_USER_ID
        sentinel, "demo") is explicitly rejected with 403. That session is never
        backed by a `users` row (Phase 13 deliberately never persists the demo
        credentials anywhere), so its identity cannot satisfy the `user_id` foreign
        key every investigation table carries -- inventing a database row for it
        would contradict that design instead of respecting it.

    Reuses _valid_session_request() -- the exact same session+CSRF check
    require_auth() already applies to its browser path -- so there is exactly one
    CSRF-verification code path in the codebase, not two that could drift apart.
    """
    if not _valid_session_request(request):
        raise HTTPException(
            status_code=401,
            detail=_UNAUTHORIZED_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )
    identity = session_identity(request.cookies.get(SESSION_COOKIE_NAME))
    if identity is None:
        # Defensive: _valid_session_request() just confirmed the session is active,
        # so this is unreachable in practice, but never assume identity exists.
        raise HTTPException(
            status_code=401,
            detail=_UNAUTHORIZED_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id, _username = identity
    if user_id == DEMO_USER_ID:
        logger.info(
            "Demo session rejected from persistent-investigation endpoint",
            extra={"event": "demo_investigation_rejected", "path": request.url.path},
        )
        raise HTTPException(
            status_code=403,
            detail="Demo sessions cannot save or view persistent investigations. Register an account to use this feature.",
        )
    request.state.user_id = user_id
    request.state.auth_method = "session"
    return int(user_id)
