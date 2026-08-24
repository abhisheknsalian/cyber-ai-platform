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
"""

import hmac
import logging
import os

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.sessions import CSRF_HEADER_NAME, SESSION_COOKIE_NAME, csrf_token_for, is_valid_session

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
        logger.info("Authentication succeeded", extra={"event": "auth_success", "method": "api_key"})
        return
    if _valid_session_request(request):
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
