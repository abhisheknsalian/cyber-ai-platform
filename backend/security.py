"""Lightweight API-key authentication for the application endpoints.

The key is read from the CYBER_AI_API_KEY environment variable only -- it is never
hardcoded, logged, or echoed back in a response/error. Deliberately read fresh on
every request (not cached at import time) rather than following the module-level
constant pattern used by backend/rag/config.py and backend/ml/config.py: this is a
secret, not a path/hyperparameter, so there is no benefit to caching it, and reading
it fresh means the dependency fails closed correctly if the variable is unset or
changes, without requiring a process restart or import-order tricks in tests.
"""

import hmac
import os

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# auto_error=False so we control the status code ourselves -- FastAPI's default
# HTTPBearer raises 403 on a missing/malformed header, but the spec here requires 401
# for every failure mode (missing, malformed, and invalid).
_bearer_scheme = HTTPBearer(auto_error=False)

_UNAUTHORIZED_DETAIL = "Missing or invalid API key."


def require_api_key(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer_scheme),
) -> None:
    """FastAPI dependency enforcing `Authorization: Bearer <CYBER_AI_API_KEY>`.

    Fails closed: if CYBER_AI_API_KEY isn't configured, every request to a protected
    endpoint is rejected (401) rather than silently allowed through.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=401,
            detail=_UNAUTHORIZED_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )

    configured_key = os.getenv("CYBER_AI_API_KEY")

    # hmac.compare_digest for constant-time comparison -- a plain `==` would leak
    # timing information about how many leading characters of the key are correct.
    if not configured_key or not hmac.compare_digest(credentials.credentials, configured_key):
        raise HTTPException(
            status_code=401,
            detail=_UNAUTHORIZED_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )
