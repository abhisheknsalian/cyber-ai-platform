"""Cross-cutting ASGI middleware: request/correlation IDs + access logging, and
security response headers. Neither middleware participates in authentication -- the
request ID is a correlation aid only, never a credential (see require_auth() in
backend/security.py, which is untouched by this module).
"""

from __future__ import annotations

import logging
import re
import secrets
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from backend.logging_config import reset_request_id, set_request_id

logger = logging.getLogger("backend.request")

REQUEST_ID_HEADER = "X-Request-ID"

# Generated IDs use this same charset, so a sanity check on an incoming client-supplied
# ID also bounds it to something safe to place in headers/logs (no newlines, no
# control characters, no absurd length -- a client could otherwise use this header to
# inject fake log lines or bloat log storage).
_MAX_REQUEST_ID_LENGTH = 128
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]+$")


def _sanitize_incoming_request_id(raw: str | None) -> str | None:
    if not raw:
        return None
    if len(raw) > _MAX_REQUEST_ID_LENGTH:
        return None
    if not _VALID_REQUEST_ID.match(raw):
        return None
    return raw


def generate_request_id() -> str:
    return secrets.token_urlsafe(16)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns every request a correlation ID (accepting a caller-supplied
    X-Request-ID if it looks reasonable, otherwise generating one), exposes it via
    request.state.request_id and the X-Request-ID response header, and logs a
    single-line "request completed" event with method/path/status/duration_ms.

    This ID is never validated as -- or accepted in place of -- an API key or session
    cookie; backend/security.py's require_auth() does not read it.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = _sanitize_incoming_request_id(request.headers.get(REQUEST_ID_HEADER))
        request_id = incoming or generate_request_id()
        request.state.request_id = request_id
        token = set_request_id(request_id)

        start = time.perf_counter()
        logger.info(
            "request received",
            extra={"event": "request_received", "method": request.method, "path": request.url.path},
        )
        try:
            try:
                response = await call_next(request)
            except Exception:
                duration_ms = round((time.perf_counter() - start) * 1000, 2)
                logger.exception(
                    "request failed with an unhandled exception",
                    extra={
                        "event": "request_failed",
                        "method": request.method,
                        "path": request.url.path,
                        "duration_ms": duration_ms,
                    },
                )
                raise

            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            response.headers[REQUEST_ID_HEADER] = request_id
            logger.info(
                "request completed",
                extra={
                    "event": "request_completed",
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": response.status_code,
                    "duration_ms": duration_ms,
                },
            )
            return response
        finally:
            # Reset only after every log call above so they all see the real ID --
            # resetting first (before logging "request completed") would make that
            # log line's own request_id show "-" instead of the ID it's reporting on.
            reset_request_id(token)


# Applied to every response. A pure JSON API never needs to render markup itself, so
# a strict default-deny CSP is safe here -- except for FastAPI's own auto-generated
# docs (/docs, /redoc), which load Swagger/ReDoc's JS+CSS from a CDN and would be
# broken by it; those paths are deliberately excluded rather than disabling the CSP
# for everything.
_DOCS_PATHS = {"/docs", "/redoc", "/openapi.json"}
_STRICT_CSP = "default-src 'none'; frame-ancestors 'none'"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds standard defensive headers to every response. Does not touch CORS (that
    remains CORSMiddleware's job, configured in backend/main.py) and does not change
    any response body or status code."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        if request.url.path not in _DOCS_PATHS:
            response.headers["Content-Security-Policy"] = _STRICT_CSP

        # Auth responses carry session-adjacent state and must never be cached by an
        # intermediary or the browser's back/forward cache.
        if request.url.path.startswith("/auth/"):
            response.headers["Cache-Control"] = "no-store"

        return response
