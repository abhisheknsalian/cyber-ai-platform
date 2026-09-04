"""Cross-cutting ASGI middleware: request/correlation IDs + access logging, and
security response headers. Neither middleware participates in authentication -- the
request ID is a correlation aid only, never a credential (see require_auth() in
backend/security.py, which is untouched by this module).

Phase 15 (observability): the request-completion/failure log lines below now also
include `user_id`/`auth_method` when backend/security.py's require_auth() or
require_user_id() dependency populated them on `request.state` earlier in the same
request (dependencies run before the route body, which runs inside call_next() --
by the time this middleware logs after call_next() returns, those fields are already
set for any authenticated request). Public/unauthenticated endpoints simply never
have them, so they're included only when present rather than as an explicit null,
keeping those log lines exactly as before. This also feeds backend/metrics.py's
`http_requests_total` / `http_request` duration metric, in the same place the access
log line is already built, so the two never drift apart.
"""

from __future__ import annotations

import logging
import re
import secrets
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from backend import metrics
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


def _add_identity(extra: dict, request: Request) -> None:
    """Adds user_id/auth_method to a log `extra` dict when backend/security.py's
    require_auth()/require_user_id() dependency already resolved them for this
    request (set on request.state, never read back into the auth decision itself --
    see this module's docstring). Omitted entirely for public/unauthenticated
    requests rather than logged as null, so an anonymous GET /health line looks
    exactly as it did before this field existed."""
    user_id = getattr(request.state, "user_id", None)
    auth_method = getattr(request.state, "auth_method", None)
    if user_id is not None:
        extra["user_id"] = user_id
    if auth_method is not None:
        extra["auth_method"] = auth_method


# GET /health and GET /ready are polled on a fixed interval by the frontend
# (frontend/src/hooks/useHealth.ts, useReadiness.ts) purely to drive the sidebar's
# system-status indicator -- not user-initiated, and not part of any investigation
# pipeline this phase needs to trace. A busier production deployment might reasonably
# suppress their access-log lines (or drop them to DEBUG) to cut noise. This project
# deliberately does NOT do that: tests/test_request_id.py::test_request_id_appears_in_logs
# already asserts that *every* request -- specifically GET /health, the simplest
# possible case -- produces a request-correlated log line, and at this project's
# traffic volume (a local/demo deployment) the noise is negligible. Revisit this if
# real production log volume ever makes it worth the tradeoff.


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
                extra = {
                    "event": "request_failed",
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                }
                _add_identity(extra, request)
                logger.exception("request failed with an unhandled exception", extra=extra)
                metrics.increment("http_requests_total", method=request.method, path=request.url.path, status="500")
                metrics.observe_duration_ms(
                    "http_request", duration_ms, method=request.method, path=request.url.path
                )
                raise

            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            response.headers[REQUEST_ID_HEADER] = request_id
            extra = {
                "event": "request_completed",
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            }
            _add_identity(extra, request)
            logger.info("request completed", extra=extra)
            metrics.increment(
                "http_requests_total",
                method=request.method,
                path=request.url.path,
                status=str(response.status_code),
            )
            metrics.observe_duration_ms(
                "http_request", duration_ms, method=request.method, path=request.url.path
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
