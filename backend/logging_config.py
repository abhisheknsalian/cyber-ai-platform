"""Structured logging setup, stdlib-only (no external dependency).

Every log record is emitted as a single JSON line: timestamp, level, logger name,
message, and a "-" request_id when no request is in flight (startup/shutdown), or the
current request's ID when one is (see backend/middleware.py). Call-sites that want
extra structured fields (duration_ms, prediction, etc.) pass them via the stdlib
logging `extra=` kwarg; this module renders whatever is present without requiring
every call-site to agree on a fixed schema.

Hard rule enforced by convention (not code): never pass a secret (API key, password,
session token, CSRF token, Authorization header value) as a message or extra field.
See tests/test_logging.py and the pre-existing tests/test_session_auth.py checks.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys

_REQUEST_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)

# LogRecord attributes that already exist on every record (stdlib) -- anything else
# passed via extra= is "additional" structured context worth including in the output.
_STANDARD_RECORD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
}


def get_request_id() -> str | None:
    return _REQUEST_ID.get()


def set_request_id(request_id: str | None) -> contextvars.Token:
    return _REQUEST_ID.set(request_id)


def reset_request_id(token: contextvars.Token) -> None:
    _REQUEST_ID.reset(token)


class _RequestIdFilter(logging.Filter):
    """Attaches the current request ID (or "-") to every record, so the formatter can
    always reference record.request_id uniformly, including for logs emitted outside
    any request (e.g. application startup)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = get_request_id() or "-"
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Deliberately does not use %-style templates so
    call-sites can pass free-form extra= fields without a fixed schema."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", "-"),
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_RECORD_ATTRS and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    """Replaces the ad hoc logging.basicConfig(...) call from earlier phases with a
    single structured handler on the root logger. Idempotent -- safe to call more
    than once (e.g. once per test session)."""
    root = logging.getLogger()
    root.setLevel(level)

    for existing in list(root.handlers):
        root.removeHandler(existing)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(_RequestIdFilter())
    root.addHandler(handler)
