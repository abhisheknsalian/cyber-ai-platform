"""Lightweight in-memory rate limiting.

LIMITATION (documented per Phase 8 requirements, see README "Rate Limiting"): this
state lives in this single process's memory. It is correct for the current
docker-compose.yml architecture (one backend container, uvicorn run without
--workers, so exactly one process ever holds this dict) but is NOT a distributed
solution -- running multiple backend replicas or worker processes would give each its
own independent counters. Redis or another shared store would be needed for that, and
Phase 8 does not introduce one (no demonstrated requirement yet).

Keyed by client IP only, never by username/API key -- rate-limiting POST /auth/login
by the *attempted username* would let an attacker distinguish "this username exists
and is now throttled" from "this username doesn't exist and isn't," which is exactly
the enumeration side-channel the generic "Invalid username or password" error is
already designed to avoid (see backend/services/auth.py).
"""

from __future__ import annotations

import logging
import os
import threading
import time

from fastapi import HTTPException, Request

logger = logging.getLogger("backend.rate_limit")


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r (must be an integer); using default %d", name, raw, default)
        return default
    if value <= 0:
        logger.warning("Invalid %s=%r (must be positive); using default %d", name, raw, default)
        return default
    return value


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("Invalid %s=%r (must be a number); using default %s", name, raw, default)
        return default
    if value <= 0:
        logger.warning("Invalid %s=%r (must be positive); using default %s", name, raw, default)
        return default
    return value


class RateLimiter:
    """Sliding-window request limiter: at most `limit` calls to check() per key in
    any trailing `window_seconds` window. Thread-safe -- FastAPI runs sync `def`
    route handlers in a thread pool, so concurrent requests can call check()
    simultaneously even with uvicorn's default single worker process."""

    def __init__(self, limit: int, window_seconds: float):
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, float]:
        """Returns (allowed, retry_after_seconds). Records the call as a hit only
        when it's allowed, so a client stuck at the limit doesn't get an
        ever-receding window."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t > cutoff]
            if len(hits) >= self.limit:
                self._hits[key] = hits
                retry_after = max(hits[0] + self.window_seconds - now, 0.0)
                return False, retry_after
            hits.append(now)
            self._hits[key] = hits
            return True, 0.0

    def reset(self) -> None:
        """Test-only: clears all recorded state."""
        with self._lock:
            self._hits.clear()


LOGIN_RATE_LIMIT = RateLimiter(
    limit=_int_env("RATE_LIMIT_LOGIN_MAX", 5),
    window_seconds=_float_env("RATE_LIMIT_LOGIN_WINDOW_SECONDS", 60.0),
)

# Shared across /analyze, /classify, /analyze/classification: all three are
# "expensive" AI-pipeline calls (LLM invocation and/or model inference) from the same
# authenticated caller's perspective, so one limiter/budget is proportional -- three
# separate limiters would just let a caller multiply their effective quota by hitting
# a different endpoint each time.
AI_RATE_LIMIT = RateLimiter(
    limit=_int_env("RATE_LIMIT_AI_MAX", 20),
    window_seconds=_float_env("RATE_LIMIT_AI_WINDOW_SECONDS", 60.0),
)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _enforce(limiter: RateLimiter, request: Request, *, event: str, detail: str) -> None:
    allowed, retry_after = limiter.check(_client_key(request))
    if allowed:
        return
    retry_after_seconds = max(int(retry_after) + 1, 1)
    logger.warning(
        "rate limit exceeded",
        extra={"event": event, "path": request.url.path, "retry_after": retry_after_seconds},
    )
    raise HTTPException(
        status_code=429,
        detail=detail,
        headers={"Retry-After": str(retry_after_seconds)},
    )


def enforce_login_rate_limit(request: Request) -> None:
    _enforce(
        LOGIN_RATE_LIMIT,
        request,
        event="login_rate_limited",
        detail="Too many login attempts. Please try again later.",
    )


def enforce_ai_rate_limit(request: Request) -> None:
    _enforce(
        AI_RATE_LIMIT,
        request,
        event="ai_rate_limited",
        detail="Too many requests. Please try again later.",
    )
