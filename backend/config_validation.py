"""Startup configuration validation.

RAG_TOP_K/RAG_SCORE_THRESHOLD/OLLAMA_MODEL/etc. are already parsed (and already fail
fast on a malformed value, just with a raw Python traceback) at import time in
backend/rag/config.py and backend/ml/config.py -- those modules are unchanged here.
This module adds the validation that was genuinely missing: the *new* rate-limit
settings introduced this phase, and CORS_ORIGINS, which is security-relevant (used
with allow_credentials=True) but was never explicitly validated beyond "split on
commas". It never prints a secret's value -- only whether one is set.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("backend.config")


class ConfigurationError(RuntimeError):
    """Raised when a non-secret setting is present but malformed. Deliberately
    distinct from a missing secret (CYBER_AI_API_KEY etc.), which is allowed to be
    absent in local dev -- see validate_startup_config()."""


def _check_cors_origins() -> None:
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173")
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    if not origins:
        raise ConfigurationError(
            "CORS_ORIGINS is set but contains no usable origins. "
            "Provide a comma-separated list of allowed origins, e.g. http://localhost:5173."
        )
    if "*" in origins:
        # A wildcard is rejected outright: backend/main.py pairs allow_origins with
        # allow_credentials=True, and browsers refuse (and the spec forbids) combining
        # a wildcard origin with credentialed requests -- so this is never a usable
        # configuration, only ever a misconfiguration.
        raise ConfigurationError(
            "CORS_ORIGINS must not contain '*' -- allow_credentials=True requires an "
            "explicit origin allowlist. List the exact origin(s) instead, e.g. "
            "http://localhost:5173,http://localhost:8080."
        )
    for origin in origins:
        if not (origin.startswith("http://") or origin.startswith("https://")):
            raise ConfigurationError(
                f"CORS_ORIGINS entry {origin!r} is not a valid http(s) origin."
            )


def _check_rate_limit_settings() -> None:
    # Importing here (not at module top) avoids a circular import: rate_limit.py
    # already validates and logs a warning + falls back to a safe default for any
    # individually malformed value, so this is a second, stricter pass that fails
    # startup outright if the *limiter objects themselves* ended up non-positive --
    # which should be unreachable given rate_limit.py's own guards, but is cheap
    # insurance against a future change to that module silently accepting a bad value.
    from backend.rate_limit import AI_RATE_LIMIT, LOGIN_RATE_LIMIT

    for name, limiter in (("login", LOGIN_RATE_LIMIT), ("AI pipeline", AI_RATE_LIMIT)):
        if limiter.limit <= 0 or limiter.window_seconds <= 0:
            raise ConfigurationError(
                f"The {name} rate limiter has a non-positive limit or window, which "
                "would reject every request. Check RATE_LIMIT_* environment variables."
            )


def validate_startup_config() -> None:
    """Called once from the FastAPI lifespan, before the app starts serving.

    Fails fast (raises ConfigurationError) for malformed *non-secret* settings.
    Missing secrets (CYBER_AI_API_KEY, CYBER_AI_USERNAME/PASSWORD) are intentionally
    NOT fatal here -- backend/main.py's lifespan() already warns about those, and
    local development without them configured yet must keep working (public
    endpoints like /health, /threats, /auth/me function fine either way).
    """
    _check_cors_origins()
    _check_rate_limit_settings()
    logger.info("Startup configuration validated", extra={"event": "config_validated"})
