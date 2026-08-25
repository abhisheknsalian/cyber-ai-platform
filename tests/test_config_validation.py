"""Tests for the Phase 8 startup configuration validation (backend/config_validation.py).

Missing *secrets* (CYBER_AI_API_KEY, CYBER_AI_USERNAME/PASSWORD) are intentionally NOT
covered here as fatal cases -- they're allowed to be absent at startup (see
backend/main.py's lifespan(), unchanged from earlier phases) so local development
keeps working. This file covers the genuinely new validation: CORS_ORIGINS and the
rate-limit environment variables.
"""

import pytest

from backend.config_validation import ConfigurationError, validate_startup_config
from backend.rate_limit import RateLimiter, _float_env, _int_env


def test_valid_default_configuration_passes(monkeypatch):
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    validate_startup_config()  # must not raise


def test_valid_explicit_cors_origins_passes(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8080")
    validate_startup_config()  # must not raise


def test_wildcard_cors_origin_is_rejected(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "*")
    with pytest.raises(ConfigurationError):
        validate_startup_config()


def test_wildcard_mixed_with_a_real_origin_is_still_rejected(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173,*")
    with pytest.raises(ConfigurationError):
        validate_startup_config()


def test_empty_cors_origins_is_rejected(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "   ,  ,")
    with pytest.raises(ConfigurationError):
        validate_startup_config()


def test_non_url_cors_origin_is_rejected(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "not-a-url")
    with pytest.raises(ConfigurationError):
        validate_startup_config()


# --- Phase 12: placeholder-credential detection (warns, never fails startup) -------


def test_placeholder_api_key_does_not_raise(monkeypatch):
    monkeypatch.setenv("CYBER_AI_API_KEY", "changeme-generate-a-long-random-value")
    validate_startup_config()  # must not raise -- a warning, not a startup failure


def test_placeholder_username_and_password_logs_a_warning(monkeypatch, caplog):
    monkeypatch.setenv("CYBER_AI_USERNAME", "changeme")
    monkeypatch.setenv("CYBER_AI_PASSWORD", "changeme-use-a-strong-password")
    with caplog.at_level("WARNING", logger="backend.config"):
        validate_startup_config()
    messages = [record.message for record in caplog.records]
    assert any("CYBER_AI_USERNAME" in m and "placeholder" in m for m in messages)
    assert any("CYBER_AI_PASSWORD" in m and "placeholder" in m for m in messages)


def test_a_real_looking_credential_does_not_trigger_the_placeholder_warning(monkeypatch, caplog):
    monkeypatch.setenv("CYBER_AI_API_KEY", "a-genuinely-random-64-char-value-not-the-placeholder")
    with caplog.at_level("WARNING", logger="backend.config"):
        validate_startup_config()
    assert not any("placeholder" in record.message for record in caplog.records)


def test_configuration_error_never_includes_a_secret_value(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "*")
    monkeypatch.setenv("CYBER_AI_API_KEY", "super-secret-value-should-never-appear")
    try:
        validate_startup_config()
    except ConfigurationError as exc:
        assert "super-secret-value-should-never-appear" not in str(exc)
    else:
        pytest.fail("expected ConfigurationError")


# --- rate_limit.py's own env-var parsing: malformed values fail safely (fall back to
# a safe default with a logged warning) rather than crashing the process. ------------


def test_int_env_falls_back_to_default_on_malformed_value(monkeypatch):
    monkeypatch.setenv("SOME_LIMIT", "not-a-number")
    assert _int_env("SOME_LIMIT", 42) == 42


def test_int_env_falls_back_to_default_on_non_positive_value(monkeypatch):
    monkeypatch.setenv("SOME_LIMIT", "-5")
    assert _int_env("SOME_LIMIT", 42) == 42


def test_int_env_uses_valid_configured_value(monkeypatch):
    monkeypatch.setenv("SOME_LIMIT", "7")
    assert _int_env("SOME_LIMIT", 42) == 7


def test_float_env_falls_back_to_default_on_malformed_value(monkeypatch):
    monkeypatch.setenv("SOME_WINDOW", "not-a-number")
    assert _float_env("SOME_WINDOW", 60.0) == 60.0


def test_missing_env_var_uses_default(monkeypatch):
    monkeypatch.delenv("SOME_LIMIT", raising=False)
    assert _int_env("SOME_LIMIT", 42) == 42


def test_rate_limiter_rejects_non_positive_construction_values_at_validation_time():
    # A directly-misconfigured limiter (bypassing the env-var guards) is exactly what
    # the second validation pass in config_validation.py exists to catch.
    from backend import rate_limit as rate_limit_module

    original = rate_limit_module.LOGIN_RATE_LIMIT
    rate_limit_module.LOGIN_RATE_LIMIT = RateLimiter(limit=0, window_seconds=60)
    try:
        with pytest.raises(ConfigurationError):
            validate_startup_config()
    finally:
        rate_limit_module.LOGIN_RATE_LIMIT = original
