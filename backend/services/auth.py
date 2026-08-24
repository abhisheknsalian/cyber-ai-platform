"""Login credential validation for browser-based session authentication.

Credentials are read from CYBER_AI_USERNAME / CYBER_AI_PASSWORD only -- never
hardcoded, logged, or returned in a response -- and compared with hmac.compare_digest
(constant-time), read fresh per request for the same reason backend/security.py reads
CYBER_AI_API_KEY fresh: it's a secret, not a cacheable config value.
"""

import hmac
import os

from backend.sessions import create_session, destroy_session


class InvalidCredentialsError(ValueError):
    """Raised for any bad login attempt. Never says which field was wrong."""


def login(username: str, password: str) -> tuple[str, str]:
    """Validate credentials and return (session_token, csrf_token) on success."""
    configured_username = os.getenv("CYBER_AI_USERNAME")
    configured_password = os.getenv("CYBER_AI_PASSWORD")

    # Both comparisons always run (no short-circuit `if`/`elif` between them) so a
    # correct username with a wrong password takes the same time as a wrong username
    # -- otherwise the response time itself would leak which field was correct.
    username_ok = bool(configured_username) and hmac.compare_digest(username, configured_username)
    password_ok = bool(configured_password) and hmac.compare_digest(password, configured_password)

    if not (username_ok and password_ok):
        raise InvalidCredentialsError("Invalid username or password.")

    return create_session()


def logout(session_token: str | None) -> None:
    destroy_session(session_token)
