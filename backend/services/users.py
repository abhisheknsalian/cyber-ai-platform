"""Persistent user accounts: registration and credential verification.

Passwords are hashed with argon2-cffi's PasswordHasher, which uses the Argon2id
variant by default (OWASP's current recommendation) -- never stored, logged, or
returned in plaintext anywhere. Verification always runs a real argon2 check, even
for a username that doesn't exist (against a precomputed dummy hash), so that a
nonexistent username takes ~the same time as a wrong password for one that does --
the same timing-side-channel concern backend/services/auth.py already documents for
the demo-credential path, applied here to the DB-backed path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from backend.db.models import User
from backend.db.session import session_scope

_hasher = PasswordHasher()

# A precomputed hash of a value nobody will ever type, used only to give a "no such
# user" lookup the same argon2-verification cost as a real wrong-password check.
_DUMMY_HASH = _hasher.hash("cyber-ai-platform-dummy-hash-for-timing-parity")

# Username OR email-shaped: letters/digits/._-+ plus @ for email-style handles.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._+-]{3,64}$|^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$")
_HAS_LETTER_RE = re.compile(r"[A-Za-z]")
_HAS_DIGIT_RE = re.compile(r"\d")


class InvalidRegistrationError(ValueError):
    """Raised for input that fails validation (bad username shape, weak password)."""


class UsernameTakenError(ValueError):
    """Raised when the username/email is already registered."""


@dataclass(frozen=True)
class UserPublic:
    """Safe-to-return user data -- never includes password_hash."""

    id: str
    username: str
    created_at: datetime


def _validate_username(username: str) -> str:
    username = username.strip()
    if not _USERNAME_RE.match(username):
        raise InvalidRegistrationError(
            "Username must be 3-64 characters (letters, numbers, . _ - +) or a valid email address."
        )
    return username


def _validate_password(password: str) -> None:
    if len(password) < 8:
        raise InvalidRegistrationError("Password must be at least 8 characters long.")
    if len(password) > 256:
        # argon2 can hash arbitrary-length input, but an unbounded password is a cheap
        # way to inflate the cost of the hashing step itself -- capped like every
        # other request body field in this project (see backend/models/schemas.py).
        raise InvalidRegistrationError("Password must be 256 characters or fewer.")
    if not (_HAS_LETTER_RE.search(password) and _HAS_DIGIT_RE.search(password)):
        raise InvalidRegistrationError("Password must contain at least one letter and one number.")


def register(username: str, password: str) -> UserPublic:
    """Validate, hash, and persist a new user. Raises InvalidRegistrationError for
    malformed input or UsernameTakenError for a duplicate -- never lets an
    IntegrityError or any other storage detail leak past this function."""
    username = _validate_username(username)
    _validate_password(password)
    password_hash = _hasher.hash(password)

    with session_scope() as db:
        user = User(username=username, password_hash=password_hash)
        db.add(user)
        try:
            db.flush()
        except IntegrityError as exc:
            raise UsernameTakenError(f"Username {username!r} is already registered.") from exc
        db.refresh(user)
        return UserPublic(id=str(user.id), username=user.username, created_at=user.created_at)


def authenticate(username: str, password: str) -> UserPublic | None:
    """Returns the user on a correct, active-account login; None otherwise. Never
    raises for a bad login -- that's an expected outcome, not an error."""
    with session_scope() as db:
        user = db.scalar(select(User).where(User.username == username))
        # Read every attribute needed below while the session is still open -- `user`
        # becomes detached the moment this `with` block exits, and touching an
        # unloaded attribute on a detached instance raises DetachedInstanceError.
        hash_to_check = user.password_hash if user is not None else _DUMMY_HASH
        is_active = user.is_active if user is not None else False
        public = UserPublic(id=str(user.id), username=user.username, created_at=user.created_at) if user else None

    try:
        _hasher.verify(hash_to_check, password)
        password_ok = True
    except (VerifyMismatchError, InvalidHash):
        password_ok = False

    if not password_ok or public is None or not is_active:
        return None
    return public
