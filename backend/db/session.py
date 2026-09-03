"""Engine/session factory, driven by DATABASE_URL (read fresh from the environment
inside get_engine() -- not at import time -- so tests can point it at an isolated
temp database before backend.db is ever imported, the same pattern conftest.py
already uses for CHROMA_PERSIST_DIR/DDOS_DATASET_PATH).

Defaults to a local SQLite file (./data/cyber_ai.db) so non-Docker local dev and
`uv run pytest` need no external database -- see README "Database Architecture".
docker-compose.yml/docker-compose.prod.yml both set DATABASE_URL to the dedicated
`db` (Postgres) service instead.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

_DEFAULT_SQLITE_URL = "sqlite:///./data/cyber_ai.db"

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def database_url() -> str:
    return os.getenv("DATABASE_URL", _DEFAULT_SQLITE_URL)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        url = database_url()
        # SQLite's default same-thread check would reject use from FastAPI's worker
        # thread pool (sync `def` routes run off the event loop thread); harmless for
        # Postgres, where this arg isn't accepted, hence the conditional.
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, connect_args=connect_args, pool_pre_ping=True, future=True)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False, future=True)
    return _session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session: commits on clean exit, rolls back and re-raises on any
    exception. backend/services/users.py is the only current caller."""
    db = get_session_factory()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
