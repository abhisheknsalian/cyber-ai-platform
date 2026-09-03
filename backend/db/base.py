from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base. alembic/env.py imports this (plus backend.db.models,
    to register every table on it) so `target_metadata = Base.metadata` reflects the
    full schema for autogeneration/comparison."""
