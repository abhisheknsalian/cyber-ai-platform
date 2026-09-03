"""Persistent relational storage for user accounts (Phase 13).

Everything before this phase used file-based or in-memory persistence (Chroma for
vectors, joblib for the classifier, an in-memory dict for sessions -- see
backend/sessions.py). Real user accounts need a relational store, so this package
adds a small SQLAlchemy 2.x layer: backend/db/base.py (the declarative Base),
backend/db/models.py (the User ORM model), backend/db/session.py (engine/session
factory, driven entirely by DATABASE_URL).

Schema changes go through Alembic (see alembic/ at the repo root), not
Base.metadata.create_all() at application startup -- see alembic/env.py and the
README "Database Architecture" section for why, and for how local dev, tests, and
Docker each provision the schema.
"""
