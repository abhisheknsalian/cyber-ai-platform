"""Persistent, per-user Network Detection history (Phase 14): a registered user can
save a POST /classify result (and, optionally, its POST /analyze/classification
follow-up) to PostgreSQL/SQLite and revisit it later. Deliberately separate from the
existing inference endpoints -- see backend/services/investigations.py's module
docstring for why persistence is never invoked from inside /classify or
/analyze/classification.
"""
