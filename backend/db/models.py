"""ORM models: users (Phase 13) and investigations/classification_results/
analysis_results (Phase 14 -- persistent, per-user Network Detection history; see
README "Database Architecture" and backend/services/investigations.py).

JSON columns use SQLAlchemy's generic `JSON` type deliberately, not
`postgresql.JSONB` -- this project runs on both SQLite (local dev/tests, see
backend/db/session.py) and PostgreSQL (Docker), and the generic type maps to real
JSONB on Postgres while still working on SQLite. See ClassificationRecord/
AnalysisRecord below.
"""

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.db.base import Base


class User(Base):
    """A registered account. Never holds a plaintext password -- only the argon2id
    hash produced by backend/services/users.py. Kept deliberately minimal (no roles,
    no profile fields) -- nothing here is used by any endpoint yet beyond identity."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class Investigation(Base):
    """One Network Detection session, owned by exactly one registered user. Can hold
    several ClassificationRecords (the user re-classifying an edited/new sample within
    the same session) -- see backend/services/investigations.py.

    `latest_classification_id` is a denormalized pointer to the newest
    ClassificationRecord, kept in sync by backend/services/investigations.py inside the
    same transaction as every insert -- lets GET /investigations render a per-row
    summary (prediction/severity) in one query instead of a correlated subquery or
    window function per row. This creates a circular FK with `classification_results`
    (which itself points back to `investigations.id`); `use_alter=True` tells
    SQLAlchemy to resolve that via a deferred ALTER-TABLE-style constraint rather than
    raising a CircularDependencyError when sorting table creation order -- see
    alembic/versions/0002_create_investigation_tables.py for the equivalent migration-
    time handling (verified empirically to work identically on SQLite and PostgreSQL).
    """

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    latest_classification_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "classification_results.id",
            ondelete="SET NULL",
            use_alter=True,
            name="fk_investigations_latest_classification_id",
        ),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    classification_results: Mapped[list["ClassificationRecord"]] = relationship(
        back_populates="investigation",
        foreign_keys="ClassificationRecord.investigation_id",
        cascade="all, delete-orphan",
        order_by="ClassificationRecord.created_at",
    )
    # Read-only convenience for GET /investigations' summary list (backend/services/
    # investigations.py) -- lazy="joined" so listing N investigations stays one query
    # (a LEFT JOIN) instead of N+1. viewonly=True: this relationship never writes;
    # `latest_classification_id` is set directly as a plain column assignment
    # alongside inserting a new ClassificationRecord.
    latest_classification: Mapped["ClassificationRecord | None"] = relationship(
        foreign_keys=[latest_classification_id],
        viewonly=True,
        lazy="joined",
    )


class ClassificationRecord(Base):
    """One persisted POST /classify result. `features` is the raw NetworkTrafficFeatures
    payload (78 CICFlowMeter fields, backend/ml/schemas.py) stored as JSON rather than
    one column per feature -- that schema is generated from FEATURE_COLUMNS
    (backend/ml/config.py) and can change without a matching migration this way. This
    table never re-runs the classifier -- see backend/services/investigations.py and
    the "no persistence inside /classify" boundary documented in README
    "Authentication" / "Database Architecture".
    """

    __tablename__ = "classification_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    features: Mapped[dict] = mapped_column(JSON, nullable=False)
    prediction: Mapped[str] = mapped_column(String(32), nullable=False)
    classification: Mapped[str] = mapped_column(String(16), nullable=False)
    probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    class_probabilities: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    investigation: Mapped["Investigation"] = relationship(
        back_populates="classification_results", foreign_keys=[investigation_id]
    )
    analysis_result: Mapped["AnalysisRecord | None"] = relationship(
        back_populates="classification_result", cascade="all, delete-orphan", uselist=False
    )


class AnalysisRecord(Base):
    """One persisted POST /analyze/classification result -- the ThreatAnalysis +
    HybridEvidence bundle for exactly one ClassificationRecord. `classification_result_id`
    is UNIQUE, enforcing the 1:0..1 relationship (BENIGN classifications legitimately
    have no row here at all -- see backend/services/classification.py, which already
    returns `analysis=None` for BENIGN). Never re-runs RAG/graph retrieval/the LLM.
    """

    __tablename__ = "analysis_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    classification_result_id: Mapped[int] = mapped_column(
        ForeignKey("classification_results.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    threat: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    attack_vectors: Mapped[list | None] = mapped_column(JSON, nullable=True)
    mitre_attack: Mapped[list | None] = mapped_column(JSON, nullable=True)
    indicators: Mapped[list | None] = mapped_column(JSON, nullable=True)
    mitigations: Mapped[list | None] = mapped_column(JSON, nullable=True)
    sources: Mapped[list | None] = mapped_column(JSON, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    classification_result: Mapped["ClassificationRecord"] = relationship(back_populates="analysis_result")
