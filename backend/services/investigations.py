"""Persistence for per-user investigations (Phase 14).

Deliberately never invokes the classifier, RAG, graph retrieval, or the LLM -- every
function here only stores/reads a result that POST /classify or
POST /analyze/classification already computed and returned to the caller. This keeps
those two inference endpoints independently usable (including by API-key clients,
which have no user identity for this layer to attach anything to -- see
backend/security.py::require_user_id) and means a persistence failure can never make
inference itself fail.

Every read and write is scoped to the owning user_id directly in the query (never
"fetch by id, then compare ownership in Python") -- see _owned_investigation() and
_owned_classification_result() below, which are the only two places a row is ever
looked up by id. A row that doesn't exist and a row that exists but belongs to a
different user are indistinguishable to every caller of this module: both come back
as None, and every route in backend/main.py turns that into the same 404.
"""

from __future__ import annotations

import logging
import time

from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from backend import metrics
from backend.db.models import AnalysisRecord, ClassificationRecord, Investigation
from backend.db.session import session_scope
from backend.investigations.schemas import (
    AnalysisResultCreateRequest,
    ClassificationResultCreateRequest,
    InvestigationCreateResponse,
    InvestigationDetail,
    InvestigationListResponse,
    InvestigationSummary,
    LatestClassificationSummary,
    StoredAnalysisResult,
    StoredClassificationResult,
)

logger = logging.getLogger("backend.investigations")

_DEFAULT_LIMIT = 20
_MAX_LIMIT = 100


def _duration_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


class AnalysisAlreadyExistsError(Exception):
    """Raised when the targeted classification_result already has an analysis_result
    -- analysis_results.classification_result_id is UNIQUE (1:0..1). The caller
    re-analyzes by persisting a new classification_result instead of overwriting an
    existing analysis -- investigation history stays append-only/immutable."""


def _owned_investigation(db, user_id: int, investigation_id: int) -> Investigation | None:
    """The one place an investigation is ever looked up by id -- always joined with
    the ownership check in the same query, never fetched first and compared after."""
    return db.scalar(
        select(Investigation).where(Investigation.id == investigation_id, Investigation.user_id == user_id)
    )


def _owned_classification_result(
    db, user_id: int, investigation_id: int, result_id: int
) -> ClassificationRecord | None:
    """Verifies the FULL chain in one query: the classification_result belongs to
    THIS investigation_id, and that investigation belongs to user_id. A result_id
    that's real but belongs to a different investigation (path confusion -- e.g. a
    caller's own valid investigation_id paired with someone else's result_id) does
    not match `ClassificationRecord.investigation_id == investigation_id` and so
    returns None exactly like a nonexistent id would."""
    return db.scalar(
        select(ClassificationRecord).where(
            ClassificationRecord.id == result_id,
            ClassificationRecord.investigation_id == investigation_id,
            ClassificationRecord.investigation.has(Investigation.user_id == user_id),
        )
    )


def _to_stored_analysis(record: AnalysisRecord | None) -> StoredAnalysisResult | None:
    if record is None:
        return None
    return StoredAnalysisResult(
        status=record.status,
        threat=record.threat,
        severity=record.severity,
        summary=record.summary,
        attack_vectors=record.attack_vectors or [],
        mitre_attack=record.mitre_attack or [],
        indicators=record.indicators or [],
        mitigations=record.mitigations or [],
        sources=record.sources or [],
        evidence=record.evidence,
        created_at=record.created_at,
    )


def _to_stored_classification(record: ClassificationRecord) -> StoredClassificationResult:
    return StoredClassificationResult(
        id=record.id,
        features=record.features,
        prediction=record.prediction,
        classification=record.classification,
        probability=record.probability,
        class_probabilities=record.class_probabilities,
        model_version=record.model_version,
        created_at=record.created_at,
        analysis_result=_to_stored_analysis(record.analysis_result),
    )


def create_investigation(user_id: int, label: str | None) -> InvestigationCreateResponse:
    start = time.perf_counter()
    with session_scope() as db:
        investigation = Investigation(user_id=user_id, label=label)
        db.add(investigation)
        db.flush()
        db.refresh(investigation)
        result = InvestigationCreateResponse(
            id=investigation.id,
            label=investigation.label,
            created_at=investigation.created_at,
            updated_at=investigation.updated_at,
        )

    duration_ms = _duration_ms(start)
    logger.info(
        "Investigation created",
        extra={
            "event": "investigation_created",
            "user_id": user_id,
            "investigation_id": result.id,
            "duration_ms": duration_ms,
            "success": True,
        },
    )
    metrics.increment("investigation_persistence_total", operation="create_investigation", outcome="success")
    metrics.observe_duration_ms("investigation_persistence", duration_ms, operation="create_investigation")
    return result


def list_investigations(user_id: int, limit: int | None, offset: int | None) -> InvestigationListResponse:
    limit = _DEFAULT_LIMIT if limit is None else max(1, min(limit, _MAX_LIMIT))
    offset = max(0, offset or 0)

    with session_scope() as db:
        total = (
            db.scalar(select(func.count()).select_from(Investigation).where(Investigation.user_id == user_id)) or 0
        )
        rows = (
            db.scalars(
                select(Investigation)
                .where(Investigation.user_id == user_id)
                # Investigation.latest_classification uses lazy="joined" (see
                # backend/db/models.py) so this stays one query regardless of how
                # many investigations are returned -- no N+1.
                .order_by(Investigation.updated_at.desc())
                .limit(limit)
                .offset(offset)
            )
            .unique()
            .all()
        )

        items = [
            InvestigationSummary(
                id=inv.id,
                label=inv.label,
                created_at=inv.created_at,
                updated_at=inv.updated_at,
                latest_classification=(
                    LatestClassificationSummary(
                        id=inv.latest_classification.id,
                        prediction=inv.latest_classification.prediction,
                        classification=inv.latest_classification.classification,
                        probability=inv.latest_classification.probability,
                        model_version=inv.latest_classification.model_version,
                        created_at=inv.latest_classification.created_at,
                    )
                    if inv.latest_classification is not None
                    else None
                ),
            )
            for inv in rows
        ]
        return InvestigationListResponse(items=items, total=total)


def get_investigation_detail(user_id: int, investigation_id: int) -> InvestigationDetail | None:
    start = time.perf_counter()
    with session_scope() as db:
        investigation = db.scalar(
            select(Investigation)
            .where(Investigation.id == investigation_id, Investigation.user_id == user_id)
            .options(
                selectinload(Investigation.classification_results).selectinload(ClassificationRecord.analysis_result)
            )
        )
        if investigation is None:
            # A WARNING, not INFO -- either the id genuinely doesn't exist (routine)
            # or a different user's investigation was requested (worth being able to
            # spot in logs even though the HTTP response is an indistinguishable 404
            # either way; see this module's docstring).
            logger.warning(
                "Investigation not found or not owned by requesting user",
                extra={
                    "event": "investigation_access_denied",
                    "user_id": user_id,
                    "investigation_id": investigation_id,
                },
            )
            return None
        result = InvestigationDetail(
            id=investigation.id,
            label=investigation.label,
            created_at=investigation.created_at,
            updated_at=investigation.updated_at,
            # Investigation.classification_results is already ordered oldest -> newest
            # (order_by=ClassificationRecord.created_at on the relationship, see
            # backend/db/models.py) -- correct for timeline rendering.
            classification_results=[_to_stored_classification(record) for record in investigation.classification_results],
        )

    duration_ms = _duration_ms(start)
    logger.info(
        "Investigation loaded",
        extra={
            "event": "investigation_loaded",
            "user_id": user_id,
            "investigation_id": investigation_id,
            "classification_result_count": len(result.classification_results),
            "duration_ms": duration_ms,
            "success": True,
        },
    )
    metrics.increment("investigation_persistence_total", operation="load_investigation", outcome="success")
    metrics.observe_duration_ms("investigation_persistence", duration_ms, operation="load_investigation")
    return result


def add_classification_result(
    user_id: int, investigation_id: int, payload: ClassificationResultCreateRequest
) -> StoredClassificationResult | None:
    """Returns None if `investigation_id` doesn't exist or isn't owned by user_id
    (caller raises 404). One transaction: inserts the classification_results row and
    updates the parent investigation's latest_classification_id + updated_at."""
    start = time.perf_counter()
    with session_scope() as db:
        investigation = _owned_investigation(db, user_id, investigation_id)
        if investigation is None:
            logger.warning(
                "Investigation not found or not owned by requesting user",
                extra={
                    "event": "investigation_access_denied",
                    "user_id": user_id,
                    "investigation_id": investigation_id,
                },
            )
            metrics.increment(
                "investigation_persistence_total", operation="persist_classification_result", outcome="denied"
            )
            return None

        record = ClassificationRecord(
            investigation_id=investigation.id,
            features=payload.features.model_dump(by_alias=True),
            prediction=payload.result.prediction,
            classification=payload.result.classification,
            probability=payload.result.probability,
            class_probabilities=payload.result.class_probabilities,
            model_version=payload.result.model_version,
        )
        db.add(record)
        db.flush()  # populate record.id for the pointer below

        investigation.latest_classification_id = record.id
        # No explicit `updated_at = now()` needed: setting the attribute above marks
        # this row dirty, so the UPDATE SQLAlchemy emits on flush already includes
        # investigation.updated_at's onupdate=func.now() (backend/db/models.py).

        db.flush()
        db.refresh(record)
        result = _to_stored_classification(record)

    duration_ms = _duration_ms(start)
    # Metadata only -- prediction/classification, never the stored feature vector or
    # any AI-generated report content.
    logger.info(
        "Classification result persisted",
        extra={
            "event": "classification_result_persisted",
            "user_id": user_id,
            "investigation_id": investigation_id,
            "classification_result_id": result.id,
            "prediction": result.prediction,
            "classification": result.classification,
            "duration_ms": duration_ms,
            "success": True,
        },
    )
    metrics.increment(
        "investigation_persistence_total", operation="persist_classification_result", outcome="success"
    )
    metrics.observe_duration_ms("investigation_persistence", duration_ms, operation="persist_classification_result")
    return result


def add_analysis_result(
    user_id: int, investigation_id: int, result_id: int, payload: AnalysisResultCreateRequest
) -> StoredAnalysisResult | None:
    """Returns None if the investigation/classification_result chain doesn't resolve
    to a row owned by user_id (caller raises 404). Raises AnalysisAlreadyExistsError
    if `result_id` already has an analysis_result (caller raises 409)."""
    start = time.perf_counter()
    with session_scope() as db:
        record = _owned_classification_result(db, user_id, investigation_id, result_id)
        if record is None:
            logger.warning(
                "Classification result not found or not owned by requesting user",
                extra={
                    "event": "investigation_access_denied",
                    "user_id": user_id,
                    "investigation_id": investigation_id,
                    "classification_result_id": result_id,
                },
            )
            metrics.increment("investigation_persistence_total", operation="persist_analysis_result", outcome="denied")
            return None

        existing = db.scalar(select(AnalysisRecord).where(AnalysisRecord.classification_result_id == record.id))
        if existing is not None:
            logger.info(
                "Analysis result already exists for this classification result",
                extra={
                    "event": "analysis_result_conflict",
                    "user_id": user_id,
                    "investigation_id": investigation_id,
                    "classification_result_id": result_id,
                },
            )
            metrics.increment(
                "investigation_persistence_total", operation="persist_analysis_result", outcome="conflict"
            )
            raise AnalysisAlreadyExistsError(
                f"classification_result {result_id} already has an analysis_result."
            )

        analysis = payload.analysis
        analysis_record = AnalysisRecord(
            classification_result_id=record.id,
            status=analysis.status,
            threat=analysis.threat,
            severity=analysis.severity,
            summary=analysis.summary,
            attack_vectors=analysis.attack_vectors,
            mitre_attack=[technique.model_dump() for technique in analysis.mitre_attack],
            indicators=analysis.indicators,
            mitigations=analysis.mitigations,
            sources=[source.model_dump() for source in analysis.sources],
            evidence=payload.evidence.model_dump() if payload.evidence is not None else None,
        )
        db.add(analysis_record)
        db.flush()
        db.refresh(analysis_record)
        result = _to_stored_analysis(analysis_record)

    duration_ms = _duration_ms(start)
    # Metadata only -- status/threat/severity, never the summary text, evidence, or
    # any other AI-generated report content.
    logger.info(
        "Analysis result persisted",
        extra={
            "event": "analysis_result_persisted",
            "user_id": user_id,
            "investigation_id": investigation_id,
            "classification_result_id": result_id,
            "status": result.status,
            "threat": result.threat,
            "severity": result.severity,
            "duration_ms": duration_ms,
            "success": True,
        },
    )
    metrics.increment("investigation_persistence_total", operation="persist_analysis_result", outcome="success")
    metrics.observe_duration_ms("investigation_persistence", duration_ms, operation="persist_analysis_result")
    return result
