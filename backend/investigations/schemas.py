"""Pydantic request/response schemas for persistent, per-user investigations
(Phase 14) -- POST/GET /investigations, GET /investigations/{id}, and the two
persistence-only endpoints that record an already-computed POST /classify or
POST /analyze/classification result. Reuses the existing ML/intelligence schemas
(NetworkTrafficFeatures, ClassificationResult, ThreatAnalysis, HybridEvidence)
wherever the shape is identical, rather than inventing parallel types.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.intelligence.schemas import HybridEvidence
from backend.ml.schemas import ClassificationResult, NetworkTrafficFeatures
from backend.models.schemas import MitreTechnique, Severity, SourceRef, ThreatAnalysis


class InvestigationCreateRequest(BaseModel):
    """POST /investigations body. `user_id` is deliberately not a field here --
    ownership comes exclusively from the authenticated session
    (backend.security.require_user_id), never from client input."""

    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, max_length=255)

    @field_validator("label")
    @classmethod
    def _blank_label_is_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


class InvestigationCreateResponse(BaseModel):
    id: int
    label: str | None
    created_at: datetime
    updated_at: datetime


class LatestClassificationSummary(BaseModel):
    """The subset of a classification_results row shown in a GET /investigations
    list row -- enough to render a status badge without fetching the full detail."""

    id: int
    prediction: str
    classification: str
    probability: float | None
    model_version: str | None
    created_at: datetime


class InvestigationSummary(BaseModel):
    id: int
    label: str | None
    created_at: datetime
    updated_at: datetime
    latest_classification: LatestClassificationSummary | None


class InvestigationListResponse(BaseModel):
    items: list[InvestigationSummary]
    total: int


class StoredAnalysisResult(BaseModel):
    """A persisted analysis_results row -- field-for-field mirrors ThreatAnalysis
    (minus `query`, which belongs to the classifier-mapped query that generated it,
    not to the stored artifact) plus the HybridEvidence bundle it was generated from.
    """

    status: Literal["analyzed", "no_relevant_intelligence"]
    threat: str | None
    severity: Severity | None
    summary: str
    attack_vectors: list[str]
    mitre_attack: list[MitreTechnique]
    indicators: list[str]
    mitigations: list[str]
    sources: list[SourceRef]
    evidence: HybridEvidence | None
    created_at: datetime


class StoredClassificationResult(BaseModel):
    """A persisted classification_results row, with its optional analysis_result.
    `features` is returned as a plain dict (exactly what's stored as JSON) rather
    than reconstructed into NetworkTrafficFeatures -- that model's field aliases
    (the literal CICFlowMeter column names, e.g. "Flow Bytes/s") add alias-handling
    complexity on the read path for no benefit here; the frontend's own
    NetworkTrafficFeatures type already describes this exact shape."""

    id: int
    features: dict[str, float]
    prediction: str
    classification: str
    probability: float | None
    class_probabilities: dict[str, float] | None
    model_version: str | None
    created_at: datetime
    analysis_result: StoredAnalysisResult | None


class InvestigationDetail(BaseModel):
    id: int
    label: str | None
    created_at: datetime
    updated_at: datetime
    classification_results: list[StoredClassificationResult]


class ClassificationResultCreateRequest(BaseModel):
    """POST /investigations/{id}/classification-results body -- an already-computed
    POST /classify result (features + the model's own output). Never re-runs the
    classifier; `features` is still validated against NetworkTrafficFeatures (the
    same schema /classify itself uses) so a persisted record can never be an
    arbitrary/malformed payload, even though it isn't re-scored."""

    model_config = ConfigDict(extra="forbid")

    features: NetworkTrafficFeatures
    result: ClassificationResult


class AnalysisResultCreateRequest(BaseModel):
    """POST .../analysis-result body -- an already-computed POST
    /analyze/classification result (analysis + hybrid evidence). Never re-runs RAG,
    graph retrieval, or the LLM."""

    model_config = ConfigDict(extra="forbid")

    analysis: ThreatAnalysis
    evidence: HybridEvidence | None = None
