"""Pydantic models for the Phase 9 intelligence layer: both the typed internal
evidence representation used by hybrid retrieval / the evidence-aware LLM layer, and
the request/response shapes for the new /intelligence/* endpoints.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from backend.intelligence.entities import EntityType, RelationType


class EntitySummary(BaseModel):
    id: str
    type: EntityType
    name: str


class RelationSummary(BaseModel):
    relation: RelationType
    target: EntitySummary
    reference: str | None = None


class ThreatGraphNeighborhood(BaseModel):
    """GET /intelligence/graph/{threat_id} response: one threat entity and every
    relationship directly connected to it."""

    threat: EntitySummary
    relations: list[RelationSummary] = Field(default_factory=list)


class VectorEvidenceItem(BaseModel):
    """One retrieved chunk, exactly as backend/rag/retrieval.py already returns it --
    this mirrors the existing SourceRef shape (backend/models/schemas.py) so nothing
    about the existing /analyze source-attribution contract changes."""

    source: str
    threat_type: str
    chunk_index: int
    score: float


class GraphEvidenceItem(BaseModel):
    """One graph relationship, resolved to its target entity's name/type -- the LLM
    never sees a bare ID, so it can reason over "DDoS Attack mitigated by Rate
    Limiting" without needing to invent what an ID string means."""

    relation: RelationType
    target_id: str
    target_name: str
    target_type: EntityType
    reference: str | None = None


class ClassifierEvidence(BaseModel):
    """The classifier's own output, carried through as evidence. This is never
    written to or reinterpreted by the LLM -- see backend/services/classification.py
    and tests/test_classifier_evidence.py."""

    prediction: str
    probability: float | None = None
    model: str


class HybridEvidence(BaseModel):
    """Typed, backend-owned evidence bundle for one query: distinguishes classifier,
    vector, and graph evidence rather than collapsing them into one free-form string.
    This is what backend/intelligence/evidence_llm.py formats into the LLM prompt, and
    what backend code (never the LLM) uses to build the final response's
    source/MITRE/mitigation lists."""

    query: str
    primary_threat: str | None = None
    classifier: ClassifierEvidence | None = None
    vector_evidence: list[VectorEvidenceItem] = Field(default_factory=list)
    graph_evidence: list[GraphEvidenceItem] = Field(default_factory=list)
    vector_duration_ms: float | None = None
    graph_duration_ms: float | None = None


class IntelligenceSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000)

    @field_validator("query")
    @classmethod
    def not_blank(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("query must not be blank")
        return stripped


class IntelligenceSearchResult(BaseModel):
    """One item in POST /intelligence/search's response: a vector match enriched with
    its threat's direct graph relationships."""

    source: str
    threat_type: str
    chunk_index: int
    score: float
    graph_relations: list[GraphEvidenceItem] = Field(default_factory=list)
