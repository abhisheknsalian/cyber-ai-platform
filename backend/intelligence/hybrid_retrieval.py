"""Hybrid retrieval: combines the existing vector retrieval
(backend/rag/retrieval.py, untouched) with structured graph traversal
(backend/intelligence/graph_store.py) into one typed evidence object. Neither
retrieval path replaces the other -- this is an additional layer sitting above both.
"""

from __future__ import annotations

import logging
import time

from backend import metrics
from backend.intelligence.entities import threat_id
from backend.intelligence.graph_store import get_graph
from backend.intelligence.normalizer import slug_for
from backend.intelligence.schemas import (
    ClassifierEvidence,
    EntitySummary,
    GraphEvidenceItem,
    HybridEvidence,
    RelationSummary,
    ThreatGraphNeighborhood,
    VectorEvidenceItem,
)
from backend.rag.config import COLLECTION_NAME, RAG_SCORE_THRESHOLD, RAG_TOP_K
from backend.rag.retrieval import retrieve_relevant

logger = logging.getLogger("backend.intelligence")


def graph_evidence_for_threat(threat_stem: str) -> list[GraphEvidenceItem]:
    """Every direct relationship for the given threat, resolved to target
    entity name/type. Returns an empty list (not an error) if the threat isn't in the
    graph -- callers treat "no graph evidence" as a normal, representable state."""
    graph = get_graph()
    tid = threat_id(threat_stem)
    if tid not in graph.entities:
        return []

    items: list[GraphEvidenceItem] = []
    for relationship in graph.relations_from(tid):
        target = graph.entities.get(relationship.target_id)
        if target is None:
            continue
        items.append(
            GraphEvidenceItem(
                relation=relationship.relation,
                target_id=target.id,
                target_name=target.name,
                target_type=target.type,
                reference=relationship.reference,
            )
        )
    return items


def graph_neighborhood(threat_stem: str) -> ThreatGraphNeighborhood | None:
    """GET /intelligence/graph/{threat_id}'s data source: the threat entity itself
    plus every relationship directly connected to it."""
    graph = get_graph()
    tid = threat_id(threat_stem)
    entity = graph.entities.get(tid)
    if entity is None:
        return None

    relations: list[RelationSummary] = []
    for relationship in graph.relations_from(tid):
        target = graph.entities.get(relationship.target_id)
        if target is None:
            continue
        relations.append(
            RelationSummary(
                relation=relationship.relation,
                target=EntitySummary(id=target.id, type=target.type, name=target.name),
                reference=relationship.reference,
            )
        )
    return ThreatGraphNeighborhood(
        threat=EntitySummary(id=entity.id, type=entity.type, name=entity.name),
        relations=relations,
    )


def gather_hybrid_evidence(
    query: str,
    *,
    threat_hint: str | None = None,
    classifier: ClassifierEvidence | None = None,
) -> HybridEvidence:
    """Runs vector retrieval (unchanged from the existing /analyze path) and, for
    whichever threat type turns out to be primary, attaches that threat's graph
    relationships as evidence.

    threat_hint: when the caller already knows the threat type (e.g. a classifier
    prediction resolved to "ddos_attack"), it's used directly instead of inferring the
    primary threat from the vector search's own top match -- this is what lets the
    classifier->RAG path (backend/services/classification.py) attach graph evidence
    even for a query where vector retrieval alone might return a different top hit.
    """
    vector_start = time.perf_counter()
    relevant = retrieve_relevant(query, k=RAG_TOP_K, threshold=RAG_SCORE_THRESHOLD)
    vector_duration_ms = round((time.perf_counter() - vector_start) * 1000, 2)

    vector_evidence = [
        VectorEvidenceItem(
            source=doc.metadata.get("source", "unknown"),
            threat_type=doc.metadata.get("threat_type", "unknown"),
            chunk_index=doc.metadata.get("chunk_index", -1),
            score=score,
        )
        for doc, score in relevant
    ]

    # Metadata only -- counts, timing, and the resolved primary threat, never the
    # retrieved chunk text itself (that's the knowledge base's actual intelligence
    # content, already served in the response; this log is a metric, not a copy).
    logger.info(
        "RAG retrieval completed",
        extra={
            "event": "rag_retrieval_completed",
            "collection": COLLECTION_NAME,
            "top_k": RAG_TOP_K,
            "retrieved_count": len(vector_evidence),
            "duration_ms": vector_duration_ms,
            "success": True,
        },
    )
    metrics.increment("rag_retrievals_total")
    metrics.observe_duration_ms("rag_retrieval", vector_duration_ms)

    primary_threat = threat_hint or (relevant[0][0].metadata.get("threat_type") if relevant else None)

    graph_start = time.perf_counter()
    graph_evidence = graph_evidence_for_threat(slug_for(primary_threat)) if primary_threat else []
    graph_duration_ms = round((time.perf_counter() - graph_start) * 1000, 2)
    # Distinct target entities referenced by this threat's relationships, plus the
    # threat entity itself when one was resolved -- how much of the graph this
    # particular request actually touched, not the graph's total size (see
    # backend/intelligence/graph_store.py's separate, one-time "graph_built" event
    # for that).
    entity_count = len({item.target_id for item in graph_evidence}) + (1 if primary_threat else 0)

    logger.info(
        "Threat graph retrieval completed",
        extra={
            "event": "graph_retrieval_completed",
            "primary_threat": primary_threat,
            "entity_count": entity_count,
            "relationship_count": len(graph_evidence),
            "duration_ms": graph_duration_ms,
            "success": True,
        },
    )
    metrics.increment("graph_retrievals_total")
    metrics.observe_duration_ms("graph_retrieval", graph_duration_ms)

    return HybridEvidence(
        query=query,
        primary_threat=primary_threat,
        classifier=classifier,
        vector_evidence=vector_evidence,
        graph_evidence=graph_evidence,
        vector_duration_ms=vector_duration_ms,
        graph_duration_ms=graph_duration_ms,
    )
