import logging
import re
import time

from backend.intelligence.evidence_context import (
    build_evidence_context,
    graph_derived_indicators,
    graph_derived_mitigations,
)
from backend.intelligence.hybrid_retrieval import graph_evidence_for_threat
from backend.intelligence.schemas import ClassifierEvidence
from backend.models.schemas import MitreTechnique, SourceRef, ThreatAnalysis
from backend.rag.config import RAG_SCORE_THRESHOLD, RAG_TOP_K, THREAT_INTEL_DIR
from backend.rag.retrieval import retrieve_relevant, vector_store_available
from backend.services.llm import generate_analysis_fragment

logger = logging.getLogger("backend.rag")

MITRE_PATTERN = re.compile(r"(T\d{4})\s*:\s*(.+)")

NO_MATCH_SUMMARY = (
    "No relevant threat intelligence was found in the knowledge base for this query. "
    "This system only answers questions covered by its threat-intelligence documents "
    "(botnets, DDoS, phishing, ransomware, SQL injection)."
)


class VectorStoreUnavailableError(RuntimeError):
    """Raised when the Chroma collection has not been built yet."""


def _extract_mitre_techniques(source_filenames: set[str]) -> list[MitreTechnique]:
    """Parse MITRE ATT&CK technique IDs/names directly out of the source .txt files.

    Extracted from the full source document (not the retrieved chunk text) so results
    are unaffected by chunk boundaries, and deterministic so the LLM cannot fabricate
    or mis-transcribe a technique ID.
    """
    seen: dict[str, MitreTechnique] = {}
    for filename in sorted(source_filenames):
        file_path = THREAT_INTEL_DIR / filename
        if not file_path.exists():
            continue
        text = file_path.read_text(encoding="utf-8")
        for technique_id, name in MITRE_PATTERN.findall(text):
            seen.setdefault(technique_id, MitreTechnique(id=technique_id, name=name.strip()))
    return list(seen.values())


def analyze_query(query: str, *, classifier: ClassifierEvidence | None = None) -> ThreatAnalysis:
    """classifier: optional evidence from a prior classifier prediction (see
    backend/services/classification.py's classify_and_analyze()). When present, it is
    included as a labeled, deterministic section of the LLM's context (see
    backend/intelligence/evidence_context.py) -- the LLM may explain it but the
    prediction/probability values themselves come only from this argument, never from
    the LLM's own output, which has no field for them (backend/models/schemas.py's
    LLMAnalysisFragment). Plain /analyze calls this with classifier=None, so its
    existing behavior (Phase 2-8) is unchanged."""
    if not vector_store_available():
        raise VectorStoreUnavailableError("Vector store has not been built yet")

    # Logs query length, not the query text itself -- the text can be arbitrary user
    # input and isn't needed to understand retrieval behavior operationally.
    start = time.perf_counter()
    relevant = retrieve_relevant(query, k=RAG_TOP_K, threshold=RAG_SCORE_THRESHOLD)
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    logger.info(
        "RAG retrieval completed",
        extra={
            "event": "rag_retrieval",
            "query_length": len(query),
            "retrieved_count": len(relevant),
            "duration_ms": duration_ms,
        },
    )

    if not relevant:
        return ThreatAnalysis(query=query, status="no_relevant_intelligence", summary=NO_MATCH_SUMMARY)

    # retrieve_relevant returns best match first, so the top hit's threat_type is the
    # single most relevant threat for this query (see README "Threat Identification").
    primary_threat = relevant[0][0].metadata.get("threat_type", "unknown")

    # `relevant` (threshold-passing, top-k) can include tangential chunks from other
    # threat files that scored as secondary matches -- e.g. a phishing query's 4th/5th
    # hit can be a DDoS chunk. Scoping everything downstream (context, sources, MITRE)
    # to only the primary threat's own chunks keeps the analysis single-topic and
    # prevents an unrelated threat's mitigations/indicators/technique IDs from leaking
    # into the response.
    primary_chunks = [(doc, score) for doc, score in relevant if doc.metadata.get("threat_type") == primary_threat]

    sources = [
        SourceRef(
            source=doc.metadata.get("source", "unknown"),
            threat_type=doc.metadata.get("threat_type", "unknown"),
            chunk_index=doc.metadata.get("chunk_index", -1),
            score=score,
        )
        for doc, score in primary_chunks
    ]
    mitre = _extract_mitre_techniques({s.source for s in sources})

    # Graph evidence for the primary threat (Phase 9) -- deterministic, derived from
    # data/threat_intel/*.txt via backend/intelligence/normalizer.py, never from the
    # LLM. Empty for a threat the graph doesn't know about (defensive; in practice
    # every threat_type this KB produces is also in the graph).
    graph_start = time.perf_counter()
    graph_evidence = graph_evidence_for_threat(primary_threat)
    graph_duration_ms = round((time.perf_counter() - graph_start) * 1000, 2)

    retrieved_text = "\n\n".join(doc.page_content for doc, _score in primary_chunks)
    context = build_evidence_context(retrieved_text=retrieved_text, graph_evidence=graph_evidence, classifier=classifier)

    logger.info(
        "RAG primary threat selected",
        extra={
            "event": "rag_threat_selected",
            "threat": primary_threat,
            "source_count": len(sources),
            "graph_relation_count": len(graph_evidence),
            "graph_duration_ms": graph_duration_ms,
        },
    )

    fragment = generate_analysis_fragment(query, context)

    if fragment.insufficient_context:
        return ThreatAnalysis(
            query=query,
            status="no_relevant_intelligence",
            summary=fragment.summary or NO_MATCH_SUMMARY,
            sources=sources,
        )

    # Indicators/mitigations are now deterministically derived from the threat graph
    # when it has them (which it does for every threat this knowledge base produces),
    # falling back to the LLM's own (context-grounded, as before) fragment only if the
    # graph has none for this threat -- structurally, not just by prompt instruction,
    # satisfying "must not invent indicators/mitigations that aren't present in
    # evidence". attack_vectors and severity remain LLM-authored: they're genuinely
    # narrative/judgment fields the source documents don't enumerate deterministically.
    indicators = graph_derived_indicators(graph_evidence) or fragment.indicators
    mitigations = graph_derived_mitigations(graph_evidence) or fragment.mitigations

    return ThreatAnalysis(
        query=query,
        status="analyzed",
        threat=primary_threat,
        severity=fragment.severity,
        summary=fragment.summary,
        attack_vectors=fragment.attack_vectors,
        mitre_attack=mitre,
        indicators=indicators,
        mitigations=mitigations,
        sources=sources,
    )
