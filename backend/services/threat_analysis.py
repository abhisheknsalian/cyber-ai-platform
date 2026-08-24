import logging
import re
import time

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


def analyze_query(query: str) -> ThreatAnalysis:
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
    context = "\n\n".join(doc.page_content for doc, _score in primary_chunks)

    logger.info(
        "RAG primary threat selected",
        extra={"event": "rag_threat_selected", "threat": primary_threat, "source_count": len(sources)},
    )

    fragment = generate_analysis_fragment(query, context)

    if fragment.insufficient_context:
        return ThreatAnalysis(
            query=query,
            status="no_relevant_intelligence",
            summary=fragment.summary or NO_MATCH_SUMMARY,
            sources=sources,
        )

    return ThreatAnalysis(
        query=query,
        status="analyzed",
        threat=primary_threat,
        severity=fragment.severity,
        summary=fragment.summary,
        attack_vectors=fragment.attack_vectors,
        mitre_attack=mitre,
        indicators=fragment.indicators,
        mitigations=fragment.mitigations,
        sources=sources,
    )
