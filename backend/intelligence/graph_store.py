"""Local graph storage: build the graph from data/threat_intel/*.txt, cache it in
process memory, and optionally persist/reload it as JSON.

No external service, no network dependency, no secrets. Building the graph is pure
text parsing (no embeddings, no model download), so unlike the Chroma vector store it
is cheap enough to build lazily on first access rather than requiring a separate
ingestion step -- get_graph() below is the only thing most callers need. Disk
persistence (save_graph/load_graph) exists for inspectability and for
`uv run python -m backend.intelligence.ingestion` (see that module), mirroring the
existing backend.rag.ingestion CLI convention -- it is not required for the graph to
work at runtime.
"""

from __future__ import annotations

import logging
import os
import time
from functools import lru_cache
from pathlib import Path

from backend.intelligence.entities import ThreatGraph
from backend.intelligence.normalizer import build_graph_from_documents
from backend.rag.config import THREAT_INTEL_DIR

logger = logging.getLogger("backend.intelligence")

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# A derived/build artifact, like rag/chroma_db/ -- gitignored, rebuilt from the
# tracked data/threat_intel/*.txt source documents.
GRAPH_STORE_PATH = Path(
    os.getenv("THREAT_GRAPH_PATH", str(PROJECT_ROOT / "rag" / "graph" / "threat_graph.json"))
)


def build_graph() -> ThreatGraph:
    """Builds the graph fresh from data/threat_intel/*.txt. Deterministic: the same
    source documents always produce an identical graph (same entity IDs, same
    relationships) -- see tests/test_intelligence_normalizer.py."""
    return build_graph_from_documents(THREAT_INTEL_DIR)


def save_graph(graph: ThreatGraph, path: Path | None = None) -> Path:
    target = path or GRAPH_STORE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(graph.model_dump_json(indent=2), encoding="utf-8")
    return target


def load_graph(path: Path | None = None) -> ThreatGraph:
    target = path or GRAPH_STORE_PATH
    return ThreatGraph.model_validate_json(target.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def get_graph() -> ThreatGraph:
    """Process-wide cached graph. Same lazy-singleton pattern already used by
    backend/rag/retrieval.py's get_vector_store() / get_embedding_model() -- built
    once per process, on first access, and reused for the process's lifetime."""
    start = time.perf_counter()
    graph = build_graph()
    duration_ms = round((time.perf_counter() - start) * 1000, 2)
    logger.info(
        "Threat graph built",
        extra={
            "event": "graph_built",
            "entity_count": len(graph.entities),
            "relationship_count": len(graph.relationships),
            "duration_ms": duration_ms,
        },
    )
    return graph


def graph_available() -> bool:
    try:
        return len(get_graph().entities) > 0
    except Exception:
        return False
