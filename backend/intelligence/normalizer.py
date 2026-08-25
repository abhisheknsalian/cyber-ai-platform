"""Deterministically converts data/threat_intel/*.txt into structured entities and
relationships. Pure text parsing -- no LLM involved anywhere in this module, so a
technique/indicator/mitigation can only end up in the graph if it is actually present
in the source document, and running this against the same files always produces the
same graph (see tests/test_intelligence_normalizer.py for the duplicate-ingestion
check).

Reuses the same "T####: Name" MITRE pattern that
backend/services/threat_analysis.py's _extract_mitre_techniques() already uses for
the existing /analyze response (that function is untouched by this module -- the
pattern is small enough that duplicating the one-line regex here is lower-risk than
refactoring already-tested, working code to share it).
"""

from __future__ import annotations

import re
from pathlib import Path

from backend.intelligence.entities import (
    Entity,
    Relationship,
    ThreatGraph,
    indicator_id,
    mitigation_id,
    slugify,
    source_id,
    technique_id,
    threat_id,
)

MITRE_PATTERN = re.compile(r"(T\d{4})\s*:\s*(.+)")

_INDICATOR_HEADER = re.compile(r"^common indicators:$", re.IGNORECASE)
_MITIGATION_HEADER = re.compile(r"^(common\s+)?mitigation(\s+strategies)?:$", re.IGNORECASE)

# Display-only: str.capitalize() doesn't know these are acronyms (would otherwise
# render "Ddos"/"Sql"). Purely cosmetic -- entity IDs are unaffected either way.
_ACRONYMS = {"ddos": "DDoS", "sql": "SQL"}


def _extract_bulleted_section(text: str, header_pattern: re.Pattern[str]) -> list[str]:
    """Returns the "- item" bullet lines directly under the first line matching
    header_pattern, stopping at the next blank line (or end of file). Sections in
    these documents are never nested, so a single stop condition is sufficient."""
    items: list[str] = []
    capturing = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if header_pattern.match(line):
            capturing = True
            continue
        if not capturing:
            continue
        if line.startswith("-"):
            item = line.lstrip("-").strip()
            if item:
                items.append(item)
        elif not line and items:
            break
    return items


def normalize_document(path: Path) -> tuple[list[Entity], list[Relationship]]:
    """Parses one threat-intel document into its Threat/Technique/Indicator/
    Mitigation/Source entities and the relationships connecting them to the threat."""
    text = path.read_text(encoding="utf-8")
    stem = path.stem
    filename = path.name

    # Threat.name is derived from the filename stem (e.g. "ddos_attack" -> "DDoS
    # Attack"), matching the existing /threats endpoint's convention
    # (backend/services/knowledge_base.py uses the same stem as threat_type).
    threat_name = " ".join(_ACRONYMS.get(word, word.capitalize()) for word in stem.split("_"))

    entities: list[Entity] = [Entity(id=threat_id(stem), type="threat", name=threat_name)]
    relationships: list[Relationship] = []

    source = Entity(id=source_id(filename), type="source", name=filename)
    entities.append(source)
    relationships.append(
        Relationship(source_id=threat_id(stem), relation="SUPPORTED_BY", target_id=source.id, reference=filename)
    )

    for mitre_code, mitre_name in MITRE_PATTERN.findall(text):
        technique = Entity(id=technique_id(mitre_code), type="technique", name=mitre_name.strip())
        entities.append(technique)
        relationships.append(
            Relationship(source_id=threat_id(stem), relation="USES", target_id=technique.id, reference=filename)
        )

    for indicator_text in _extract_bulleted_section(text, _INDICATOR_HEADER):
        indicator = Entity(id=indicator_id(indicator_text), type="indicator", name=indicator_text)
        entities.append(indicator)
        relationships.append(
            Relationship(source_id=threat_id(stem), relation="HAS_INDICATOR", target_id=indicator.id, reference=filename)
        )

    for mitigation_text in _extract_bulleted_section(text, _MITIGATION_HEADER):
        mitigation = Entity(id=mitigation_id(mitigation_text), type="mitigation", name=mitigation_text)
        entities.append(mitigation)
        relationships.append(
            Relationship(source_id=threat_id(stem), relation="MITIGATED_BY", target_id=mitigation.id, reference=filename)
        )

    return entities, relationships


def build_graph_from_documents(directory: Path) -> ThreatGraph:
    """Builds the full graph from every *.txt file in `directory`. Deterministic and
    order-independent: files are processed in sorted order and entity IDs are stable,
    so the resulting graph is identical across runs and across process restarts."""
    graph = ThreatGraph()
    for path in sorted(directory.glob("*.txt")):
        entities, relationships = normalize_document(path)
        for entity in entities:
            graph.add_entity(entity)
        for relationship in relationships:
            graph.add_relationship(relationship)
    return graph


def slug_for(text: str) -> str:
    """Exposed for callers that need to resolve free text (e.g. a classifier's
    prediction label) to the same slug the normalizer would have produced."""
    return slugify(text)
