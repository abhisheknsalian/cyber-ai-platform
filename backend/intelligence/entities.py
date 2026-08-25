"""Typed threat-intelligence entity/relationship models and their deterministic ID
scheme. IDs are computed by these pure functions -- never invented by the LLM and
never randomly generated -- so the same source text always produces the same ID.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

EntityType = Literal["threat", "technique", "indicator", "mitigation", "source"]

RelationType = Literal["USES", "HAS_INDICATOR", "MITIGATED_BY", "SUPPORTED_BY"]


def slugify(text: str) -> str:
    """Deterministic, filesystem/ID-safe slug: lowercase, non-alphanumerics become a
    single underscore, trimmed. Capped at 60 chars -- long enough to stay unique
    across this knowledge base's short indicator/mitigation phrases, short enough to
    keep IDs readable."""
    slug = re.sub(r"[^a-z0-9]+", "_", text.strip().lower()).strip("_")
    return slug[:60]


def threat_id(stem: str) -> str:
    return f"threat:{slugify(stem)}"


def technique_id(mitre_id: str) -> str:
    return f"mitre:{mitre_id.strip().upper()}"


def indicator_id(text: str) -> str:
    return f"indicator:{slugify(text)}"


def mitigation_id(text: str) -> str:
    return f"mitigation:{slugify(text)}"


def source_id(filename: str) -> str:
    return f"source:{filename.strip()}"


class Entity(BaseModel):
    id: str
    type: EntityType
    name: str


class Relationship(BaseModel):
    """A directed edge. `reference` records where this relationship was derived from
    (e.g. the source filename) so every edge -- not just every entity -- carries
    source attribution."""

    source_id: str
    relation: RelationType
    target_id: str
    reference: str | None = None


class ThreatGraph(BaseModel):
    """The full graph: every entity keyed by its own ID, plus the flat relationship
    list. Deliberately not a networkx graph -- this is small (dozens of nodes), needs
    to be JSON-serializable for the API and disk persistence, and doesn't need graph
    algorithms (shortest path, centrality, etc.) beyond "list a threat's direct
    relationships," which a flat list answers in O(n) without extra machinery."""

    entities: dict[str, Entity] = Field(default_factory=dict)
    relationships: list[Relationship] = Field(default_factory=list)

    def add_entity(self, entity: Entity) -> None:
        # Same ID + same source text always re-derives the same Entity, so re-adding
        # is idempotent -- this is what makes ingestion safe to run twice.
        self.entities[entity.id] = entity

    def add_relationship(self, relationship: Relationship) -> None:
        if relationship not in self.relationships:
            self.relationships.append(relationship)

    def relations_from(self, entity_id: str) -> list[Relationship]:
        return [r for r in self.relationships if r.source_id == entity_id]
