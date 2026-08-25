/** Mirrors backend/intelligence/schemas.py exactly (Phase 9). */

export type EntityType = "threat" | "technique" | "indicator" | "mitigation" | "source";

export type RelationType = "USES" | "HAS_INDICATOR" | "MITIGATED_BY" | "SUPPORTED_BY";

export interface EntitySummary {
  id: string;
  type: EntityType;
  name: string;
}

export interface RelationSummary {
  relation: RelationType;
  target: EntitySummary;
  reference: string | null;
}

export interface ThreatGraphNeighborhood {
  threat: EntitySummary;
  relations: RelationSummary[];
}
