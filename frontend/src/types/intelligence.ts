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

export interface VectorEvidenceItem {
  source: string;
  threat_type: string;
  chunk_index: number;
  score: number;
}

export interface GraphEvidenceItem {
  relation: RelationType;
  target_id: string;
  target_name: string;
  target_type: EntityType;
  reference: string | null;
}

export interface ClassifierEvidence {
  prediction: string;
  probability: number | null;
  model: string;
}

/** Mirrors backend/intelligence/schemas.py::HybridEvidence -- the backend-owned
 * evidence bundle (classifier + vector + graph) behind an analysis. */
export interface HybridEvidence {
  query: string;
  primary_threat: string | null;
  classifier: ClassifierEvidence | null;
  vector_evidence: VectorEvidenceItem[];
  graph_evidence: GraphEvidenceItem[];
  vector_duration_ms: number | null;
  graph_duration_ms: number | null;
}
