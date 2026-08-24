/** Mirrors backend/models/schemas.py exactly. */

export type Severity = "Low" | "Medium" | "High" | "Critical";

export type AnalysisStatus = "analyzed" | "no_relevant_intelligence";

export interface AnalyzeRequest {
  query: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
}

export interface ThreatSource {
  source: string;
  threat_type: string;
  chunk_index: number;
  score: number;
}

export interface ThreatAnalysis {
  query: string;
  status: AnalysisStatus;
  threat: string | null;
  severity: Severity | null;
  summary: string;
  attack_vectors: string[];
  mitre_attack: MitreTechnique[];
  indicators: string[];
  mitigations: string[];
  sources: ThreatSource[];
}

export interface ThreatCategory {
  threat_type: string;
  source: string;
  description: string;
}

export interface VectorStoreStatus {
  available: boolean;
  chunk_count: number;
  collection: string;
}

export interface LLMStatus {
  model: string;
  reachable: boolean;
  model_pulled: boolean;
}

export interface HealthResponse {
  status: string;
  vector_store: VectorStoreStatus;
  llm: LLMStatus;
}
