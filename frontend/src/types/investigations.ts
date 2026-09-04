/** Mirrors backend/investigations/schemas.py exactly (Phase 14). */

import type { AnalysisStatus, MitreTechnique, Severity, ThreatAnalysis, ThreatSource } from "./api";
import type { HybridEvidence } from "./intelligence";
import type { ClassificationResult, NetworkTrafficFeatures } from "./ml";

export interface InvestigationCreateRequest {
  label?: string | null;
}

export interface InvestigationCreateResponse {
  id: number;
  label: string | null;
  created_at: string;
  updated_at: string;
}

export interface LatestClassificationSummary {
  id: number;
  prediction: string;
  classification: "malicious" | "benign";
  probability: number | null;
  model_version: string | null;
  created_at: string;
}

export interface InvestigationSummary {
  id: number;
  label: string | null;
  created_at: string;
  updated_at: string;
  latest_classification: LatestClassificationSummary | null;
}

export interface InvestigationListResponse {
  items: InvestigationSummary[];
  total: number;
}

export interface StoredAnalysisResult {
  status: AnalysisStatus;
  threat: string | null;
  severity: Severity | null;
  summary: string;
  attack_vectors: string[];
  mitre_attack: MitreTechnique[];
  indicators: string[];
  mitigations: string[];
  sources: ThreatSource[];
  evidence: HybridEvidence | null;
  created_at: string;
}

export interface StoredClassificationResult {
  id: number;
  features: NetworkTrafficFeatures;
  prediction: string;
  classification: "malicious" | "benign";
  probability: number | null;
  class_probabilities: Record<string, number> | null;
  model_version: string | null;
  created_at: string;
  analysis_result: StoredAnalysisResult | null;
}

export interface InvestigationDetail {
  id: number;
  label: string | null;
  created_at: string;
  updated_at: string;
  classification_results: StoredClassificationResult[];
}

export interface ClassificationResultCreateRequest {
  features: NetworkTrafficFeatures;
  result: ClassificationResult;
}

export interface AnalysisResultCreateRequest {
  analysis: ThreatAnalysis;
  evidence?: HybridEvidence | null;
}
