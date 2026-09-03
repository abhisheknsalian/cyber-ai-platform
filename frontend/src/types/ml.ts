/** Mirrors backend/ml/schemas.py and backend/ml/config.py exactly. */

import type { ThreatAnalysis } from "./api";
import type { HybridEvidence } from "./intelligence";

/** The 78 CICFlowMeter feature columns the Random Forest model was trained on, in
 * the exact order backend/ml/config.py uses. Used only to build the "fill example"
 * helper below -- the backend is the source of truth and validates every field. */
export const FEATURE_COLUMNS = [
  "Destination Port",
  "Flow Duration",
  "Total Fwd Packets",
  "Total Backward Packets",
  "Total Length of Fwd Packets",
  "Total Length of Bwd Packets",
  "Fwd Packet Length Max",
  "Fwd Packet Length Min",
  "Fwd Packet Length Mean",
  "Fwd Packet Length Std",
  "Bwd Packet Length Max",
  "Bwd Packet Length Min",
  "Bwd Packet Length Mean",
  "Bwd Packet Length Std",
  "Flow Bytes/s",
  "Flow Packets/s",
  "Flow IAT Mean",
  "Flow IAT Std",
  "Flow IAT Max",
  "Flow IAT Min",
  "Fwd IAT Total",
  "Fwd IAT Mean",
  "Fwd IAT Std",
  "Fwd IAT Max",
  "Fwd IAT Min",
  "Bwd IAT Total",
  "Bwd IAT Mean",
  "Bwd IAT Std",
  "Bwd IAT Max",
  "Bwd IAT Min",
  "Fwd PSH Flags",
  "Bwd PSH Flags",
  "Fwd URG Flags",
  "Bwd URG Flags",
  "Fwd Header Length",
  "Bwd Header Length",
  "Fwd Packets/s",
  "Bwd Packets/s",
  "Min Packet Length",
  "Max Packet Length",
  "Packet Length Mean",
  "Packet Length Std",
  "Packet Length Variance",
  "FIN Flag Count",
  "SYN Flag Count",
  "RST Flag Count",
  "PSH Flag Count",
  "ACK Flag Count",
  "URG Flag Count",
  "CWE Flag Count",
  "ECE Flag Count",
  "Down/Up Ratio",
  "Average Packet Size",
  "Avg Fwd Segment Size",
  "Avg Bwd Segment Size",
  "Fwd Header Length.1",
  "Fwd Avg Bytes/Bulk",
  "Fwd Avg Packets/Bulk",
  "Fwd Avg Bulk Rate",
  "Bwd Avg Bytes/Bulk",
  "Bwd Avg Packets/Bulk",
  "Bwd Avg Bulk Rate",
  "Subflow Fwd Packets",
  "Subflow Fwd Bytes",
  "Subflow Bwd Packets",
  "Subflow Bwd Bytes",
  "Init_Win_bytes_forward",
  "Init_Win_bytes_backward",
  "act_data_pkt_fwd",
  "min_seg_size_forward",
  "Active Mean",
  "Active Std",
  "Active Max",
  "Active Min",
  "Idle Mean",
  "Idle Std",
  "Idle Max",
  "Idle Min",
] as const;

/** A CICFlowMeter feature vector keyed by the exact column names above. */
export type NetworkTrafficFeatures = Record<string, number>;

/** str server-side (backend/ml/schemas.py), validated at runtime against LABEL_MAP --
 * not a hardcoded Literal, so a future class (multi-class-ready pipeline) doesn't
 * require a frontend type edit. Today LABEL_MAP is still {"BENIGN", "DDoS"}. */
export type ClassifierPrediction = string;

export interface ClassificationResult {
  prediction: ClassifierPrediction;
  /** RandomForestClassifier.predict_proba for the predicted class -- the fraction of
   * trees that voted for it, not a calibrated real-world certainty. */
  probability: number | null;
  model: "random_forest";
  classification: "malicious" | "benign";
  /** The complete predict_proba() vector keyed by class label, e.g.
   * { BENIGN: 0.02, DDoS: 0.98 }. None if the loaded model has no predict_proba. */
  class_probabilities: Record<string, number> | null;
  /** The trained artifact's `trained_at` timestamp, or null if no metadata file is
   * present. */
  model_version: string | null;
}

export interface FeatureImportanceItem {
  feature: string;
  importance: number;
}

export interface ClassificationAnalysisRequest {
  prediction: ClassifierPrediction;
  probability?: number | null;
}

export interface ClassificationAnalysisResponse {
  classification: ClassificationResult;
  /** null when classification is "benign" -- there is no threat to analyze. */
  analysis: ThreatAnalysis | null;
  /** The hybrid evidence bundle backing `analysis` (classifier + vector + graph).
   * null whenever `analysis` is null. */
  evidence: HybridEvidence | null;
}
