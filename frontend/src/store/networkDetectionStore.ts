import { create } from "zustand";
import { persist } from "zustand/middleware";

import { createSafeStorage } from "./safeLocalStorage";
import type { ThreatAnalysis } from "../types/api";
import type { HybridEvidence } from "../types/intelligence";
import type { ClassificationAnalysisResponse, ClassificationResult, NetworkTrafficFeatures } from "../types/ml";

export type RequestStatus = "idle" | "loading" | "success" | "error";

const STORAGE_KEY = "cyber-ai-network-detection-v1";
const STORAGE_VERSION = 1;

interface PersistedShape {
  jsonInput: string;
  classifyStatus: RequestStatus;
  classification: ClassificationResult | null;
  /** The exact feature payload POST /classify was called with for `classification`
   * above -- kept alongside it (not re-derived from `jsonInput`, which the user may
   * go on editing after a successful classify) so "Save Investigation"
   * (frontend/src/store/investigationHistoryStore.ts) always persists the features
   * that actually produced this result, Phase 14. */
  lastClassifiedFeatures: NetworkTrafficFeatures | null;
  classifyError: string | null;
  analyzeStatus: RequestStatus;
  analysis: ThreatAnalysis | null;
  evidence: HybridEvidence | null;
  analyzeError: string | null;
  lastUpdated: string | null;
}

interface NetworkDetectionState extends PersistedShape {
  /** Marks the JSON input dirty (edited since the last classification) without
   * discarding the previous result, so the last-known-good investigation is never
   * silently lost while the user is mid-edit. */
  setJsonInput: (value: string) => void;
  startClassify: () => void;
  classifySuccess: (result: ClassificationResult, features: NetworkTrafficFeatures) => void;
  classifyFailure: (message: string) => void;
  startAnalyze: () => void;
  analyzeSuccess: (response: ClassificationAnalysisResponse) => void;
  analyzeFailure: (message: string) => void;
  clearInvestigation: () => void;
}

const INITIAL_PERSISTED_STATE: PersistedShape = {
  jsonInput: "",
  classifyStatus: "idle",
  classification: null,
  lastClassifiedFeatures: null,
  classifyError: null,
  analyzeStatus: "idle",
  analysis: null,
  evidence: null,
  analyzeError: null,
  lastUpdated: null,
};

/** Minimal structural check -- enough to reject garbage (wrong type, truncated
 * write, a value from an unrelated key/app version) without hand-rolling a full
 * schema validator. Anything that fails this is treated as "no persisted state". */
function isPersistedShape(value: unknown): value is PersistedShape {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.jsonInput === "string" &&
    typeof candidate.classifyStatus === "string" &&
    typeof candidate.analyzeStatus === "string" &&
    "classification" in candidate &&
    "analysis" in candidate
  );
}

const safeStorage = createSafeStorage(isPersistedShape);

export const useNetworkDetectionStore = create<NetworkDetectionState>()(
  persist(
    (set) => ({
      ...INITIAL_PERSISTED_STATE,

      setJsonInput: (value) => set({ jsonInput: value }),

      startClassify: () =>
        set({
          classifyStatus: "loading",
          classifyError: null,
          // A fresh classification invalidates any prior threat analysis -- it was
          // computed for a different (or edited) traffic sample.
          analyzeStatus: "idle",
          analysis: null,
          evidence: null,
          analyzeError: null,
        }),

      classifySuccess: (result, features) =>
        set({
          classifyStatus: "success",
          classification: result,
          lastClassifiedFeatures: features,
          classifyError: null,
          lastUpdated: new Date().toISOString(),
        }),

      classifyFailure: (message) =>
        set({
          classifyStatus: "error",
          classification: null,
          lastClassifiedFeatures: null,
          classifyError: message,
        }),

      startAnalyze: () => set({ analyzeStatus: "loading", analyzeError: null }),

      analyzeSuccess: (response) =>
        set({
          analyzeStatus: "success",
          analysis: response.analysis,
          evidence: response.evidence,
          analyzeError: null,
          lastUpdated: new Date().toISOString(),
        }),

      analyzeFailure: (message) =>
        set({
          analyzeStatus: "error",
          analysis: null,
          evidence: null,
          analyzeError: message,
        }),

      clearInvestigation: () => set({ ...INITIAL_PERSISTED_STATE }),
    }),
    {
      name: STORAGE_KEY,
      version: STORAGE_VERSION,
      storage: safeStorage,
      partialize: (state): PersistedShape => ({
        jsonInput: state.jsonInput,
        classifyStatus: state.classifyStatus,
        classification: state.classification,
        lastClassifiedFeatures: state.lastClassifiedFeatures,
        classifyError: state.classifyError,
        analyzeStatus: state.analyzeStatus,
        analysis: state.analysis,
        evidence: state.evidence,
        analyzeError: state.analyzeError,
        lastUpdated: state.lastUpdated,
      }),
      // A page reload can never resume an in-flight request -- any "loading" status
      // restored from a previous session is dead and must fall back to idle, or the
      // UI would show a permanent, unrecoverable spinner.
      merge: (persisted, current) => {
        if (!isPersistedShape(persisted)) return current;
        return {
          ...current,
          ...persisted,
          classifyStatus: persisted.classifyStatus === "loading" ? "idle" : persisted.classifyStatus,
          analyzeStatus: persisted.analyzeStatus === "loading" ? "idle" : persisted.analyzeStatus,
        };
      },
    },
  ),
);

/** True once a classification exists in the store -- used by the Dashboard's "Recent
 * Investigation" card and to decide whether "Clear Investigation" has anything to do. */
export function selectHasInvestigation(state: NetworkDetectionState): boolean {
  return state.classification !== null;
}
