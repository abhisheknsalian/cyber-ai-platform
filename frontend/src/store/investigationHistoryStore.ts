import { create } from "zustand";

import {
  ApiError,
  createInvestigation,
  getInvestigation,
  listInvestigations,
  saveAnalysisResult,
  saveClassificationResult,
} from "../services/api";
import type { ThreatAnalysis } from "../types/api";
import type { HybridEvidence } from "../types/intelligence";
import type { InvestigationDetail, InvestigationSummary } from "../types/investigations";
import type { ClassificationResult, NetworkTrafficFeatures } from "../types/ml";

export type LoadStatus = "idle" | "loading" | "success" | "error";
export type SaveStatus = "idle" | "saving" | "saved" | "error";

interface SaveCurrentParams {
  label?: string | null;
  features: NetworkTrafficFeatures;
  classification: ClassificationResult;
  /** Pass only once an analysis actually exists for the current classification --
   * omit (or null) while only a classification has been run. */
  analysis?: ThreatAnalysis | null;
  evidence?: HybridEvidence | null;
}

interface InvestigationHistoryState {
  investigations: InvestigationSummary[];
  total: number;
  historyStatus: LoadStatus;
  historyError: string | null;

  selectedInvestigation: InvestigationDetail | null;
  detailStatus: LoadStatus;
  detailError: string | null;

  saveStatus: SaveStatus;
  saveError: string | null;
  /** The server ids behind whatever's currently displayed on Network Detection, once
   * saved -- null until the corresponding "Save" step has actually happened. Kept
   * separate (not derived) so saveCurrent() can tell exactly what still needs saving
   * without re-POSTing anything already persisted -- see markNewClassification()
   * vs. resetActiveInvestigation() below for the two different reset scopes. */
  activeInvestigationId: number | null;
  activeClassificationResultId: number | null;
  activeAnalysisSaved: boolean;

  loadHistory: (limit?: number, offset?: number) => Promise<void>;
  selectInvestigation: (id: number) => Promise<void>;
  clearSelection: () => void;
  saveCurrent: (params: SaveCurrentParams) => Promise<void>;
  /** Call when a NEW classification has just been run within the same investigation
   * (re-running /classify without starting a fresh investigation) -- clears only the
   * classification/analysis save state, keeping activeInvestigationId so the next
   * save adds another classification_result to the SAME investigation, matching the
   * 1:N investigations->classification_results design. */
  markNewClassification: () => void;
  /** Call from "New Investigation" -- clears everything, including
   * activeInvestigationId, so the next save creates a brand new investigation. */
  resetActiveInvestigation: () => void;
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "An unexpected error occurred.";
}

export const useInvestigationHistoryStore = create<InvestigationHistoryState>()((set, get) => ({
  investigations: [],
  total: 0,
  historyStatus: "idle",
  historyError: null,

  selectedInvestigation: null,
  detailStatus: "idle",
  detailError: null,

  saveStatus: "idle",
  saveError: null,
  activeInvestigationId: null,
  activeClassificationResultId: null,
  activeAnalysisSaved: false,

  async loadHistory(limit = 20, offset = 0) {
    set({ historyStatus: "loading", historyError: null });
    try {
      const response = await listInvestigations(limit, offset);
      set({ historyStatus: "success", investigations: response.items, total: response.total });
    } catch (error) {
      set({ historyStatus: "error", historyError: errorMessage(error) });
    }
  },

  async selectInvestigation(id) {
    set({ detailStatus: "loading", detailError: null });
    try {
      const detail = await getInvestigation(id);
      set({ detailStatus: "success", selectedInvestigation: detail });
    } catch (error) {
      set({ detailStatus: "error", detailError: errorMessage(error), selectedInvestigation: null });
    }
  },

  clearSelection() {
    set({ selectedInvestigation: null, detailStatus: "idle", detailError: null });
  },

  async saveCurrent({ label, features, classification, analysis, evidence }) {
    set({ saveStatus: "saving", saveError: null });
    try {
      let investigationId = get().activeInvestigationId;
      if (investigationId === null) {
        const created = await createInvestigation({ label: label ?? null });
        investigationId = created.id;
        set({ activeInvestigationId: investigationId });
      }

      let classificationResultId = get().activeClassificationResultId;
      if (classificationResultId === null) {
        const stored = await saveClassificationResult(investigationId, { features, result: classification });
        classificationResultId = stored.id;
        set({ activeClassificationResultId: classificationResultId });
      }

      if (analysis && !get().activeAnalysisSaved) {
        await saveAnalysisResult(investigationId, classificationResultId, {
          analysis,
          evidence: evidence ?? null,
        });
        set({ activeAnalysisSaved: true });
      }

      set({ saveStatus: "saved" });
    } catch (error) {
      set({ saveStatus: "error", saveError: errorMessage(error) });
    }
  },

  markNewClassification() {
    set({
      activeClassificationResultId: null,
      activeAnalysisSaved: false,
      saveStatus: "idle",
      saveError: null,
    });
  },

  resetActiveInvestigation() {
    set({
      activeInvestigationId: null,
      activeClassificationResultId: null,
      activeAnalysisSaved: false,
      saveStatus: "idle",
      saveError: null,
    });
  },
}));
