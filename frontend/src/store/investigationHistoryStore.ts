import { create } from "zustand";
import { persist } from "zustand/middleware";

import {
  ApiError,
  createInvestigation,
  getInvestigation,
  listInvestigations,
  saveAnalysisResult,
  saveClassificationResult,
} from "../services/api";
import { createSafeStorage } from "./safeLocalStorage";
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

const STORAGE_KEY = "cyber-ai-active-investigation-v1";
const STORAGE_VERSION = 1;

/** The only slice of this store that needs to survive a page reload -- these three
 * fields describe "has THIS draft (networkDetectionStore.ts, persisted under its own
 * key) already been saved, and as what ids". Without persisting them alongside that
 * draft, a reload would restore the draft's classification/analysis content but lose
 * track of whether it was already saved, making "Save Investigation" create a
 * duplicate investigation on every reload (Phase: product audit P1-2).
 *
 * Deliberately NOT persisted: `investigations`/`selectedInvestigation`/history and
 * loading/error status -- those must always be re-fetched fresh from the server, per
 * the currently-authenticated user, never served stale from a previous session or a
 * previous (possibly different) user on the same browser. */
interface PersistedShape {
  activeInvestigationId: number | null;
  activeClassificationResultId: number | null;
  activeAnalysisSaved: boolean;
}

function isPersistedShape(value: unknown): value is PersistedShape {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    (candidate.activeInvestigationId === null || typeof candidate.activeInvestigationId === "number") &&
    (candidate.activeClassificationResultId === null || typeof candidate.activeClassificationResultId === "number") &&
    typeof candidate.activeAnalysisSaved === "boolean"
  );
}

const safeStorage = createSafeStorage(isPersistedShape);

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
   * vs. resetActiveInvestigation() below for the two different reset scopes.
   * Persisted (see PersistedShape above) so a page reload can't desynchronize these
   * from the also-persisted draft in networkDetectionStore.ts. */
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
  /** Call on logout (or an auth-expired 401) -- clears EVERYTHING in this store,
   * including the fetched history/selection (never leave one user's investigation
   * list or detail visible, even momentarily, to whoever is signed in next on the
   * same browser) and the persisted active-save-state above. See
   * frontend/src/context/AuthContext.tsx. */
  resetAll: () => void;
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "An unexpected error occurred.";
}

const INITIAL_STATE = {
  investigations: [] as InvestigationSummary[],
  total: 0,
  historyStatus: "idle" as LoadStatus,
  historyError: null as string | null,

  selectedInvestigation: null as InvestigationDetail | null,
  detailStatus: "idle" as LoadStatus,
  detailError: null as string | null,

  saveStatus: "idle" as SaveStatus,
  saveError: null as string | null,
  activeInvestigationId: null as number | null,
  activeClassificationResultId: null as number | null,
  activeAnalysisSaved: false,
};

export const useInvestigationHistoryStore = create<InvestigationHistoryState>()(
  persist(
    (set, get) => ({
      ...INITIAL_STATE,

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

      resetAll() {
        set({ ...INITIAL_STATE });
      },
    }),
    {
      name: STORAGE_KEY,
      version: STORAGE_VERSION,
      storage: safeStorage,
      partialize: (state): PersistedShape => ({
        activeInvestigationId: state.activeInvestigationId,
        activeClassificationResultId: state.activeClassificationResultId,
        activeAnalysisSaved: state.activeAnalysisSaved,
      }),
      merge: (persisted, current) => {
        if (!isPersistedShape(persisted)) return current;
        return { ...current, ...persisted };
      },
    },
  ),
);
