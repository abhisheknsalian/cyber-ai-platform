import { RotateCcw, Save } from "lucide-react";

import { AnalysisResult } from "../components/analysis/AnalysisResult";
import { ErrorState } from "../components/analysis/ErrorState";
import { LoadingState } from "../components/analysis/LoadingState";
import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";
import type { PipelineStage, StageState } from "../components/common/PipelineStages";
import { PipelineStages } from "../components/common/PipelineStages";
import { DetectionResultCard } from "../components/detection/DetectionResultCard";
import { JsonEditor } from "../components/detection/JsonEditor";
import { useAuth } from "../context/AuthContext";
import { analyzeClassification, ApiError, classifyTraffic } from "../services/api";
import { useInvestigationHistoryStore } from "../store/investigationHistoryStore";
import type { RequestStatus } from "../store/networkDetectionStore";
import { useNetworkDetectionStore } from "../store/networkDetectionStore";
import { FEATURE_COLUMNS } from "../types/ml";
import type { NetworkTrafficFeatures } from "../types/ml";

function buildExamplePayload(): string {
  const example = Object.fromEntries(FEATURE_COLUMNS.map((column) => [column, 0]));
  return JSON.stringify(example, null, 2);
}

function toStageState(status: RequestStatus): StageState {
  if (status === "loading") return "processing";
  if (status === "success") return "complete";
  if (status === "error") return "error";
  return "idle";
}

function buildStages(params: {
  classifyStatus: RequestStatus;
  classification: { classification: "malicious" | "benign" } | null;
  analyzeStatus: RequestStatus;
}): PipelineStage[] {
  const { classifyStatus, classification, analyzeStatus } = params;

  const stages: PipelineStage[] = [
    {
      id: "received",
      label: "Flow Received",
      state: classifyStatus === "idle" ? "idle" : classifyStatus === "error" ? "error" : "complete",
    },
    { id: "rf", label: "Random Forest", state: toStageState(classifyStatus) },
    {
      id: "classified",
      label: "Threat Classified",
      state: classification !== null ? "complete" : classifyStatus === "error" ? "error" : "idle",
    },
  ];

  if (classification?.classification === "malicious") {
    const phase = toStageState(analyzeStatus);
    stages.push(
      { id: "rag", label: "RAG Retrieval", state: phase },
      { id: "graph", label: "Threat Graph", state: phase },
      { id: "llm", label: "Llama Analysis", state: phase },
      { id: "report", label: "Threat Report", state: phase },
    );
  }

  return stages;
}

/** Investigation persistence is session-user-only on the backend (see
 * backend/security.py::require_user_id) -- demo sessions and unauthenticated
 * requests are structurally unable to own a row, so "Save" is hidden rather than
 * shown-then-failing for those cases. */
function canPersistInvestigations(authenticated: boolean, userId: string | null): boolean {
  return authenticated && userId !== null && userId !== "demo";
}

function saveButtonLabel(params: {
  saveStatus: string;
  classificationSaved: boolean;
  hasAnalysis: boolean;
  analysisSaved: boolean;
}): string {
  const { saveStatus, classificationSaved, hasAnalysis, analysisSaved } = params;
  if (saveStatus === "saving") return "Saving…";
  if (!classificationSaved) return "Save Investigation";
  if (hasAnalysis && !analysisSaved) return "Save Analysis";
  return "Saved";
}

export function NetworkDetectionPage() {
  const { authenticated, userId } = useAuth();
  const {
    jsonInput,
    classifyStatus,
    classification,
    lastClassifiedFeatures,
    classifyError,
    analyzeStatus,
    analysis,
    evidence,
    analyzeError,
    setJsonInput,
    startClassify,
    classifySuccess,
    classifyFailure,
    startAnalyze,
    analyzeSuccess,
    analyzeFailure,
    clearInvestigation,
  } = useNetworkDetectionStore();
  const {
    saveStatus,
    saveError,
    activeClassificationResultId,
    activeAnalysisSaved,
    saveCurrent,
    markNewClassification,
    resetActiveInvestigation,
  } = useInvestigationHistoryStore();

  // Controls the "Clear Investigation" button -- there's a draft or a result to
  // discard even before a classification has actually run.
  const hasSomethingToClear = classification !== null || classifyStatus === "error" || jsonInput.trim().length > 0;
  // Controls the Investigation Timeline -- only shown once an actual classify
  // attempt has happened (success or error), never just because the user is typing.
  const hasRunInvestigation = classifyStatus !== "idle";
  const canSave = canPersistInvestigations(authenticated, userId);

  async function handleClassify() {
    let parsed: NetworkTrafficFeatures;
    try {
      parsed = JSON.parse(jsonInput);
    } catch {
      classifyFailure("That isn't valid JSON. Check for a trailing comma or missing quote.");
      return;
    }

    startClassify();
    // A new classification result is unsaved until "Save Investigation" is clicked
    // again -- but stays part of the SAME investigation (if one is already open) so
    // re-classifying within a session adds another classification_result to it,
    // rather than starting a new investigation every time.
    markNewClassification();
    try {
      const result = await classifyTraffic(parsed);
      classifySuccess(result, parsed);
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "An unexpected error occurred.";
      classifyFailure(message);
    }
  }

  async function handleAnalyze() {
    if (classification === null) return;

    startAnalyze();
    try {
      const result = await analyzeClassification({
        prediction: classification.prediction,
        probability: classification.probability,
      });
      analyzeSuccess(result);
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "An unexpected error occurred.";
      analyzeFailure(message);
    }
  }

  async function handleSaveInvestigation() {
    // Loose nullish check (not `=== null`): a classification result persisted by an
    // older build of this app (before lastClassifiedFeatures existed in
    // networkDetectionStore's persisted shape) would restore with this field
    // `undefined`, not `null` -- both mean "nothing safe to save yet".
    if (classification === null || lastClassifiedFeatures == null) return;
    await saveCurrent({
      features: lastClassifiedFeatures,
      classification,
      analysis: analyzeStatus === "success" ? analysis : null,
      evidence: analyzeStatus === "success" ? evidence : null,
    });
  }

  function handleClearInvestigation() {
    clearInvestigation();
    resetActiveInvestigation();
  }

  const stages = buildStages({ classifyStatus, classification, analyzeStatus });
  const hasAnalysis = analyzeStatus === "success" && analysis !== null;
  const saveDisabled =
    saveStatus === "saving" || (activeClassificationResultId !== null && (!hasAnalysis || activeAnalysisSaved));

  return (
    <div>
      <PageHeader
        eyebrow="CICIDS2017 / CICFlowMeter · Random Forest Classifier"
        title="Network Traffic Detection"
        description="Scores a single, already-extracted 78-feature CICFlowMeter flow vector offline against a trained Random Forest model. This is not live packet capture or real-time network monitoring."
        status={
          <div className="flex items-center gap-2">
            <span className="rounded border border-border-strong bg-surface-hover px-2.5 py-1 font-mono text-[11px] uppercase tracking-wide text-text-muted">
              Offline Flow Analysis
            </span>
            {hasSomethingToClear ? (
              <button
                type="button"
                onClick={handleClearInvestigation}
                className="flex items-center gap-1.5 rounded border border-border-strong px-2.5 py-1 text-[11px] font-medium text-text-muted transition-colors hover:border-malicious/50 hover:text-malicious-strong"
              >
                <RotateCcw className="h-3 w-3" strokeWidth={1.75} />
                New Investigation
              </button>
            ) : null}
          </div>
        }
      />

      <Card className="p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs font-medium uppercase tracking-wide text-text-muted">Network Flow Input</p>
          <span className="font-mono text-[11px] uppercase tracking-wide text-text-faint">
            78 features · CICFlowMeter format
          </span>
        </div>

        <JsonEditor
          value={jsonInput}
          onChange={setJsonInput}
          placeholder={'{ "Destination Port": 80, "Flow Duration": 1234, ... }'}
          ariaLabel="Network flow features JSON"
          disabled={classifyStatus === "loading"}
        />

        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setJsonInput(buildExamplePayload())}
              className="rounded-md border border-border-strong px-3 py-2 text-xs font-medium text-text-muted transition-colors hover:border-accent/50 hover:text-text"
            >
              Load Example
            </button>
            <button
              type="button"
              onClick={() => setJsonInput("")}
              disabled={jsonInput.length === 0}
              className="rounded-md border border-border-strong px-3 py-2 text-xs font-medium text-text-muted transition-colors hover:border-border-strong hover:bg-surface-hover hover:text-text disabled:cursor-not-allowed disabled:opacity-40"
            >
              Clear
            </button>
          </div>
          <button
            type="button"
            onClick={handleClassify}
            disabled={classifyStatus === "loading" || jsonInput.trim().length === 0}
            className="rounded-md bg-accent px-5 py-2.5 text-sm font-semibold text-surface transition-colors hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
          >
            {classifyStatus === "loading" ? "Classifying…" : "Classify Traffic"}
          </button>
        </div>
      </Card>

      {hasRunInvestigation ? (
        <Card className="mt-6 p-5">
          <p className="mb-4 text-xs font-semibold uppercase tracking-wide text-text-muted">Investigation Timeline</p>
          <PipelineStages stages={stages} />
        </Card>
      ) : null}

      <div className="mt-6 space-y-6">
        {classifyStatus === "loading" && <LoadingState />}
        {classifyStatus === "error" && classifyError && <ErrorState message={classifyError} />}

        {classifyStatus === "success" && classification && (
          <DetectionResultCard
            result={classification}
            onAnalyze={handleAnalyze}
            analyzing={analyzeStatus === "loading"}
            analyzed={analyzeStatus === "success"}
          />
        )}

        {classifyStatus === "success" && classification ? (
          <Card className="flex flex-wrap items-center justify-between gap-3 p-4">
            {canSave && lastClassifiedFeatures != null ? (
              <>
                <div className="text-xs text-text-muted">
                  {saveStatus === "error" && saveError
                    ? <span className="text-malicious-strong">{saveError}</span>
                    : activeClassificationResultId !== null
                      ? "This investigation is saved to your account."
                      : "Not yet saved -- only visible in this browser until you save it."}
                </div>
                <button
                  type="button"
                  onClick={handleSaveInvestigation}
                  disabled={saveDisabled}
                  className="flex items-center gap-1.5 rounded-md border border-border-strong px-3 py-2 text-xs font-medium text-text-muted transition-colors hover:border-accent/50 hover:text-text disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <Save className="h-3.5 w-3.5" strokeWidth={1.75} />
                  {saveButtonLabel({
                    saveStatus,
                    classificationSaved: activeClassificationResultId !== null,
                    hasAnalysis,
                    analysisSaved: activeAnalysisSaved,
                  })}
                </button>
              </>
            ) : canSave ? (
              <p className="font-mono text-[11px] text-text-faint">
                This result was loaded from an older session and can't be saved -- click "Classify Traffic" again to
                save it.
              </p>
            ) : (
              <p className="font-mono text-[11px] text-text-faint">
                Sign in with a registered account to save investigations. Demo sessions are not persisted.
              </p>
            )}
          </Card>
        ) : null}

        {analyzeStatus === "loading" && <LoadingState />}
        {analyzeStatus === "error" && analyzeError && <ErrorState message={analyzeError} />}
        {analyzeStatus === "success" && analysis && <AnalysisResult result={analysis} evidence={evidence} />}
      </div>
    </div>
  );
}
