import { RotateCcw } from "lucide-react";

import { AnalysisResult } from "../components/analysis/AnalysisResult";
import { ErrorState } from "../components/analysis/ErrorState";
import { LoadingState } from "../components/analysis/LoadingState";
import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";
import type { PipelineStage, StageState } from "../components/common/PipelineStages";
import { PipelineStages } from "../components/common/PipelineStages";
import { DetectionResultCard } from "../components/detection/DetectionResultCard";
import { JsonEditor } from "../components/detection/JsonEditor";
import { analyzeClassification, ApiError, classifyTraffic } from "../services/api";
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

export function NetworkDetectionPage() {
  const {
    jsonInput,
    classifyStatus,
    classification,
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

  // Controls the "Clear Investigation" button -- there's a draft or a result to
  // discard even before a classification has actually run.
  const hasSomethingToClear = classification !== null || classifyStatus === "error" || jsonInput.trim().length > 0;
  // Controls the Investigation Timeline -- only shown once an actual classify
  // attempt has happened (success or error), never just because the user is typing.
  const hasRunInvestigation = classifyStatus !== "idle";

  async function handleClassify() {
    let parsed: NetworkTrafficFeatures;
    try {
      parsed = JSON.parse(jsonInput);
    } catch {
      classifyFailure("That isn't valid JSON. Check for a trailing comma or missing quote.");
      return;
    }

    startClassify();
    try {
      const result = await classifyTraffic(parsed);
      classifySuccess(result);
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

  const stages = buildStages({ classifyStatus, classification, analyzeStatus });

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
                onClick={clearInvestigation}
                className="flex items-center gap-1.5 rounded border border-border-strong px-2.5 py-1 text-[11px] font-medium text-text-muted transition-colors hover:border-malicious/50 hover:text-malicious-strong"
              >
                <RotateCcw className="h-3 w-3" strokeWidth={1.75} />
                Clear Investigation
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

        {analyzeStatus === "loading" && <LoadingState />}
        {analyzeStatus === "error" && analyzeError && <ErrorState message={analyzeError} />}
        {analyzeStatus === "success" && analysis && <AnalysisResult result={analysis} evidence={evidence} />}
      </div>
    </div>
  );
}
