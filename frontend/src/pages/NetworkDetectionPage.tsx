import { ShieldCheck } from "lucide-react";
import { useState } from "react";

import { AnalysisResult } from "../components/analysis/AnalysisResult";
import { ErrorState } from "../components/analysis/ErrorState";
import { LoadingState } from "../components/analysis/LoadingState";
import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";
import { StatusPill } from "../components/common/StatusPill";
import { analyzeClassification, ApiError, classifyTraffic } from "../services/api";
import { FEATURE_COLUMNS } from "../types/ml";
import type {
  ClassificationAnalysisResponse,
  ClassificationResult as ClassificationResultType,
  NetworkTrafficFeatures,
} from "../types/ml";

type ClassifyState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; result: ClassificationResultType }
  | { status: "error"; message: string };

type AnalyzeState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; result: ClassificationAnalysisResponse }
  | { status: "error"; message: string };

function buildExamplePayload(): string {
  const example = Object.fromEntries(FEATURE_COLUMNS.map((column) => [column, 0]));
  return JSON.stringify(example, null, 2);
}

export function NetworkDetectionPage() {
  const [jsonInput, setJsonInput] = useState("");
  const [classifyState, setClassifyState] = useState<ClassifyState>({ status: "idle" });
  const [analyzeState, setAnalyzeState] = useState<AnalyzeState>({ status: "idle" });

  async function handleClassify() {
    setAnalyzeState({ status: "idle" });

    let parsed: NetworkTrafficFeatures;
    try {
      parsed = JSON.parse(jsonInput);
    } catch {
      setClassifyState({
        status: "error",
        message: "That isn't valid JSON. Check for a trailing comma or missing quote.",
      });
      return;
    }

    setClassifyState({ status: "loading" });
    try {
      const result = await classifyTraffic(parsed);
      setClassifyState({ status: "success", result });
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "An unexpected error occurred.";
      setClassifyState({ status: "error", message });
    }
  }

  async function handleAnalyze() {
    if (classifyState.status !== "success") return;

    setAnalyzeState({ status: "loading" });
    try {
      const result = await analyzeClassification({
        prediction: classifyState.result.prediction,
        probability: classifyState.result.probability,
      });
      setAnalyzeState({ status: "success", result });
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "An unexpected error occurred.";
      setAnalyzeState({ status: "error", message });
    }
  }

  return (
    <div>
      <PageHeader
        title="Network Traffic Detection"
        description="CICIDS2017-based DDoS traffic classifier (Random Forest). Scores a single, already-extracted CICFlowMeter feature vector offline -- this is not live network monitoring."
      />

      <Card className="p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs font-medium uppercase tracking-wide text-text-muted">
            Network flow features (JSON)
          </p>
          <button
            type="button"
            onClick={() => setJsonInput(buildExamplePayload())}
            className="text-xs text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent"
          >
            Fill example shape (all zeros)
          </button>
        </div>
        <textarea
          value={jsonInput}
          onChange={(event) => setJsonInput(event.target.value)}
          placeholder={'{ "Destination Port": 80, "Flow Duration": 1234, ... }'}
          rows={10}
          spellCheck={false}
          className="w-full rounded-md border border-border-strong bg-surface px-4 py-3 font-mono text-xs text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
        />
        <div className="mt-3 flex justify-end">
          <button
            type="button"
            onClick={handleClassify}
            disabled={classifyState.status === "loading" || jsonInput.trim().length === 0}
            className="rounded-md bg-accent px-5 py-2.5 text-sm font-semibold text-surface transition-colors hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
          >
            Classify
          </button>
        </div>
      </Card>

      <div className="mt-6 space-y-6">
        {classifyState.status === "loading" && <LoadingState />}
        {classifyState.status === "error" && <ErrorState message={classifyState.message} />}

        {classifyState.status === "success" && (
          <Card className="p-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="h-5 w-5 text-accent" strokeWidth={1.75} />
                <span className="font-mono text-lg font-semibold uppercase tracking-wide text-text">
                  {classifyState.result.prediction}
                </span>
              </div>
              <StatusPill
                ok={classifyState.result.classification === "benign"}
                onLabel="Benign"
                offLabel="Malicious"
              />
            </div>

            <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-3">
              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-text-muted">Probability</p>
                <p className="mt-1 font-mono text-sm text-text">
                  {classifyState.result.probability !== null
                    ? `${(classifyState.result.probability * 100).toFixed(1)}%`
                    : "n/a"}
                </p>
              </div>
              <div>
                <p className="text-xs font-medium uppercase tracking-wide text-text-muted">Model</p>
                <p className="mt-1 font-mono text-sm text-text">{classifyState.result.model}</p>
              </div>
            </div>

            <div className="mt-5">
              <button
                type="button"
                onClick={handleAnalyze}
                disabled={analyzeState.status === "loading"}
                className="rounded-md border border-border-strong bg-surface-hover px-4 py-2 text-sm font-medium text-text transition-colors hover:border-accent/50 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Analyze Threat
              </button>
            </div>
          </Card>
        )}

        {analyzeState.status === "loading" && <LoadingState />}
        {analyzeState.status === "error" && <ErrorState message={analyzeState.message} />}

        {analyzeState.status === "success" && analyzeState.result.analysis === null && (
          <Card className="flex flex-col items-center gap-3 p-10 text-center">
            <ShieldCheck className="h-8 w-8 text-emerald-400" strokeWidth={1.5} />
            <div>
              <p className="text-sm font-medium text-text">No threat detected</p>
              <p className="mt-1.5 text-sm text-text-muted">
                Traffic was classified as BENIGN -- there is no threat to analyze.
              </p>
            </div>
          </Card>
        )}

        {analyzeState.status === "success" && analyzeState.result.analysis !== null && (
          <AnalysisResult result={analyzeState.result.analysis} />
        )}
      </div>
    </div>
  );
}
