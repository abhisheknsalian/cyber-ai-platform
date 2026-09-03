import { ArrowRight, ShieldAlert, ShieldCheck } from "lucide-react";

import type { ClassificationResult } from "../../types/ml";
import { Card } from "../common/Card";
import { ConfidenceBar } from "../common/ConfidenceBar";
import { StatusPill } from "../common/StatusPill";

interface DetectionResultCardProps {
  result: ClassificationResult;
  onAnalyze: () => void;
  analyzing: boolean;
  analyzed: boolean;
}

export function DetectionResultCard({ result, onAnalyze, analyzing, analyzed }: DetectionResultCardProps) {
  const malicious = result.classification === "malicious";

  return (
    <Card glow={malicious ? "malicious" : "benign"} className="p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          {malicious ? (
            <ShieldAlert className="h-5 w-5 text-malicious-strong" strokeWidth={1.75} />
          ) : (
            <ShieldCheck className="h-5 w-5 text-benign-strong" strokeWidth={1.75} />
          )}
          <span className="text-xs font-semibold uppercase tracking-[0.2em] text-text-muted">
            {malicious ? "Threat Detected" : "No Threat Detected"}
          </span>
        </div>
        <StatusPill ok={!malicious} onLabel="Benign" offLabel="Malicious" pulse={malicious} />
      </div>

      <p
        className={`mt-4 font-mono text-2xl font-bold uppercase tracking-wide ${
          malicious ? "text-malicious-strong" : "text-benign-strong"
        }`}
      >
        {result.prediction}
      </p>

      {result.probability !== null ? (
        <div className="mt-5 max-w-sm">
          <ConfidenceBar value={result.probability} tone={malicious ? "malicious" : "benign"} />
        </div>
      ) : null}

      {result.class_probabilities ? (
        <div className="mt-4 flex flex-wrap gap-2">
          {Object.entries(result.class_probabilities).map(([label, probability]) => (
            <span
              key={label}
              className="rounded border border-border-strong bg-surface-hover px-2 py-1 font-mono text-[11px] text-text-muted"
            >
              {label} <span className="text-text">{(probability * 100).toFixed(1)}%</span>
            </span>
          ))}
        </div>
      ) : null}

      <div className="mt-5 grid grid-cols-2 gap-4 border-t border-border pt-4 sm:grid-cols-3">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wide text-text-muted">Model</p>
          <p className="mt-1 font-mono text-sm text-text">{result.model.replace(/_/g, " ")}</p>
        </div>
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wide text-text-muted">Status</p>
          <p
            className={`mt-1 font-mono text-sm font-semibold uppercase ${
              malicious ? "text-malicious-strong" : "text-benign-strong"
            }`}
          >
            {result.classification}
          </p>
        </div>
        {result.model_version ? (
          <div>
            <p className="text-[11px] font-medium uppercase tracking-wide text-text-muted">Trained</p>
            <p className="mt-1 font-mono text-xs text-text">{result.model_version}</p>
          </div>
        ) : null}
      </div>

      {malicious ? (
        <div className="mt-5">
          <button
            type="button"
            onClick={onAnalyze}
            disabled={analyzing}
            className="flex items-center gap-2 rounded-md bg-accent px-4 py-2.5 text-sm font-semibold text-surface transition-colors hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
          >
            {analyzing ? "Analyzing…" : analyzed ? "Re-analyze Threat" : "Analyze Threat"}
            <ArrowRight className="h-4 w-4" strokeWidth={2} />
          </button>
        </div>
      ) : null}
    </Card>
  );
}
