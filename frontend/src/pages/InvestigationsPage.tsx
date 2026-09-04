import { ArrowLeft, ChevronLeft, ChevronRight, History, Radar } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { AnalysisResult } from "../components/analysis/AnalysisResult";
import { ErrorState } from "../components/analysis/ErrorState";
import { LoadingState } from "../components/analysis/LoadingState";
import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";
import { StatusPill } from "../components/common/StatusPill";
import { useAuth } from "../context/AuthContext";
import { useInvestigationHistoryStore } from "../store/investigationHistoryStore";
import type { StoredClassificationResult } from "../types/investigations";

const PAGE_SIZE = 20;

function formatTimestamp(value: string): string {
  return new Date(value).toLocaleString();
}

function ClassificationTimelineEntry({ result }: { result: StoredClassificationResult }) {
  const malicious = result.classification === "malicious";
  return (
    <Card glow={malicious ? "malicious" : "benign"} className="p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className={`font-mono text-sm font-bold uppercase tracking-wide ${
              malicious ? "text-malicious-strong" : "text-benign-strong"
            }`}
          >
            {result.prediction}
          </span>
          {result.probability !== null ? (
            <span className="font-mono text-[11px] text-text-muted">{(result.probability * 100).toFixed(1)}%</span>
          ) : null}
        </div>
        <span className="font-mono text-[11px] text-text-faint">{formatTimestamp(result.created_at)}</span>
      </div>

      {result.analysis_result ? (
        <div className="mt-4">
          <AnalysisResult result={{ ...result.analysis_result, query: "" }} evidence={result.analysis_result.evidence} />
        </div>
      ) : (
        <p className="mt-2 font-mono text-[11px] text-text-faint">
          {malicious ? "Not analyzed." : "No analysis needed for benign traffic."}
        </p>
      )}
    </Card>
  );
}

export function InvestigationsPage() {
  const { authenticated, userId } = useAuth();
  const canView = authenticated && userId !== null && userId !== "demo";

  const {
    investigations,
    total,
    historyStatus,
    historyError,
    selectedInvestigation,
    detailStatus,
    detailError,
    loadHistory,
    selectInvestigation,
    clearSelection,
  } = useInvestigationHistoryStore();

  const [offset, setOffset] = useState(0);

  useEffect(() => {
    if (canView) loadHistory(PAGE_SIZE, offset);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canView, offset]);

  if (!canView) {
    return (
      <div>
        <PageHeader
          eyebrow="Saved Investigations"
          title="Investigations"
          description="Persistent, per-account history of Network Detection classifications and their AI analysis."
        />
        <Card className="p-6 text-sm text-text-muted">
          Persistent investigations require a registered account. Demo sessions are not saved -- create an account
          from the login page to start building investigation history.
        </Card>
      </div>
    );
  }

  if (selectedInvestigation) {
    return (
      <div>
        <PageHeader
          eyebrow="Saved Investigation"
          title={selectedInvestigation.label ?? `Investigation #${selectedInvestigation.id}`}
          description={`Created ${formatTimestamp(selectedInvestigation.created_at)} · Last updated ${formatTimestamp(
            selectedInvestigation.updated_at,
          )}`}
          status={
            <button
              type="button"
              onClick={clearSelection}
              className="flex items-center gap-1.5 rounded border border-border-strong px-2.5 py-1 text-[11px] font-medium text-text-muted transition-colors hover:border-accent/50 hover:text-text"
            >
              <ArrowLeft className="h-3 w-3" strokeWidth={1.75} />
              Back to Investigations
            </button>
          }
        />

        {detailStatus === "loading" && <LoadingState />}
        {detailStatus === "error" && detailError && <ErrorState message={detailError} />}

        <div className="space-y-4">
          {selectedInvestigation.classification_results.length === 0 ? (
            <Card className="p-6 text-sm text-text-faint">This investigation has no classification results.</Card>
          ) : (
            selectedInvestigation.classification_results.map((result) => (
              <ClassificationTimelineEntry key={result.id} result={result} />
            ))
          )}
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        eyebrow="Saved Investigations"
        title="Investigations"
        description="Persistent, per-account history of Network Detection classifications and their AI analysis."
      />

      {historyStatus === "loading" && <LoadingState />}
      {historyStatus === "error" && historyError && <ErrorState message={historyError} />}

      {historyStatus === "success" && investigations.length === 0 ? (
        <Card className="p-6">
          <div className="flex items-center gap-2 text-text-muted">
            <History className="h-4 w-4" strokeWidth={1.75} />
            <span className="text-xs font-medium uppercase tracking-wide">No investigations yet</span>
          </div>
          <p className="mt-3 text-sm text-text-faint">
            Classify a network flow on Network Detection and save it to see it here.
          </p>
          <Link
            to="/detection"
            className="mt-4 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline"
          >
            <Radar className="h-3.5 w-3.5" strokeWidth={1.75} />
            Open Network Detection
          </Link>
        </Card>
      ) : (
        <div className="space-y-3">
          {investigations.map((investigation) => {
            const latest = investigation.latest_classification;
            const malicious = latest?.classification === "malicious";
            return (
              <button
                key={investigation.id}
                type="button"
                onClick={() => selectInvestigation(investigation.id)}
                className="block w-full text-left"
              >
                <Card
                  glow={latest ? (malicious ? "malicious" : "benign") : "none"}
                  className="flex flex-wrap items-center justify-between gap-3 p-4 transition-transform duration-150 hover:-translate-y-0.5"
                >
                  <div>
                    <p className="text-sm font-medium text-text">
                      {investigation.label ?? `Investigation #${investigation.id}`}
                    </p>
                    <p className="mt-1 font-mono text-[11px] text-text-faint">
                      Updated {formatTimestamp(investigation.updated_at)}
                    </p>
                  </div>
                  {latest ? (
                    <div className="flex items-center gap-3">
                      <span
                        className={`font-mono text-sm font-bold uppercase tracking-wide ${
                          malicious ? "text-malicious-strong" : "text-benign-strong"
                        }`}
                      >
                        {latest.prediction}
                      </span>
                      {latest.probability !== null ? (
                        <span className="font-mono text-[11px] text-text-muted">
                          {(latest.probability * 100).toFixed(1)}%
                        </span>
                      ) : null}
                      <StatusPill ok={!malicious} onLabel="Benign" offLabel="Malicious" />
                    </div>
                  ) : (
                    <span className="font-mono text-[11px] text-text-faint">No classification yet</span>
                  )}
                </Card>
              </button>
            );
          })}
        </div>
      )}

      {total > PAGE_SIZE ? (
        <div className="mt-4 flex items-center justify-between">
          <button
            type="button"
            onClick={() => setOffset((value) => Math.max(0, value - PAGE_SIZE))}
            disabled={offset === 0}
            className="flex items-center gap-1 rounded-md border border-border-strong px-3 py-1.5 text-xs text-text-muted transition-colors hover:border-accent/50 hover:text-text disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft className="h-3.5 w-3.5" strokeWidth={1.75} />
            Previous
          </button>
          <span className="font-mono text-[11px] text-text-faint">
            {offset + 1}-{Math.min(offset + PAGE_SIZE, total)} of {total}
          </span>
          <button
            type="button"
            onClick={() => setOffset((value) => value + PAGE_SIZE)}
            disabled={offset + PAGE_SIZE >= total}
            className="flex items-center gap-1 rounded-md border border-border-strong px-3 py-1.5 text-xs text-text-muted transition-colors hover:border-accent/50 hover:text-text disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
            <ChevronRight className="h-3.5 w-3.5" strokeWidth={1.75} />
          </button>
        </div>
      ) : null}
    </div>
  );
}
