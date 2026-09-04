import { ArrowRight, Radar } from "lucide-react";
import { useEffect } from "react";
import { Link } from "react-router-dom";

import { useAuth } from "../../context/AuthContext";
import { useInvestigationHistoryStore } from "../../store/investigationHistoryStore";
import { useNetworkDetectionStore } from "../../store/networkDetectionStore";
import { Card } from "../common/Card";
import { StatusPill } from "../common/StatusPill";

function EmptyState({ linkTo, linkLabel }: { linkTo: string; linkLabel: string }) {
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 text-text-muted">
        <Radar className="h-4 w-4" strokeWidth={1.75} />
        <span className="text-xs font-medium uppercase tracking-wide">Recent Investigation</span>
      </div>
      <p className="mt-3 text-sm text-text-faint">
        No investigation yet. Classify a network flow on Network Detection to see it here.
      </p>
      <Link to={linkTo} className="mt-4 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline">
        {linkLabel}
        <ArrowRight className="h-3 w-3" strokeWidth={2} />
      </Link>
    </Card>
  );
}

/** For a registered (non-demo) user: the most recently updated PERSISTED
 * investigation -- real server data, never fabricated. Demo/unauthenticated
 * sessions can't persist investigations at all (backend/security.py::require_user_id
 * rejects them), so they keep the original Phase-6 behavior below: reading the local,
 * unsaved draft straight from networkDetectionStore. */
function PersistedRecentInvestigation() {
  const { investigations, historyStatus, loadHistory } = useInvestigationHistoryStore();

  useEffect(() => {
    loadHistory(1, 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (historyStatus === "loading" || historyStatus === "idle") {
    return (
      <Card className="p-5">
        <div className="h-20 animate-pulse rounded bg-surface-hover" />
      </Card>
    );
  }

  const latestInvestigation = investigations[0];
  const latest = latestInvestigation?.latest_classification;

  if (!latestInvestigation || !latest) {
    return <EmptyState linkTo="/detection" linkLabel="Open Network Detection" />;
  }

  const malicious = latest.classification === "malicious";

  return (
    <Link to="/investigations" className="block focus-visible:outline-none">
      <Card
        glow={malicious ? "malicious" : "benign"}
        className="p-5 transition-transform duration-150 hover:-translate-y-0.5"
      >
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-text-muted">
            <Radar className="h-4 w-4" strokeWidth={1.75} />
            <span className="text-xs font-medium uppercase tracking-wide">Recent Investigation</span>
          </div>
          <StatusPill ok={!malicious} onLabel="Benign" offLabel="Malicious" />
        </div>

        <p
          className={`mt-3 font-mono text-xl font-bold uppercase tracking-wide ${
            malicious ? "text-malicious-strong" : "text-benign-strong"
          }`}
        >
          {latest.prediction}
        </p>

        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
          {latest.probability !== null ? <span>{(latest.probability * 100).toFixed(1)}% confidence</span> : null}
          <span>{latestInvestigation.label ?? `Investigation #${latestInvestigation.id}`}</span>
        </div>

        <p className="mt-3 font-mono text-[11px] text-text-faint">
          {new Date(latestInvestigation.updated_at).toLocaleString()}
        </p>
      </Card>
    </Link>
  );
}

/** Original (Phase 6) behavior: reads the unsaved local draft directly -- never a
 * fetch, never fabricated history. Used for demo sessions, which cannot persist
 * investigations at all. */
function DraftRecentInvestigation() {
  const classification = useNetworkDetectionStore((state) => state.classification);
  const analyzeStatus = useNetworkDetectionStore((state) => state.analyzeStatus);
  const analysis = useNetworkDetectionStore((state) => state.analysis);
  const lastUpdated = useNetworkDetectionStore((state) => state.lastUpdated);

  if (!classification) {
    return <EmptyState linkTo="/detection" linkLabel="Open Network Detection" />;
  }

  const malicious = classification.classification === "malicious";
  const analyzedLabel = analyzeStatus === "success" && analysis ? "Analyzed" : malicious ? "Not yet analyzed" : "No analysis needed";

  return (
    <Link to="/detection" className="block focus-visible:outline-none">
      <Card
        glow={malicious ? "malicious" : "benign"}
        className="p-5 transition-transform duration-150 hover:-translate-y-0.5"
      >
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-text-muted">
            <Radar className="h-4 w-4" strokeWidth={1.75} />
            <span className="text-xs font-medium uppercase tracking-wide">Recent Investigation</span>
          </div>
          <StatusPill ok={!malicious} onLabel="Benign" offLabel="Malicious" />
        </div>

        <p
          className={`mt-3 font-mono text-xl font-bold uppercase tracking-wide ${
            malicious ? "text-malicious-strong" : "text-benign-strong"
          }`}
        >
          {classification.prediction}
        </p>

        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-muted">
          {classification.probability !== null ? <span>{(classification.probability * 100).toFixed(1)}% confidence</span> : null}
          <span className="font-mono">{classification.model.replace(/_/g, " ")}</span>
          <span>{analyzedLabel}</span>
        </div>

        {lastUpdated ? <p className="mt-3 font-mono text-[11px] text-text-faint">{new Date(lastUpdated).toLocaleString()}</p> : null}
      </Card>
    </Link>
  );
}

export function RecentInvestigationCard() {
  const { authenticated, userId } = useAuth();
  const canPersist = authenticated && userId !== null && userId !== "demo";

  return canPersist ? <PersistedRecentInvestigation /> : <DraftRecentInvestigation />;
}
