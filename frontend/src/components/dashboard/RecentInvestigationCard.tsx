import { ArrowRight, Radar } from "lucide-react";
import { Link } from "react-router-dom";

import { useNetworkDetectionStore } from "../../store/networkDetectionStore";
import { Card } from "../common/Card";
import { StatusPill } from "../common/StatusPill";

/** Reads directly from the persisted network-detection store -- never a fetch, never
 * fabricated history. If no investigation has been run this session (or survived a
 * reload), this honestly says so rather than inventing one. */
export function RecentInvestigationCard() {
  const classification = useNetworkDetectionStore((state) => state.classification);
  const analyzeStatus = useNetworkDetectionStore((state) => state.analyzeStatus);
  const analysis = useNetworkDetectionStore((state) => state.analysis);
  const lastUpdated = useNetworkDetectionStore((state) => state.lastUpdated);

  if (!classification) {
    return (
      <Card className="p-5">
        <div className="flex items-center gap-2 text-text-muted">
          <Radar className="h-4 w-4" strokeWidth={1.75} />
          <span className="text-xs font-medium uppercase tracking-wide">Recent Investigation</span>
        </div>
        <p className="mt-3 text-sm text-text-faint">
          No investigation yet. Classify a network flow on Network Detection to see it here.
        </p>
        <Link
          to="/detection"
          className="mt-4 inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline"
        >
          Open Network Detection
          <ArrowRight className="h-3 w-3" strokeWidth={2} />
        </Link>
      </Card>
    );
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
