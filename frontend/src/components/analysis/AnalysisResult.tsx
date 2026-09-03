import { ExternalLink, FileText, GitBranch, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

import type { ThreatAnalysis } from "../../types/api";
import type { HybridEvidence } from "../../types/intelligence";
import { Card } from "../common/Card";
import { SeverityBadge } from "../common/SeverityBadge";

interface AnalysisResultProps {
  result: ThreatAnalysis;
  /** The hybrid evidence bundle behind this analysis (classifier/vector/graph),
   * when it came from POST /analyze/classification. null/undefined for a plain
   * /analyze query, which doesn't return one. */
  evidence?: HybridEvidence | null;
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">{title}</h3>
      <div className="mt-2">{children}</div>
    </div>
  );
}

function TagList({ items }: { items: string[] }) {
  if (items.length === 0) {
    return <p className="text-sm text-text-faint">None reported for this query.</p>;
  }
  return (
    <div className="flex flex-wrap gap-2">
      {items.map((item) => (
        <span
          key={item}
          className="rounded-md border border-border-strong bg-surface-hover px-2.5 py-1 text-xs text-text"
        >
          {item}
        </span>
      ))}
    </div>
  );
}

const RELATION_LABEL: Record<string, string> = {
  USES: "Uses",
  HAS_INDICATOR: "Indicator",
  MITIGATED_BY: "Mitigated by",
  SUPPORTED_BY: "Sourced from",
};

export function AnalysisResult({ result, evidence }: AnalysisResultProps) {
  return (
    <div className="space-y-6">
      <Card className="p-6" glow="accent">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="h-5 w-5 text-accent" strokeWidth={1.75} />
            <span className="font-mono text-lg font-semibold uppercase tracking-wide text-text">
              {result.threat}
            </span>
          </div>
          {result.severity ? <SeverityBadge severity={result.severity} /> : null}
        </div>

        <p className="mt-1 text-[11px] font-medium uppercase tracking-wide text-text-faint">Executive Summary</p>
        <p className="mt-2 text-sm leading-relaxed text-text-muted">{result.summary}</p>
      </Card>

      <Card className="grid grid-cols-1 gap-6 p-6 sm:grid-cols-2">
        <Section title="Attack Vectors">
          <TagList items={result.attack_vectors} />
        </Section>
        <Section title="Indicators">
          <TagList items={result.indicators} />
        </Section>
      </Card>

      <Card className="p-6">
        <Section title="MITRE ATT&CK">
          {result.mitre_attack.length === 0 ? (
            <p className="text-sm text-text-faint">
              No MITRE ATT&CK technique from the knowledge base was matched to this query.
            </p>
          ) : (
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {result.mitre_attack.map((technique) => (
                <a
                  key={technique.id}
                  href={`https://attack.mitre.org/techniques/${technique.id}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center justify-between rounded-md border border-border-strong bg-surface-hover px-3 py-2.5 transition-colors hover:border-accent/50"
                >
                  <div>
                    <p className="font-mono text-sm font-semibold text-accent">{technique.id}</p>
                    <p className="text-xs text-text-muted">{technique.name}</p>
                  </div>
                  <ExternalLink className="h-3.5 w-3.5 shrink-0 text-text-faint" strokeWidth={1.75} />
                </a>
              ))}
            </div>
          )}
        </Section>
      </Card>

      <Card className="p-6">
        <Section title="Mitigations">
          <TagList items={result.mitigations} />
        </Section>
      </Card>

      {evidence && evidence.graph_evidence.length > 0 ? (
        <Card className="p-6">
          <div className="mb-3 flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-text-muted" strokeWidth={1.75} />
            <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
              Related Graph Relationships ({evidence.graph_evidence.length})
            </h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {evidence.graph_evidence.map((relation, index) => (
              <span
                key={`${relation.relation}-${relation.target_id}-${index}`}
                className="rounded-md border border-border-strong bg-surface-hover px-2.5 py-1.5 font-mono text-xs text-text"
              >
                <span className="text-text-faint">{RELATION_LABEL[relation.relation] ?? relation.relation}</span>{" "}
                {relation.target_name}
              </span>
            ))}
          </div>
        </Card>
      ) : null}

      <Card className="p-6">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-text-muted" strokeWidth={1.75} />
            <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
              Intelligence Sources ({result.sources.length})
            </h3>
          </div>
          {evidence?.vector_duration_ms != null ? (
            <span className="font-mono text-[11px] text-text-faint">
              retrieval {evidence.vector_duration_ms.toFixed(1)}ms
              {evidence.graph_duration_ms != null ? ` · graph ${evidence.graph_duration_ms.toFixed(1)}ms` : ""}
            </span>
          ) : null}
        </div>
        <div className="space-y-2">
          {result.sources.map((source, index) => (
            <div
              key={`${source.source}-${source.chunk_index}-${index}`}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-surface px-3 py-2"
            >
              <div>
                <p className="font-mono text-sm text-text">{source.source}</p>
                <p className="text-xs text-text-muted">
                  Threat type: {source.threat_type} · Chunk: {source.chunk_index}
                </p>
              </div>
              <span className="font-mono text-xs text-text-faint">score {source.score.toFixed(4)}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
