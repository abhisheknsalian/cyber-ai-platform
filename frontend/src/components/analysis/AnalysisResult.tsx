import { ExternalLink, FileText, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

import type { ThreatAnalysis } from "../../types/api";
import { Card } from "../common/Card";
import { SeverityBadge } from "../common/SeverityBadge";

interface AnalysisResultProps {
  result: ThreatAnalysis;
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

export function AnalysisResult({ result }: AnalysisResultProps) {
  return (
    <div className="space-y-6">
      <Card className="p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="h-5 w-5 text-accent" strokeWidth={1.75} />
            <span className="font-mono text-lg font-semibold uppercase tracking-wide text-text">
              {result.threat}
            </span>
          </div>
          {result.severity ? <SeverityBadge severity={result.severity} /> : null}
        </div>

        <p className="mt-4 text-sm leading-relaxed text-text-muted">{result.summary}</p>
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

      <Card className="p-6">
        <div className="mb-3 flex items-center gap-2">
          <FileText className="h-4 w-4 text-text-muted" strokeWidth={1.75} />
          <h3 className="text-xs font-semibold uppercase tracking-wide text-text-muted">
            Sources ({result.sources.length})
          </h3>
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
