import { Bug, ChevronDown, Database, Lock, Mail, Network, ShieldAlert, Zap } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useState } from "react";

import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";
import { StatusPill } from "../components/common/StatusPill";
import { ThreatGraphView } from "../components/intelligence/ThreatGraphView";
import { useThreats } from "../hooks/useThreats";

const ICONS: Record<string, LucideIcon> = {
  phishing: Mail,
  ransomware: Lock,
  ddos_attack: Zap,
  sql_injection: Database,
  botnet: Network,
};

function formatThreatType(threatType: string): string {
  return threatType
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

export function ThreatIntelligencePage() {
  const { threats, loading, error } = useThreats();
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <div>
      <PageHeader
        eyebrow="Local Knowledge Base"
        title="Threat Intelligence"
        description="Threat categories loaded from data/threat_intel/, each with its direct relationships (techniques, indicators, mitigations, sources) in the threat graph."
      />

      {error && (
        <Card className="mb-6 border-malicious/30 bg-malicious/5 px-4 py-3 text-sm text-malicious-strong">{error}</Card>
      )}

      {loading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-40 animate-pulse rounded-md border border-border bg-surface-raised" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {threats.map((threat) => {
            const Icon = ICONS[threat.threat_type] ?? ShieldAlert;
            const isExpanded = expanded === threat.threat_type;
            return (
              <Card key={threat.threat_type} className={isExpanded ? "p-5 xl:col-span-3" : "p-5"}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <Icon className="h-5 w-5 text-accent" strokeWidth={1.75} />
                    <div>
                      <p className="font-mono text-[10px] uppercase tracking-wider text-text-faint">Threat Type</p>
                      <h2 className="text-sm font-semibold text-text">{formatThreatType(threat.threat_type)}</h2>
                    </div>
                  </div>
                  <StatusPill ok onLabel="In KB" offLabel="Missing" />
                </div>

                <p className="mt-3 text-[11px] font-medium uppercase tracking-wide text-text-faint">Description</p>
                <p className="mt-1 text-sm leading-relaxed text-text-muted">{threat.description}</p>

                <p className="mt-3 text-[11px] font-medium uppercase tracking-wide text-text-faint">Source</p>
                <p className="mt-1 font-mono text-xs text-text">{threat.source}</p>

                <button
                  type="button"
                  onClick={() => setExpanded(isExpanded ? null : threat.threat_type)}
                  aria-expanded={isExpanded}
                  className="mt-4 flex w-full items-center justify-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-text-muted transition-colors hover:border-border-strong hover:bg-surface-hover hover:text-text"
                >
                  <ChevronDown
                    className={`h-3.5 w-3.5 transition-transform ${isExpanded ? "rotate-180" : ""}`}
                    strokeWidth={1.75}
                  />
                  {isExpanded ? "Hide relationship graph" : "View relationship graph"}
                </button>

                {isExpanded && (
                  <div className="mt-4 border-t border-border pt-4">
                    <ThreatGraphView threatId={threat.threat_type} />
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}

      {!loading && threats.length === 0 && !error && (
        <Card className="p-8 text-center text-sm text-text-muted">
          <Bug className="mx-auto mb-3 h-6 w-6 text-text-faint" strokeWidth={1.5} />
          No threat-intelligence documents were found.
        </Card>
      )}
    </div>
  );
}
