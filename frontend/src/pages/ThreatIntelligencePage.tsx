import { Bug, Database, Lock, Mail, Network, ShieldAlert, Zap } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";
import { StatusPill } from "../components/common/StatusPill";
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

  return (
    <div>
      <PageHeader
        title="Threat Intelligence"
        description="The threat categories currently available in the local knowledge base (data/threat_intel/)."
      />

      {error && (
        <Card className="mb-6 border-severity-critical/30 bg-severity-critical/5 px-4 py-3 text-sm text-severity-critical">
          {error}
        </Card>
      )}

      {loading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-32 animate-pulse rounded-lg border border-border bg-surface-raised" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {threats.map((threat) => {
            const Icon = ICONS[threat.threat_type] ?? ShieldAlert;
            return (
              <Card key={threat.threat_type} className="p-5">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <Icon className="h-5 w-5 text-accent" strokeWidth={1.75} />
                    <h2 className="text-sm font-semibold text-text">{formatThreatType(threat.threat_type)}</h2>
                  </div>
                  <StatusPill ok onLabel="In knowledge base" offLabel="Missing" />
                </div>
                <p className="mt-3 text-sm leading-relaxed text-text-muted">{threat.description}</p>
                <p className="mt-3 font-mono text-xs text-text-faint">{threat.source}</p>
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
