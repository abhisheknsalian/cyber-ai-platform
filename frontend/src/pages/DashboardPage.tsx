import { Brain, Cpu, Database, Layers, ShieldCheck } from "lucide-react";

import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";
import { StatusPill } from "../components/common/StatusPill";
import { ArchitecturePipeline } from "../components/dashboard/ArchitecturePipeline";
import { RecentInvestigationCard } from "../components/dashboard/RecentInvestigationCard";
import { StatCard } from "../components/dashboard/StatCard";
import { useHealth } from "../hooks/useHealth";
import { useReadiness } from "../hooks/useReadiness";
import { useThreats } from "../hooks/useThreats";

export function DashboardPage() {
  const { health, loading: healthLoading, error: healthError } = useHealth();
  const { readiness, loading: readinessLoading, error: readinessError } = useReadiness();
  const { threats, loading: threatsLoading, error: threatsError } = useThreats();

  const apiOnline = healthLoading ? undefined : health !== null || readiness !== null;

  return (
    <div>
      <PageHeader
        eyebrow="Security Operations Console"
        title="Dashboard"
        description="Live status of the local, self-hosted threat-intelligence and detection backend -- classifier, RAG engine, and LLM."
      />

      {(healthError || readinessError || threatsError) && (
        <Card className="mb-6 border-malicious/30 bg-malicious/5 px-4 py-3 text-sm text-malicious-strong">
          {healthError ?? readinessError ?? threatsError}
        </Card>
      )}

      <p className="mb-2 font-mono text-[11px] font-semibold uppercase tracking-[0.15em] text-text-faint">
        System Status
      </p>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-5">
        <StatCard
          icon={ShieldCheck}
          label="API"
          loading={healthLoading && readinessLoading}
          value={apiOnline === undefined ? "—" : <StatusPill ok={apiOnline} onLabel="Online" offLabel="Unreachable" pulse={apiOnline} />}
        />

        <StatCard
          icon={Database}
          label="RAG Engine"
          loading={healthLoading}
          value={health ? <StatusPill ok={health.vector_store.available} onLabel="Ready" offLabel="Not built" /> : "—"}
        />

        <StatCard
          icon={Layers}
          label="Vector Store"
          loading={healthLoading}
          value={health ? health.vector_store.chunk_count : "—"}
          hint={health ? <span className="font-mono">collection "{health.vector_store.collection}"</span> : undefined}
        />

        <StatCard
          icon={Brain}
          label="LLM"
          loading={healthLoading}
          value={health ? <StatusPill ok={health.llm.reachable} onLabel="Online" offLabel="Unreachable" /> : "—"}
          hint={health ? <span className="font-mono">{health.llm.model}</span> : undefined}
        />

        <StatCard
          icon={Cpu}
          label="ML Engine"
          loading={readinessLoading}
          value={readiness ? <StatusPill ok={readiness.checks.classifier} onLabel="Ready" offLabel="Not trained" /> : "—"}
          hint={<span className="font-mono">Random Forest · CICIDS2017</span>}
        />
      </div>

      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="p-5 lg:col-span-2">
          <div className="flex items-center gap-2 text-text-muted">
            <Database className="h-4 w-4" strokeWidth={1.75} />
            <span className="text-xs font-medium uppercase tracking-wide">Threat Intelligence</span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            {threatsLoading ? (
              <div className="h-8 w-16 animate-pulse rounded bg-surface-hover" />
            ) : (
              <span className="text-3xl font-bold text-text">{threats.length}</span>
            )}
            <span className="text-sm text-text-muted">knowledge sources</span>
          </div>
          <p className="mt-1 text-xs text-text-faint">Documents in data/threat_intel/</p>
          <div className="mt-4 flex flex-wrap gap-1.5">
            {threatsLoading ? (
              <div className="h-6 w-full animate-pulse rounded bg-surface-hover" />
            ) : (
              threats.map((t) => (
                <span
                  key={t.threat_type}
                  className="rounded border border-border-strong bg-surface-hover px-2 py-0.5 font-mono text-xs text-text"
                >
                  {t.threat_type}
                </span>
              ))
            )}
          </div>
        </Card>

        <RecentInvestigationCard />
      </div>

      <Card className="mt-6 p-5">
        <p className="mb-4 text-xs font-medium uppercase tracking-wide text-text-muted">Analysis Pipeline</p>
        <ArchitecturePipeline />
      </Card>
    </div>
  );
}
