import { Cpu, Database, Layers, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";

import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";
import { StatusPill } from "../components/common/StatusPill";
import { StatCard } from "../components/dashboard/StatCard";
import { useHealth } from "../hooks/useHealth";
import { useThreats } from "../hooks/useThreats";

export function DashboardPage() {
  const { health, loading: healthLoading, error: healthError } = useHealth();
  const { threats, loading: threatsLoading, error: threatsError } = useThreats();

  return (
    <div>
      <PageHeader
        title="Dashboard"
        description="Live status of the local retrieval-augmented threat intelligence backend."
      />

      {(healthError || threatsError) && (
        <Card className="mb-6 border-severity-critical/30 bg-severity-critical/5 px-4 py-3 text-sm text-severity-critical">
          {healthError ?? threatsError}
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Database}
          label="Threat Intelligence Sources"
          value={threats.length}
          hint="Documents in data/threat_intel/"
          loading={threatsLoading}
        />

        <Card className="p-5">
          <div className="flex items-center gap-2 text-text-muted">
            <Layers className="h-4 w-4" strokeWidth={1.75} />
            <span className="text-xs font-medium uppercase tracking-wide">Supported Threat Types</span>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
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

        <StatCard
          icon={ShieldCheck}
          label="RAG Status"
          loading={healthLoading}
          value={
            health ? (
              <StatusPill ok={health.vector_store.available} onLabel="Ready" offLabel="Not built" />
            ) : (
              "—"
            )
          }
          hint={health ? `${health.vector_store.chunk_count} chunks · collection "${health.vector_store.collection}"` : undefined}
        />

        <StatCard
          icon={Cpu}
          label="LLM Status"
          loading={healthLoading}
          value={
            health ? (
              <StatusPill ok={health.llm.reachable} onLabel="Online" offLabel="Unreachable" />
            ) : (
              "—"
            )
          }
          hint={
            health ? (
              <span className="font-mono">
                {health.llm.model} {health.llm.model_pulled ? "(pulled)" : "(not pulled)"}
              </span>
            ) : undefined
          }
        />
      </div>

      <Card className="mt-6 p-5">
        <h2 className="text-sm font-semibold text-text">Get started</h2>
        <p className="mt-1.5 text-sm text-text-muted">
          Ask a question grounded in the local threat-intelligence knowledge base on the{" "}
          <Link to="/analyze" className="text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent">
            Threat Analysis
          </Link>{" "}
          page, or browse what's in the knowledge base on{" "}
          <Link
            to="/intelligence"
            className="text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent"
          >
            Threat Intelligence
          </Link>
          .
        </p>
      </Card>
    </div>
  );
}
