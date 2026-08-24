import { ArrowDown } from "lucide-react";

import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";

const ARCHITECTURE_LAYERS = [
  { label: "React", detail: "This dashboard (Vite + TypeScript + Tailwind)" },
  { label: "FastAPI", detail: "Backend API — /analyze, /health, /threats" },
  { label: "RAG orchestration", detail: "Relevance filtering, threat identification, MITRE extraction" },
  { label: "ChromaDB", detail: "Local vector store over data/threat_intel/*.txt" },
  { label: "Ollama", detail: "Local LLM runtime" },
  { label: "Llama 3.2", detail: "Structured, context-grounded generation" },
];

export function AboutPage() {
  return (
    <div>
      <PageHeader title="About" description="AI-Powered Cyber Threat Intelligence Platform" />

      <Card className="p-6">
        <p className="text-sm leading-relaxed text-text-muted">
          This platform answers cybersecurity questions using retrieval-augmented generation (RAG)
          over a small, local threat-intelligence knowledge base. It does not use any cloud LLM API
          or external threat-intelligence feed — every part of the pipeline, from embedding to
          generation, runs locally.
        </p>
      </Card>

      <Card className="mt-6 p-6">
        <h2 className="mb-5 text-xs font-semibold uppercase tracking-wide text-text-muted">Architecture</h2>
        <div className="flex flex-col items-center gap-1.5">
          {ARCHITECTURE_LAYERS.map((layer, index) => (
            <div key={layer.label} className="flex w-full max-w-md flex-col items-center">
              <div className="w-full rounded-md border border-border-strong bg-surface-hover px-4 py-3 text-center">
                <p className="font-mono text-sm font-semibold text-text">{layer.label}</p>
                <p className="mt-0.5 text-xs text-text-muted">{layer.detail}</p>
              </div>
              {index < ARCHITECTURE_LAYERS.length - 1 && (
                <ArrowDown className="my-1.5 h-4 w-4 text-text-faint" strokeWidth={1.75} />
              )}
            </div>
          ))}
        </div>
      </Card>

      <Card className="mt-6 p-6">
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Knowledge base</h2>
        <p className="text-sm leading-relaxed text-text-muted">
          The system currently uses a local threat-intelligence knowledge base of five documents
          (botnet, DDoS, phishing, ransomware, SQL injection) — see the{" "}
          <span className="font-mono text-text">Threat Intelligence</span> page for what's actually
          loaded. There is no live threat-feed integration, no classifier integration, and no
          authentication yet — this is a backend-plus-dashboard prototype.
        </p>
      </Card>
    </div>
  );
}
