import { ArrowDown } from "lucide-react";

import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";

const ARCHITECTURE_LAYERS = [
  { label: "React", detail: "This console (Vite + TypeScript + Tailwind)" },
  { label: "FastAPI", detail: "Backend API -- /classify, /analyze, /health, /ready, /threats" },
  { label: "ML Classifier + RAG Orchestration", detail: "Random Forest inference; retrieval, relevance filtering, MITRE extraction" },
  { label: "Random Forest · ChromaDB · Threat Graph", detail: "CICIDS2017-trained classifier, local vector store, structured entity graph" },
  { label: "Ollama", detail: "Local LLM runtime" },
  { label: "Llama 3.2", detail: "Structured, context-grounded generation" },
];

export function AboutPage() {
  return (
    <div>
      <PageHeader eyebrow="Cyber AI Platform" title="About" description="AI-Powered Cyber Threat Intelligence Platform" />

      <Card className="p-6">
        <p className="text-sm leading-relaxed text-text-muted">
          This platform combines a Random Forest network-traffic classifier with retrieval-augmented generation
          (RAG) over a small, local threat-intelligence knowledge base and structured threat graph. It does not use
          any cloud LLM API or external threat-intelligence feed -- every part of the pipeline, from classification
          and embedding to generation, runs locally.
        </p>
      </Card>

      <Card className="mt-6 p-6">
        <h2 className="mb-5 text-xs font-semibold uppercase tracking-wide text-text-muted">Architecture</h2>
        <div className="flex flex-col items-center gap-1.5">
          {ARCHITECTURE_LAYERS.map((layer, index) => (
            <div key={layer.label} className="flex w-full max-w-lg flex-col items-center">
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

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2">
        <Card className="p-6">
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Detection</h2>
          <p className="text-sm leading-relaxed text-text-muted">
            The Network Detection classifier is trained on the CICIDS2017 "Friday Afternoon DDoS" capture and scores
            a single, already-extracted 78-feature CICFlowMeter flow vector offline. It is a DDoS/BENIGN traffic
            classifier, not a general-purpose malware detector, and it does not capture or monitor live network
            traffic.
          </p>
        </Card>

        <Card className="p-6">
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">Knowledge base</h2>
          <p className="text-sm leading-relaxed text-text-muted">
            The RAG layer uses a local threat-intelligence knowledge base of five documents (botnet, DDoS,
            phishing, ransomware, SQL injection) plus a structured threat graph -- see the{" "}
            <span className="font-mono text-text">Threat Intelligence</span> page for what's actually loaded.
          </p>
        </Card>
      </div>

      <Card className="mt-6 p-6">
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-text-muted">What this is not</h2>
        <p className="text-sm leading-relaxed text-text-muted">
          This is a local-first cybersecurity research/prototype platform, protected by session-based
          authentication. It does not integrate live threat feeds, live packet capture, production SOC monitoring,
          real-time network monitoring, or any external threat-intelligence API.
        </p>
      </Card>
    </div>
  );
}
