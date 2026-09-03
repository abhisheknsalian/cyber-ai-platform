const SAMPLE_QUERIES = [
  "Explain phishing attacks and mitigation",
  "Explain ransomware attacks",
  "How can DDoS attacks be mitigated?",
  "What are SQL injection indicators?",
  "Explain botnet attacks",
];

interface SampleQueriesProps {
  onSelect: (query: string) => void;
}

export function SampleQueries({ onSelect }: SampleQueriesProps) {
  return (
    <div>
      <p className="mb-2 font-mono text-[11px] font-semibold uppercase tracking-[0.15em] text-text-faint">
        Quick Investigations
      </p>
      <div className="flex flex-wrap gap-2">
        {SAMPLE_QUERIES.map((query) => (
          <button
            key={query}
            type="button"
            onClick={() => onSelect(query)}
            className="rounded-md border border-border-strong bg-surface-hover px-3 py-1.5 text-xs text-text-muted transition-colors hover:border-accent/50 hover:text-text"
          >
            {query}
          </button>
        ))}
      </div>
    </div>
  );
}
