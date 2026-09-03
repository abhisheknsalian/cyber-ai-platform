const STAGES = ["Network Flow", "Random Forest", "Threat Classification", "RAG Retrieval", "Threat Graph", "LLM", "Threat Report"];

/** A static explainer of the backend's actual request pipeline (not a live-status
 * tracker -- see components/common/PipelineStages for that, used on Network
 * Detection where each stage's state reflects a real in-flight investigation). */
export function ArchitecturePipeline() {
  return (
    <div className="flex items-center gap-0 overflow-x-auto pb-1">
      {STAGES.map((stage, index) => (
        <div key={stage} className="flex shrink-0 items-center">
          {index > 0 ? (
            <div className="h-px w-5 shrink-0 bg-border-strong sm:w-8" aria-hidden />
          ) : null}
          <div className="rounded-md border border-border-strong bg-surface-hover px-3 py-2.5 text-center">
            <p className="whitespace-nowrap font-mono text-xs font-semibold text-text">{stage}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
