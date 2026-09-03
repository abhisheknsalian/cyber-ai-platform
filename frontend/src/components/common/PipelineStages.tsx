import { Check, Loader2, X } from "lucide-react";

export type StageState = "idle" | "processing" | "complete" | "error";

export interface PipelineStage {
  id: string;
  label: string;
  state: StageState;
}

const STATE_RING: Record<StageState, string> = {
  idle: "border-border-strong bg-surface text-text-faint",
  processing: "border-accent bg-accent/10 text-accent",
  complete: "border-benign bg-benign/10 text-benign-strong",
  error: "border-malicious bg-malicious/10 text-malicious-strong",
};

const CONNECTOR_STATE: Record<StageState, string> = {
  idle: "bg-border",
  processing: "bg-accent/50",
  complete: "bg-benign/50",
  error: "bg-malicious/50",
};

interface PipelineStagesProps {
  stages: PipelineStage[];
}

/** A horizontal stage tracker shared by the Dashboard's static architecture diagram
 * and Network Detection's live investigation timeline. Each stage's `state` is the
 * only thing that differs between those two uses -- this component never invents
 * progress on its own. */
export function PipelineStages({ stages }: PipelineStagesProps) {
  return (
    <ol className="flex items-start gap-0 overflow-x-auto pb-1">
      {stages.map((stage, index) => (
        <li key={stage.id} className="flex shrink-0 items-start">
          {index > 0 ? (
            <span
              aria-hidden
              className={`mt-4 h-px w-6 shrink-0 sm:w-10 ${CONNECTOR_STATE[stages[index - 1].state]}`}
            />
          ) : null}
          <div className="flex w-20 flex-col items-center gap-2 text-center sm:w-24">
            <span
              className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border-2 font-mono text-[11px] font-bold ${STATE_RING[stage.state]}`}
            >
              {stage.state === "complete" ? (
                <Check className="h-4 w-4" strokeWidth={2.5} />
              ) : stage.state === "processing" ? (
                <Loader2 className="h-4 w-4 animate-spin" strokeWidth={2.5} />
              ) : stage.state === "error" ? (
                <X className="h-4 w-4" strokeWidth={2.5} />
              ) : (
                String(index + 1).padStart(2, "0")
              )}
            </span>
            <span
              className={`text-[10px] font-medium uppercase leading-tight tracking-wide ${
                stage.state === "idle" ? "text-text-faint" : "text-text-muted"
              }`}
            >
              {stage.label}
            </span>
          </div>
        </li>
      ))}
    </ol>
  );
}
