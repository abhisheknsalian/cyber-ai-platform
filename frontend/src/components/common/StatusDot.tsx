export type SystemStatusState = "online" | "offline" | "checking";

const STATE_STYLES: Record<SystemStatusState, { dot: string; text: string; label: string }> = {
  online: { dot: "bg-benign", text: "text-benign-strong", label: "ONLINE" },
  offline: { dot: "bg-malicious", text: "text-malicious-strong", label: "OFFLINE" },
  checking: { dot: "bg-text-faint", text: "text-text-faint", label: "CHECKING" },
};

interface StatusDotProps {
  label: string;
  state: SystemStatusState;
}

/** One row of the sidebar/dashboard "SYSTEM STATUS" list -- a live dependency
 * indicator sourced from GET /health and GET /ready, never fabricated. */
export function StatusDot({ label, state }: StatusDotProps) {
  const styles = STATE_STYLES[state];
  return (
    <div className="flex items-center justify-between gap-3 py-1">
      <span className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-wide text-text-muted">
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${styles.dot} ${state === "online" ? "animate-pulse-dot" : ""}`} />
        {label}
      </span>
      <span className={`font-mono text-[11px] font-semibold tracking-wide ${styles.text}`}>{styles.label}</span>
    </div>
  );
}
