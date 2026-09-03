interface StatusPillProps {
  ok: boolean;
  onLabel: string;
  offLabel: string;
  pulse?: boolean;
}

export function StatusPill({ ok, onLabel, offLabel, pulse = false }: StatusPillProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 font-mono text-xs font-medium uppercase tracking-wide ${
        ok ? "border-benign/40 bg-benign/10 text-benign-strong" : "border-malicious/40 bg-malicious/10 text-malicious-strong"
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-benign" : "bg-malicious"} ${pulse ? "animate-pulse-dot" : ""}`}
      />
      {ok ? onLabel : offLabel}
    </span>
  );
}
