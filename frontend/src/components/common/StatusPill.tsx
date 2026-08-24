interface StatusPillProps {
  ok: boolean;
  onLabel: string;
  offLabel: string;
}

export function StatusPill({ ok, onLabel, offLabel }: StatusPillProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium ${
        ok
          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
          : "border-severity-critical/40 bg-severity-critical/10 text-severity-critical"
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-emerald-400" : "bg-severity-critical"}`} />
      {ok ? onLabel : offLabel}
    </span>
  );
}
