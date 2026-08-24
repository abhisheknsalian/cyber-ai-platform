import type { Severity } from "../../types/api";

const SEVERITY_STYLES: Record<Severity, string> = {
  Low: "text-severity-low border-severity-low/40 bg-severity-low/10",
  Medium: "text-severity-medium border-severity-medium/40 bg-severity-medium/10",
  High: "text-severity-high border-severity-high/40 bg-severity-high/10",
  Critical: "text-severity-critical border-severity-critical/40 bg-severity-critical/10",
};

interface SeverityBadgeProps {
  severity: Severity;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-xs font-semibold uppercase tracking-wider ${SEVERITY_STYLES[severity]}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}
