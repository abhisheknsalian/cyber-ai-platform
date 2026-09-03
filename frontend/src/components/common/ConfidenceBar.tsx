type ConfidenceTone = "malicious" | "benign" | "neutral";

interface ConfidenceBarProps {
  /** 0-1 probability, straight from the backend's predict_proba -- never rounded or
   * invented here beyond display formatting. */
  value: number;
  tone?: ConfidenceTone;
  label?: string;
}

const TONE_STYLES: Record<ConfidenceTone, string> = {
  malicious: "bg-malicious",
  benign: "bg-benign",
  neutral: "bg-accent",
};

export function ConfidenceBar({ value, tone = "neutral", label = "Confidence" }: ConfidenceBarProps) {
  const clamped = Math.min(Math.max(value, 0), 1);
  const percent = clamped * 100;

  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-text-muted">{label}</span>
        <span className="font-mono text-sm font-semibold text-text">{percent.toFixed(1)}%</span>
      </div>
      <div
        role="progressbar"
        aria-valuenow={Math.round(percent)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
        className="h-2 w-full overflow-hidden rounded-full bg-surface-sunken"
      >
        <div
          className={`h-full animate-confidence-fill rounded-full ${TONE_STYLES[tone]}`}
          style={{ width: `${percent}%` }}
        />
      </div>
    </div>
  );
}
