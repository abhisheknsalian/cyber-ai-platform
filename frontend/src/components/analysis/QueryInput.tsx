interface QueryInputProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  disabled: boolean;
}

export function QueryInput({ value, onChange, onSubmit, disabled }: QueryInputProps) {
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <p className="mb-2 font-mono text-[11px] font-semibold uppercase tracking-[0.15em] text-text-faint">
        Investigation Query
      </p>
      <div className="flex flex-col gap-3 sm:flex-row">
        <input
          type="text"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          placeholder="Explain phishing attacks and mitigation"
          maxLength={2000}
          aria-label="Investigation query"
          className="flex-1 rounded-md border border-border-strong bg-surface-sunken px-4 py-2.5 text-sm text-text placeholder:text-text-faint focus:border-accent focus:outline-none"
        />
        <button
          type="submit"
          disabled={disabled || value.trim().length === 0}
          className="shrink-0 rounded-md bg-accent px-5 py-2.5 text-sm font-semibold text-surface transition-colors hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
        >
          {disabled ? "Analyzing…" : "Analyze"}
        </button>
      </div>
    </form>
  );
}
