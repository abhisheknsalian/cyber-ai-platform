import { AlertTriangle, Check, ClipboardCopy, Sparkles } from "lucide-react";
import { useMemo, useRef, useState } from "react";

interface JsonValidity {
  valid: boolean;
  error: string | null;
  keyCount: number | null;
}

function validateJson(text: string): JsonValidity {
  const trimmed = text.trim();
  if (trimmed.length === 0) {
    return { valid: false, error: null, keyCount: null };
  }
  try {
    const parsed = JSON.parse(trimmed);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return { valid: false, error: "Expected a JSON object of \"feature name\": number pairs.", keyCount: null };
    }
    return { valid: true, error: null, keyCount: Object.keys(parsed).length };
  } catch (error) {
    return { valid: false, error: error instanceof Error ? error.message : "Invalid JSON.", keyCount: null };
  }
}

interface JsonEditorProps {
  value: string;
  onChange: (value: string) => void;
  rows?: number;
  placeholder?: string;
  ariaLabel?: string;
  disabled?: boolean;
}

/** A dependency-free JSON editor: monospace textarea + synced line-number gutter,
 * inline validity feedback, format-in-place, and copy-to-clipboard. Not a full code
 * editor (no syntax highlighting) -- deliberately, to avoid pulling in a heavy
 * editor dependency for a single JSON textarea. */
export function JsonEditor({ value, onChange, rows = 16, placeholder, ariaLabel, disabled = false }: JsonEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const gutterRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);

  const lineCount = useMemo(() => Math.max(value.split("\n").length, 1), [value]);
  const validity = useMemo(() => validateJson(value), [value]);

  function handleScroll() {
    if (textareaRef.current && gutterRef.current) {
      gutterRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  }

  function handleFormat() {
    if (!validity.valid) return;
    onChange(JSON.stringify(JSON.parse(value), null, 2));
  }

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API unavailable (e.g. insecure context) -- not worth surfacing.
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between gap-2 rounded-t-md border border-b-0 border-border-strong bg-surface-sunken px-3 py-1.5">
        <span className="font-mono text-[11px] uppercase tracking-wider text-text-faint">flow.json</span>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={handleFormat}
            disabled={disabled || !validity.valid}
            className="flex items-center gap-1 rounded px-2 py-1 text-[11px] font-medium text-text-muted transition-colors hover:bg-surface-hover hover:text-text disabled:cursor-not-allowed disabled:opacity-30"
          >
            <Sparkles className="h-3 w-3" strokeWidth={1.75} />
            Format
          </button>
          <button
            type="button"
            onClick={handleCopy}
            disabled={disabled || value.length === 0}
            className="flex items-center gap-1 rounded px-2 py-1 text-[11px] font-medium text-text-muted transition-colors hover:bg-surface-hover hover:text-text disabled:cursor-not-allowed disabled:opacity-30"
          >
            {copied ? (
              <Check className="h-3 w-3 text-benign" strokeWidth={1.75} />
            ) : (
              <ClipboardCopy className="h-3 w-3" strokeWidth={1.75} />
            )}
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </div>

      <div className="flex overflow-hidden rounded-b-md border border-border-strong bg-surface-sunken focus-within:border-accent/60 focus-within:shadow-[0_0_20px_-14px_var(--color-accent)]">
        <div
          ref={gutterRef}
          aria-hidden
          className="select-none overflow-hidden border-r border-border py-3 pl-3 pr-2 text-right font-mono text-xs leading-5 text-text-faint"
          style={{ height: `${rows * 1.25}rem` }}
        >
          {Array.from({ length: lineCount }, (_, i) => (
            <div key={i}>{i + 1}</div>
          ))}
        </div>
        <textarea
          ref={textareaRef}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          onScroll={handleScroll}
          placeholder={placeholder}
          spellCheck={false}
          disabled={disabled}
          aria-label={ariaLabel}
          aria-invalid={value.trim().length > 0 && !validity.valid}
          rows={rows}
          className="w-full resize-none bg-transparent px-3 py-3 font-mono text-xs leading-5 text-text placeholder:text-text-faint focus:outline-none disabled:opacity-60"
        />
      </div>

      <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs">
        {value.trim().length === 0 ? (
          <span className="text-text-faint">Paste a CICFlowMeter feature vector, or load the example shape below.</span>
        ) : validity.valid ? (
          <span className="flex items-center gap-1.5 text-benign-strong">
            <Check className="h-3.5 w-3.5" strokeWidth={1.75} />
            Valid JSON · {validity.keyCount} fields
          </span>
        ) : (
          <span className="flex items-center gap-1.5 text-malicious-strong" role="alert">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" strokeWidth={1.75} />
            {validity.error ?? "Invalid JSON"}
          </span>
        )}
      </div>
    </div>
  );
}
