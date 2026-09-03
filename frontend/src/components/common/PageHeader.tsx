import type { ReactNode } from "react";

interface PageHeaderProps {
  eyebrow?: string;
  title: string;
  description?: string;
  /** Right-aligned slot for a status badge, e.g. "OFFLINE FLOW ANALYSIS". */
  status?: ReactNode;
}

export function PageHeader({ eyebrow, title, description, status }: PageHeaderProps) {
  return (
    <div className="mb-8 flex flex-wrap items-start justify-between gap-4 border-b border-border pb-6">
      <div>
        {eyebrow ? (
          <p className="mb-1.5 font-mono text-[11px] font-medium uppercase tracking-[0.2em] text-accent">
            {eyebrow}
          </p>
        ) : null}
        <h1 className="text-xl font-semibold tracking-tight text-text sm:text-2xl">{title}</h1>
        {description ? <p className="mt-2 max-w-2xl text-sm leading-relaxed text-text-muted">{description}</p> : null}
      </div>
      {status ? <div className="shrink-0">{status}</div> : null}
    </div>
  );
}
