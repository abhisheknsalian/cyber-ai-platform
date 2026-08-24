import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { Card } from "../common/Card";

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  loading?: boolean;
}

export function StatCard({ icon: Icon, label, value, hint, loading = false }: StatCardProps) {
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 text-text-muted">
        <Icon className="h-4 w-4" strokeWidth={1.75} />
        <span className="text-xs font-medium uppercase tracking-wide">{label}</span>
      </div>

      <div className="mt-3">
        {loading ? (
          <div className="h-7 w-24 animate-pulse rounded bg-surface-hover" />
        ) : (
          <div className="text-2xl font-semibold text-text">{value}</div>
        )}
      </div>

      {hint ? <div className="mt-2 text-xs text-text-muted">{hint}</div> : null}
    </Card>
  );
}
