import { AlertTriangle } from "lucide-react";

import { Card } from "../common/Card";

interface ErrorStateProps {
  message: string;
}

export function ErrorState({ message }: ErrorStateProps) {
  return (
    <Card className="flex items-start gap-3 border-severity-critical/30 bg-severity-critical/5 p-5">
      <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-severity-critical" strokeWidth={1.75} />
      <div>
        <p className="text-sm font-medium text-severity-critical">Analysis failed</p>
        <p className="mt-1 text-sm text-text-muted">{message}</p>
      </div>
    </Card>
  );
}
