import { AlertTriangle } from "lucide-react";

import { Card } from "../common/Card";

interface ErrorStateProps {
  message: string;
}

export function ErrorState({ message }: ErrorStateProps) {
  return (
    <Card className="flex items-start gap-3 border-malicious/30 bg-malicious/5 p-5" role="alert">
      <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-malicious-strong" strokeWidth={1.75} />
      <div>
        <p className="text-sm font-medium text-malicious-strong">Request failed</p>
        <p className="mt-1 text-sm text-text-muted">{message}</p>
      </div>
    </Card>
  );
}
