import { SearchX } from "lucide-react";

import { Card } from "../common/Card";

interface NoRelevantIntelligenceProps {
  summary: string;
}

export function NoRelevantIntelligence({ summary }: NoRelevantIntelligenceProps) {
  return (
    <Card className="flex flex-col items-center gap-3 border-border-strong p-10 text-center">
      <SearchX className="h-8 w-8 text-text-faint" strokeWidth={1.5} />
      <div>
        <p className="text-sm font-medium text-text">No relevant cybersecurity intelligence was found for this query</p>
        <p className="mx-auto mt-1.5 max-w-md text-sm text-text-muted">{summary}</p>
      </div>
    </Card>
  );
}
