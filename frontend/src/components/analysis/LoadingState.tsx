import { Loader2 } from "lucide-react";
import { useEffect, useState } from "react";

import { Card } from "../common/Card";

const STAGES = ["Retrieving relevant intelligence", "Analyzing threat patterns", "Generating report"];

const STAGE_INTERVAL_MS = 1800;

export function LoadingState() {
  const [stageIndex, setStageIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setStageIndex((current) => Math.min(current + 1, STAGES.length - 1));
    }, STAGE_INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);

  return (
    <Card className="flex flex-col items-center gap-4 p-10 text-center" role="status" aria-live="polite">
      <Loader2 className="h-6 w-6 animate-spin text-accent" strokeWidth={1.75} />
      <p className="text-sm font-medium text-text">Analyzing threat intelligence…</p>
      <ul className="space-y-1.5 font-mono text-xs">
        {STAGES.map((stage, index) => (
          <li key={stage} className={index <= stageIndex ? "text-accent" : "text-text-faint"}>
            {stage}
          </li>
        ))}
      </ul>
    </Card>
  );
}
