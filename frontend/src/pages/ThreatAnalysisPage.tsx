import { useState } from "react";

import { AnalysisResult } from "../components/analysis/AnalysisResult";
import { ErrorState } from "../components/analysis/ErrorState";
import { LoadingState } from "../components/analysis/LoadingState";
import { NoRelevantIntelligence } from "../components/analysis/NoRelevantIntelligence";
import { QueryInput } from "../components/analysis/QueryInput";
import { SampleQueries } from "../components/analysis/SampleQueries";
import { Card } from "../components/common/Card";
import { PageHeader } from "../components/common/PageHeader";
import { analyzeThreat, ApiError } from "../services/api";
import type { ThreatAnalysis } from "../types/api";

type RequestState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; result: ThreatAnalysis }
  | { status: "error"; message: string };

export function ThreatAnalysisPage() {
  const [query, setQuery] = useState("");
  const [request, setRequest] = useState<RequestState>({ status: "idle" });

  async function runAnalysis(submittedQuery: string) {
    const trimmed = submittedQuery.trim();
    if (!trimmed) {
      setRequest({ status: "error", message: "Enter a question before analyzing." });
      return;
    }

    setRequest({ status: "loading" });
    try {
      const result = await analyzeThreat(trimmed);
      setRequest({ status: "success", result });
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "An unexpected error occurred.";
      setRequest({ status: "error", message });
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Retrieval-Augmented Generation · Local LLM"
        title="AI Threat Analysis"
        description="Ask a cybersecurity question and get a structured intelligence report grounded in the local threat-intelligence knowledge base and a local Llama 3.2 model -- not a general-purpose chatbot."
      />

      <Card className="p-5">
        <QueryInput
          value={query}
          onChange={setQuery}
          onSubmit={() => runAnalysis(query)}
          disabled={request.status === "loading"}
        />
        <div className="mt-4 border-t border-border pt-4">
          <SampleQueries onSelect={(sample) => setQuery(sample)} />
        </div>
      </Card>

      <div className="mt-6">
        {request.status === "loading" && <LoadingState />}
        {request.status === "error" && <ErrorState message={request.message} />}
        {request.status === "success" && request.result.status === "no_relevant_intelligence" && (
          <NoRelevantIntelligence summary={request.result.summary} />
        )}
        {request.status === "success" && request.result.status === "analyzed" && (
          <AnalysisResult result={request.result} />
        )}
      </div>
    </div>
  );
}
