import { useEffect, useState } from "react";

import { ApiError, getThreatGraph } from "../services/api";
import type { ThreatGraphNeighborhood } from "../types/intelligence";

interface UseThreatGraphResult {
  data: ThreatGraphNeighborhood | null;
  loading: boolean;
  error: string | null;
}

export function useThreatGraph(threatId: string): UseThreatGraphResult {
  const [data, setData] = useState<ThreatGraphNeighborhood | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getThreatGraph(threatId)
      .then((result) => {
        if (!cancelled) setData(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : "Failed to load the threat graph.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [threatId]);

  return { data, loading, error };
}
