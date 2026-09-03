import { useEffect, useState } from "react";

import { ApiError, getReadiness } from "../services/api";
import type { ReadinessResponse } from "../types/api";

interface UseReadinessResult {
  readiness: ReadinessResponse | null;
  loading: boolean;
  error: string | null;
}

/** Polls GET /ready periodically so the sidebar/dashboard system-status indicators
 * reflect the classifier/vector-store/LLM's *current* availability, not just a
 * snapshot from when the page first loaded. */
export function useReadiness(pollIntervalMs = 30_000): UseReadinessResult {
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    function poll() {
      getReadiness()
        .then((data) => {
          if (!cancelled) {
            setReadiness(data);
            setError(null);
          }
        })
        .catch((err: unknown) => {
          if (!cancelled) {
            setError(err instanceof ApiError ? err.message : "Failed to reach the Cyber AI backend.");
          }
        })
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    }

    poll();
    const interval = setInterval(poll, pollIntervalMs);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [pollIntervalMs]);

  return { readiness, loading, error };
}
