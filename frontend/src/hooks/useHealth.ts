import { useEffect, useState } from "react";

import { ApiError, getHealth } from "../services/api";
import type { HealthResponse } from "../types/api";

interface UseHealthResult {
  health: HealthResponse | null;
  loading: boolean;
  error: string | null;
}

export function useHealth(): UseHealthResult {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getHealth()
      .then((data) => {
        if (!cancelled) setHealth(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : "Failed to reach the Cyber AI backend.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return { health, loading, error };
}
