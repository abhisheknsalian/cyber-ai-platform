import { useEffect, useState } from "react";

import { ApiError, getThreats } from "../services/api";
import type { ThreatCategory } from "../types/api";

interface UseThreatsResult {
  threats: ThreatCategory[];
  loading: boolean;
  error: string | null;
}

export function useThreats(): UseThreatsResult {
  const [threats, setThreats] = useState<ThreatCategory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getThreats()
      .then((data) => {
        if (!cancelled) setThreats(data);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : "Failed to load threat categories.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return { threats, loading, error };
}
