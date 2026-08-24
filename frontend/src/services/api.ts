import type { AnalyzeRequest, HealthResponse, ThreatAnalysis, ThreatCategory } from "../types/api";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

const REQUEST_TIMEOUT_MS = 60_000;

/** Thrown for every failure mode: network-down, timeout, non-2xx, and malformed responses. */
export class ApiError extends Error {
  readonly status: number | null;

  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError("The request took too long to respond. The local model may still be loading.");
    }
    throw new ApiError("Unable to connect to the Cyber AI backend. Make sure the FastAPI server is running.");
  } finally {
    clearTimeout(timeout);
  }

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}.`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") {
        detail = body.detail;
      }
    } catch {
      // Response body wasn't JSON -- keep the generic message above.
    }
    throw new ApiError(detail, response.status);
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError("The backend returned a response that could not be understood.");
  }
}

export function analyzeThreat(query: string): Promise<ThreatAnalysis> {
  const body: AnalyzeRequest = { query };
  return request<ThreatAnalysis>("/analyze", { method: "POST", body: JSON.stringify(body) });
}

export function getHealth(): Promise<HealthResponse> {
  return request<HealthResponse>("/health");
}

export function getThreats(): Promise<ThreatCategory[]> {
  return request<ThreatCategory[]>("/threats");
}
