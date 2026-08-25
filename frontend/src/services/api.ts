import type { AnalyzeRequest, HealthResponse, ThreatAnalysis, ThreatCategory } from "../types/api";
import type { AuthStatusResponse, LoginRequest } from "../types/auth";
import type { ThreatGraphNeighborhood } from "../types/intelligence";
import type {
  ClassificationAnalysisRequest,
  ClassificationAnalysisResponse,
  ClassificationResult,
  FeatureImportanceItem,
  NetworkTrafficFeatures,
} from "../types/ml";

// Resolution order: (1) window.__APP_CONFIG__, injected at container startup by
// frontend/docker-entrypoint.sh from the VITE_API_URL environment variable -- this
// is what lets one built Docker image point at different backend URLs without a
// rebuild; (2) import.meta.env.VITE_API_URL, baked in at build time (used by
// `npm run dev`/`npm run build` outside Docker); (3) the local-dev default.
const API_URL = window.__APP_CONFIG__?.VITE_API_URL || import.meta.env.VITE_API_URL || "http://localhost:8000";

const REQUEST_TIMEOUT_MS = 60_000;

// Must match backend/sessions.py exactly. The CSRF cookie is deliberately NOT
// HttpOnly -- reading it here and echoing it back as a header is the whole point of
// the double-submit CSRF pattern. This is not a secret: it only proves this page's
// own JS (not a third-party site) made the request; the actual credential is the
// separate, HttpOnly session cookie that this code can never read.
const CSRF_COOKIE_NAME = "cyber_ai_csrf";
const CSRF_HEADER_NAME = "X-CSRF-Token";

/** Dispatched whenever any request comes back 401, except /auth/login itself (a
 * failed login attempt isn't "your session expired"). AuthContext listens for this
 * to drop the app back to the login page instead of leaving pages stuck on a
 * generic error. */
export const UNAUTHORIZED_EVENT = "cyber-ai:unauthorized";

/** Thrown for every failure mode: network-down, timeout, non-2xx, and malformed responses. */
export class ApiError extends Error {
  readonly status: number | null;

  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

function readCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  const method = (init?.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };

  // CSRF header is only meaningful (and only checked server-side) for
  // state-changing requests authenticated by the session cookie.
  if (method !== "GET" && method !== "HEAD") {
    const csrfToken = readCookie(CSRF_COOKIE_NAME);
    if (csrfToken) {
      headers[CSRF_HEADER_NAME] = csrfToken;
    }
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      credentials: "include", // send/receive the HttpOnly session + CSRF cookies
      signal: controller.signal,
      headers,
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
    if (response.status === 401 && path !== "/auth/login") {
      window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    }

    let detail = `Request failed with status ${response.status}.`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") {
        detail = body.detail;
      } else if (Array.isArray(body?.detail)) {
        // FastAPI/Pydantic validation errors: a list of {loc, msg, ...}.
        const messages = body.detail
          .slice(0, 5)
          .map((error: { loc?: unknown[]; msg?: string }) => {
            const field = Array.isArray(error.loc) ? error.loc.at(-1) : undefined;
            return field ? `${field}: ${error.msg}` : error.msg;
          })
          .filter(Boolean);
        if (messages.length > 0) {
          detail = messages.join("; ");
        }
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

export function login(payload: LoginRequest): Promise<AuthStatusResponse> {
  return request<AuthStatusResponse>("/auth/login", { method: "POST", body: JSON.stringify(payload) });
}

export function logout(): Promise<AuthStatusResponse> {
  return request<AuthStatusResponse>("/auth/logout", { method: "POST" });
}

export function getAuthStatus(): Promise<AuthStatusResponse> {
  return request<AuthStatusResponse>("/auth/me");
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

export function classifyTraffic(features: NetworkTrafficFeatures): Promise<ClassificationResult> {
  return request<ClassificationResult>("/classify", { method: "POST", body: JSON.stringify(features) });
}

export function getFeatureImportance(): Promise<FeatureImportanceItem[]> {
  return request<FeatureImportanceItem[]>("/ml/feature-importance");
}

export function analyzeClassification(
  payload: ClassificationAnalysisRequest,
): Promise<ClassificationAnalysisResponse> {
  return request<ClassificationAnalysisResponse>("/analyze/classification", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** Public endpoint (Phase 9) -- no auth/CSRF required, same as getThreats(). */
export function getThreatGraph(threatId: string): Promise<ThreatGraphNeighborhood> {
  return request<ThreatGraphNeighborhood>(`/intelligence/graph/${encodeURIComponent(threatId)}`);
}
