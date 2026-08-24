import { ShieldHalf } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";

import { Card } from "../components/common/Card";
import { useAuth } from "../context/AuthContext";
import { ApiError } from "../services/api";

export function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login({ username, password });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "An unexpected error occurred.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface px-4">
      <Card className="w-full max-w-sm p-8">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <ShieldHalf className="h-8 w-8 text-accent" strokeWidth={1.75} />
          <p className="text-sm font-semibold tracking-wide text-text">CYBER AI</p>
          <p className="text-xs text-text-muted">Sign in to the Threat Intelligence Platform</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="username"
              className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-text-muted"
            >
              Username
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="w-full rounded-md border border-border-strong bg-surface px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
              required
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-text-muted"
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="w-full rounded-md border border-border-strong bg-surface px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
              required
            />
          </div>

          {error ? (
            <p className="rounded-md border border-severity-critical/30 bg-severity-critical/5 px-3 py-2 text-sm text-severity-critical">
              {error}
            </p>
          ) : null}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-md bg-accent px-4 py-2.5 text-sm font-semibold text-surface transition-colors hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </Card>
    </div>
  );
}
