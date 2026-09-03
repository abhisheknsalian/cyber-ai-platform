import { ShieldHalf } from "lucide-react";
import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import { Card } from "../components/common/Card";
import { useAuth } from "../context/AuthContext";
import { ApiError } from "../services/api";

export function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    try {
      await register({ username, password });
      setSuccess(true);
      // Brief pause so the success state is actually visible before the redirect.
      setTimeout(() => navigate("/login"), 1200);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "An unexpected error occurred.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden px-4">
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-1/2 h-[560px] w-[560px] -translate-x-1/2 -translate-y-1/2 rounded-full"
        style={{
          background: "radial-gradient(circle, color-mix(in srgb, var(--color-accent) 12%, transparent), transparent 70%)",
        }}
      />
      <Card glow="accent" className="relative w-full max-w-sm p-8">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <ShieldHalf className="h-8 w-8 text-accent" strokeWidth={1.75} />
          <p className="text-sm font-semibold tracking-[0.2em] text-text">CYBER AI</p>
          <p className="font-mono text-[11px] uppercase tracking-wider text-text-faint">Create Account</p>
        </div>

        {success ? (
          <p
            role="status"
            className="rounded-md border border-benign/30 bg-benign/5 px-3 py-2.5 text-center text-sm text-benign-strong"
          >
            Account created. Redirecting to sign in…
          </p>
        ) : (
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
                className="w-full rounded-md border border-border-strong bg-surface-sunken px-3 py-2 font-mono text-sm text-text focus:border-accent focus:outline-none"
                required
                minLength={3}
                maxLength={64}
              />
              <p className="mt-1 font-mono text-[10px] text-text-faint">3-64 characters, or a valid email address.</p>
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
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="w-full rounded-md border border-border-strong bg-surface-sunken px-3 py-2 font-mono text-sm text-text focus:border-accent focus:outline-none"
                required
                minLength={8}
              />
              <p className="mt-1 font-mono text-[10px] text-text-faint">At least 8 characters, with a letter and a number.</p>
            </div>

            <div>
              <label
                htmlFor="confirm-password"
                className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-text-muted"
              >
                Confirm Password
              </label>
              <input
                id="confirm-password"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                className="w-full rounded-md border border-border-strong bg-surface-sunken px-3 py-2 font-mono text-sm text-text focus:border-accent focus:outline-none"
                required
              />
            </div>

            {error ? (
              <p role="alert" className="rounded-md border border-malicious/30 bg-malicious/5 px-3 py-2 text-sm text-malicious-strong">
                {error}
              </p>
            ) : null}

            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-md bg-accent px-4 py-2.5 text-sm font-semibold text-surface transition-colors hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
            >
              {submitting ? "Creating account…" : "Create account"}
            </button>
          </form>
        )}

        <p className="mt-6 text-center font-mono text-[11px] text-text-faint">
          Already have an account?{" "}
          <Link to="/login" className="text-accent hover:text-accent-strong">
            Sign in
          </Link>
        </p>
      </Card>
    </div>
  );
}
