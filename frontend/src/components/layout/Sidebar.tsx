import { Info, LayoutDashboard, Library, LogOut, Radar, Search, ShieldHalf } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { NavLink } from "react-router-dom";

import { useAuth } from "../../context/AuthContext";
import { useHealth } from "../../hooks/useHealth";
import { useReadiness } from "../../hooks/useReadiness";
import type { SystemStatusState } from "../common/StatusDot";
import { StatusDot } from "../common/StatusDot";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  end: boolean;
}

interface NavGroup {
  heading: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  { heading: "Overview", items: [{ to: "/", label: "Dashboard", icon: LayoutDashboard, end: true }] },
  {
    heading: "Detection",
    items: [
      { to: "/detection", label: "Network Detection", icon: Radar, end: false },
      { to: "/analyze", label: "Threat Analysis", icon: Search, end: false },
    ],
  },
  { heading: "Intelligence", items: [{ to: "/intelligence", label: "Threat Intelligence", icon: Library, end: false }] },
  { heading: "System", items: [{ to: "/about", label: "About", icon: Info, end: false }] },
];

function deriveState(loading: boolean, error: string | null, ok: boolean | undefined): SystemStatusState {
  if (loading) return "checking";
  if (error || ok === undefined) return "offline";
  return ok ? "online" : "offline";
}

export function Sidebar() {
  const { username, logout } = useAuth();
  const { health, loading: healthLoading, error: healthError } = useHealth();
  const { readiness, loading: readinessLoading, error: readinessError } = useReadiness();

  // The API itself is "online" if either call actually reached it and got a
  // response -- independent of whether the sub-dependencies it reports on (RAG,
  // LLM, ML engine) are themselves healthy.
  const apiState: SystemStatusState =
    healthLoading && readinessLoading ? "checking" : health !== null || readiness !== null ? "online" : "offline";
  const ragState = deriveState(healthLoading, healthError, health?.vector_store.available);
  const llmState = deriveState(healthLoading, healthError, health?.llm.reachable);
  const mlState = deriveState(readinessLoading, readinessError, readiness?.checks.classifier);

  return (
    <aside className="flex shrink-0 flex-col border-b border-border bg-surface shadow-[inset_-1px_0_0_0_rgba(23,230,206,0.04)] lg:h-screen lg:w-64 lg:border-b-0 lg:border-r">
      <div className="flex items-center gap-2.5 border-b border-border px-5 py-4 lg:py-5">
        <ShieldHalf className="h-6 w-6 shrink-0 text-accent" strokeWidth={1.75} />
        <div>
          <p className="text-sm font-semibold tracking-[0.15em] text-text">CYBER AI</p>
          <p className="font-mono text-[10px] uppercase tracking-wider text-text-faint">Threat Intelligence Platform</p>
        </div>
      </div>

      <nav className="flex flex-1 flex-col gap-4 overflow-y-auto px-3 py-4 lg:py-5">
        {NAV_GROUPS.map((group) => (
          <div key={group.heading}>
            <p className="mb-1.5 px-3 font-mono text-[10px] font-semibold uppercase tracking-[0.15em] text-text-faint">
              {group.heading}
            </p>
            <div className="flex flex-col gap-0.5">
              {group.items.map(({ to, label, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    [
                      "group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                      isActive
                        ? "bg-surface-hover text-text shadow-[inset_0_0_0_1px_var(--color-border-active)]"
                        : "text-text-muted hover:bg-surface-hover hover:text-text",
                    ].join(" ")
                  }
                >
                  {({ isActive }) => (
                    <>
                      <span
                        className={`absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-accent transition-opacity ${
                          isActive ? "opacity-100" : "opacity-0"
                        }`}
                        aria-hidden
                      />
                      <Icon className="h-4 w-4 shrink-0" strokeWidth={1.75} />
                      {label}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="border-t border-border px-4 py-3">
        <p className="mb-2 px-1 font-mono text-[10px] font-semibold uppercase tracking-[0.15em] text-text-faint">
          System Status
        </p>
        <div className="rounded-md border border-border bg-surface-sunken px-3 py-2">
          <StatusDot label="API" state={apiState} />
          <StatusDot label="RAG Engine" state={ragState} />
          <StatusDot label="LLM" state={llmState} />
          <StatusDot label="ML Engine" state={mlState} />
        </div>
      </div>

      <div className="flex items-center justify-between gap-2 border-t border-border px-5 py-4">
        <div className="min-w-0">
          <p className="text-[11px] text-text-faint">Local-first · RAG + Ollama</p>
          {username ? <p className="mt-0.5 truncate text-xs text-text-muted">Signed in as {username}</p> : null}
        </div>
        <button
          type="button"
          onClick={() => logout()}
          className="flex shrink-0 items-center gap-1.5 rounded-md border border-transparent px-2 py-1.5 text-xs text-text-muted transition-colors hover:border-border-strong hover:bg-surface-hover hover:text-text"
        >
          <LogOut className="h-3.5 w-3.5" strokeWidth={1.75} />
          Log out
        </button>
      </div>
    </aside>
  );
}
