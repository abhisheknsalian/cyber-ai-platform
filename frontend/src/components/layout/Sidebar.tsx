import { Info, LayoutDashboard, Library, Radar, ShieldHalf, Search } from "lucide-react";
import { NavLink } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/analyze", label: "Threat Analysis", icon: Search, end: false },
  { to: "/detection", label: "Network Detection", icon: Radar, end: false },
  { to: "/intelligence", label: "Threat Intelligence", icon: Library, end: false },
  { to: "/about", label: "About", icon: Info, end: false },
];

export function Sidebar() {
  return (
    <aside className="flex shrink-0 flex-col border-b border-border bg-surface-raised lg:w-64 lg:border-b-0 lg:border-r">
      <div className="flex items-center gap-2.5 border-b border-border px-5 py-4 lg:py-5">
        <ShieldHalf className="h-6 w-6 shrink-0 text-accent" strokeWidth={1.75} />
        <div>
          <p className="text-sm font-semibold tracking-wide text-text">CYBER AI</p>
          <p className="text-xs text-text-muted">Threat Intelligence Platform</p>
        </div>
      </div>

      <nav className="flex flex-wrap gap-1 px-3 py-3 lg:flex-col lg:py-4">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              [
                "flex items-center gap-3 rounded-md border px-3 py-2 text-sm transition-colors",
                isActive
                  ? "border-border-strong bg-surface-hover text-text"
                  : "border-transparent text-text-muted hover:bg-surface-hover hover:text-text",
              ].join(" ")
            }
          >
            <Icon className="h-4 w-4" strokeWidth={1.75} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto hidden border-t border-border px-5 py-4 lg:block">
        <p className="text-xs text-text-faint">Local-first · RAG + Ollama</p>
      </div>
    </aside>
  );
}
