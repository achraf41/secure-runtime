export type AppView = "run" | "policy" | "logs";

const items = [
  { label: "Dashboard", icon: "⌂", view: "run" as AppView, target: "dashboard" },
  { label: "Run Application", icon: "▶", view: "run" as AppView, target: "run-application" },
  { label: "Policy", icon: "◇", view: "policy" as AppView, target: null },
  { label: "Logs", icon: "≡", view: "logs" as AppView, target: null },
];

interface SidebarProps {
  activeView: AppView;
  onNavigate: (view: AppView, target: string | null) => void;
}

export function Sidebar({ activeView, onNavigate }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="brand-mark" aria-hidden="true"><span /></div>
      <nav className="sidebar-nav" aria-label="Primary navigation">
        {items.map((item) => (
          <button
            className={"nav-item " + (item.view === activeView && item.label !== "Run Application" ? "selected" : "")}
            disabled={!item.view}
            key={item.label}
            onClick={() => item.view && onNavigate(item.view, item.target)}
            title={!item.view ? item.label + " is coming soon" : item.label}
            type="button"
          >
            <span className="nav-icon" aria-hidden="true">{item.icon}</span>
            <span>{item.label}</span>
            {!item.view && <span className="soon-label">Soon</span>}
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        <span className="health-dot" />
        <div><strong>Runtime ready</strong><small>Local Linux host</small></div>
      </div>
    </aside>
  );
}
