import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { SecurityLogEntry, SecurityLogsResponse } from "../types";
import { formatError } from "../utils/errors";

export interface LogsFilterRequest { appId: string; requestId: number; }

function eventLabel(value: string) {
  return value.split("_").filter(Boolean).map((part) => part[0]?.toUpperCase() + part.slice(1)).join(" ");
}

function timestampLabel(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function decisionClass(value: string | null) {
  const normalized = value?.toLowerCase();
  return normalized === "allow" ? "allow" : normalized === "deny" ? "deny" : "neutral";
}

function formatBytes(value: number | null) {
  if (value === null) return "Not available";
  return value < 1024 * 1024 ? value.toLocaleString() + " bytes" : (value / 1024 / 1024).toFixed(2) + " MB";
}

function formatUsec(value: number | null) {
  if (value === null) return "Not available";
  return value < 1_000_000 ? (value / 1000).toFixed(2) + " ms" : (value / 1_000_000).toFixed(2) + " s";
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><span>{label}</span><strong>{children ?? "Not available"}</strong></div>;
}

export function LogsViewer({ requestedApplication }: { requestedApplication: LogsFilterRequest | null }) {
  const [data, setData] = useState<SecurityLogsResponse | null>(null);
  const [selected, setSelected] = useState<SecurityLogEntry | null>(null);
  const [search, setSearch] = useState("");
  const [application, setApplication] = useState("");
  const [decision, setDecision] = useState("");
  const [eventType, setEventType] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null);

  async function refresh() {
    setLoading(true); setError(null);
    try {
      const response = await invoke<SecurityLogsResponse>("load_security_logs");
      setData(response);
      setSelected(null);
      setRefreshedAt(new Date());
    } catch (loadError) {
      setError(formatError(loadError));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void refresh(); }, []);
  useEffect(() => {
    if (requestedApplication?.appId) {
      setApplication(requestedApplication.appId);
      void refresh();
    }
  }, [requestedApplication]);

  const newestFirst = useMemo(() => [...(data?.entries ?? [])].reverse(), [data]);
  const applications = useMemo(() => [...new Set(newestFirst.map((entry) => entry.appId))].sort(), [newestFirst]);
  const decisions = useMemo(() => [...new Set(newestFirst.flatMap((entry) => entry.decision ? [entry.decision] : []))].sort(), [newestFirst]);
  const eventTypes = useMemo(() => [...new Set(newestFirst.map((entry) => entry.eventType))].sort(), [newestFirst]);
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return newestFirst.filter((entry) => {
      const matchesSearch = !query || [entry.appId, entry.eventType, entry.reason ?? ""].some((value) => value.toLowerCase().includes(query));
      return matchesSearch && (!application || entry.appId === application) && (!decision || entry.decision === decision) && (!eventType || entry.eventType === eventType);
    });
  }, [newestFirst, search, application, decision, eventType]);

  const isResource = selected?.eventType === "resource_usage";

  return <div className="dashboard logs-page">
    <section className="intro-row"><div><h2>Security logs</h2><p>Read-only audit events recorded by desktop secure-runtime executions.</p></div><div className="logs-refresh"><span>{refreshedAt ? "Last refreshed " + refreshedAt.toLocaleTimeString() : "Not refreshed"}</span><button className="secondary-button" disabled={loading} onClick={() => void refresh()} type="button">{loading ? "Refreshing…" : "Refresh"}</button></div></section>

    <section className="card logs-toolbar"><label className="logs-search"><span>⌕</span><input aria-label="Search security logs" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search application, event, or reason…" /></label><select aria-label="Filter by event" value={eventType} onChange={(event) => setEventType(event.target.value)}><option value="">All events</option>{eventTypes.map((value) => <option key={value} value={value}>{eventLabel(value)}</option>)}</select><select aria-label="Filter by decision" value={decision} onChange={(event) => setDecision(event.target.value)}><option value="">All decisions</option>{decisions.map((value) => <option key={value} value={value}>{value}</option>)}</select><select aria-label="Filter by application" value={application} onChange={(event) => setApplication(event.target.value)}><option value="">All applications</option>{applications.map((value) => <option key={value} value={value}>{value}</option>)}</select>{(search || application || decision || eventType) && <button className="text-button clear-filters" onClick={() => { setSearch(""); setApplication(""); setDecision(""); setEventType(""); }} type="button">Clear filters</button>}</section>

    {error && <div className="error-banner" role="alert"><span>!</span><div><strong>Logs could not be loaded</strong><p>{error}</p></div></div>}
    {data && data.malformedLines > 0 && <div className="logs-warning" role="status">Skipped {data.malformedLines} malformed or unreadable JSONL {data.malformedLines === 1 ? "line" : "lines"}. Valid events remain available.</div>}
    {data?.limited && <div className="logs-limit">Showing the most recent {data.maxEntries.toLocaleString()} of {data.validEntriesSeen.toLocaleString()} valid events.</div>}

    <div className="logs-layout">
      <section className="card logs-table-card">
        <div className="logs-table-meta"><span>{filtered.length.toLocaleString()} events shown</span>{data && <code title={data.sourcePath}>{data.sourcePath}</code>}</div>
        {loading && !data ? <div className="logs-empty loading-state"><span className="button-spinner" /><h2>Loading security events…</h2><p>Reading the most recent desktop audit records.</p></div> : !loading && data && data.entries.length === 0 ? <div className="logs-empty"><span>≡</span><h2>No security events have been recorded yet.</h2><p>Events will appear here after running sandboxed applications from the desktop.</p></div> : (
          <div className="logs-table-wrap"><table className="logs-table"><thead><tr><th>Timestamp</th><th>Application</th><th>Event</th><th>Decision</th></tr></thead><tbody>{filtered.map((entry, index) => <tr aria-label={eventLabel(entry.eventType) + " for " + entry.appId} className={selected === entry ? "selected" : ""} key={entry.timestamp + entry.appId + entry.eventType + index} onClick={() => setSelected(entry)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setSelected(entry); } }} role="button" tabIndex={0}><td><time title={entry.timestamp}>{timestampLabel(entry.timestamp)}</time></td><td><code>{entry.appId}</code></td><td><span className="event-label">{eventLabel(entry.eventType)}</span></td><td>{entry.decision ? <span className={"decision-pill " + decisionClass(entry.decision)}>{entry.decision}</span> : <span className="not-applicable">Not applicable</span>}</td></tr>)}</tbody></table>{!loading && data && data.entries.length > 0 && filtered.length === 0 && <div className="logs-no-match">No events match the current search and filters.</div>}</div>
        )}
      </section>

      <aside className="card log-details">
        <div className="policy-section-title"><span>i</span><div><h2>Event details</h2><p>{selected ? "Complete stored event fields" : "Select an event"}</p></div></div>
        {!selected ? <div className="detail-empty">Select a row to inspect its complete audit record.</div> : <><button className="secondary-button filter-application-action" onClick={() => setApplication(selected.appId)} type="button">Filter by this application</button><div className="detail-grid"><Detail label="Timestamp">{timestampLabel(selected.timestamp)}</Detail><Detail label="Application">{selected.appId}</Detail><Detail label="Event type">{eventLabel(selected.eventType)}</Detail><Detail label="Raw event type"><code>{selected.eventType}</code></Detail>{selected.decision !== null && <Detail label="Decision"><span className={"decision-pill " + decisionClass(selected.decision)}>{selected.decision}</span></Detail>}{selected.riskScore !== null && <Detail label="Risk score">{selected.riskScore}</Detail>}{selected.reason !== null && <div className="detail-reason"><span>Reason</span><p>{selected.reason}</p></div>}</div>{isResource && <div className="resource-detail"><h3>Resource usage</h3><div className="detail-grid"><Detail label="Peak memory">{formatBytes(selected.memoryPeakBytes)}</Detail><Detail label="CPU usage">{formatUsec(selected.cpuUsageUsec)}</Detail><Detail label="CPU user">{formatUsec(selected.cpuUserUsec)}</Detail><Detail label="CPU system">{formatUsec(selected.cpuSystemUsec)}</Detail><Detail label="Throttle events">{selected.cpuNrThrottled ?? "Not available"}</Detail><Detail label="CPU throttled">{formatUsec(selected.cpuThrottledUsec)}</Detail><Detail label="Peak processes">{selected.pidsPeak ?? "Not available"}</Detail><Detail label="OOM count">{selected.oomCount ?? "Not available"}</Detail><Detail label="OOM kill count">{selected.oomKillCount ?? "Not available"}</Detail></div></div>}</>}
      </aside>
    </div>
  </div>;
}
