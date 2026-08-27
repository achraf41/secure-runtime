import type { CgroupStats } from "../types";

function bytesToMb(value: number | null) {
  return value == null ? "—" : (value / 1024 / 1024).toFixed(2) + " MB";
}
function usecToReadable(value: number | null) {
  if (value == null) return "—";
  const milliseconds = value / 1000;
  return milliseconds < 1000
    ? milliseconds.toFixed(2) + " ms"
    : (milliseconds / 1000).toFixed(2) + " s";
}

export function ResourceStats({ stats }: { stats: CgroupStats | null }) {
  return (
    <section className="card resource-card">
      <div><span className="eyebrow">cgroup v2</span><h2>Resource Statistics</h2></div>
      {!stats ? (
        <p className="unavailable">Cgroup statistics unavailable for this execution.</p>
      ) : (
        <div className="resource-grid">
          <div><span>Peak Memory</span><strong>{bytesToMb(stats.memoryPeakBytes)}</strong></div>
          <div><span>CPU Usage</span><strong>{usecToReadable(stats.cpuUsageUsec)}</strong></div>
          <div><span>CPU User</span><strong>{usecToReadable(stats.cpuUserUsec)}</strong></div>
          <div><span>CPU System</span><strong>{usecToReadable(stats.cpuSystemUsec)}</strong></div>
          <div><span>CPU Throttled</span><strong>{usecToReadable(stats.cpuThrottledUsec)}</strong></div>
          <div><span>Peak Processes</span><strong>{stats.pidsPeak ?? "—"}</strong></div>
          <div><span>OOM Count</span><strong>{stats.oomCount ?? "—"}</strong></div>
          <div><span>OOM Kill Count</span><strong>{stats.oomKillCount ?? "—"}</strong></div>
        </div>
      )}
    </section>
  );
}
