import type { ExecutionOutcome, UiStatus } from "../types";

export function StatusBadge({ status, outcome }: { status: UiStatus; outcome?: ExecutionOutcome }) {
  const outcomeLabels: Record<ExecutionOutcome, string> = {
    exited: "Exited",
    signaled: "Terminated by signal",
    timedOut: "Timed out",
    outputLimitExceeded: "Output limited",
  };
  const statusLabels = { idle: "Idle", running: "Running", finished: "Finished", failed: "Failed" };
  const label = status === "finished" && outcome ? outcomeLabels[outcome] : statusLabels[status];
  return (
    <span className={"status-badge status-" + status}>
      <span className={status === "running" ? "pulse-dot" : "status-dot"} />
      {label}
    </span>
  );
}
