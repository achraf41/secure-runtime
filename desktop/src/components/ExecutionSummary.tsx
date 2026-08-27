import type { ExecutionResult } from "../types";

function formatDuration(milliseconds: number) {
  if (!Number.isFinite(milliseconds)) return "—";
  return milliseconds < 1000
    ? Math.round(milliseconds) + " ms"
    : (milliseconds / 1000).toFixed(2) + " s";
}

export function ExecutionSummary({ result }: { result: ExecutionResult }) {
  const outcomeLabels = {
    exited: "Exited",
    signaled: "Terminated by signal",
    timedOut: "Timed out",
    outputLimitExceeded: "Output limited",
  };
  const enforcementMessage = result.outcome === "outputLimitExceeded"
    ? "Execution stopped because the application exceeded the configured output limit."
    : result.outcome === "timedOut"
      ? "Execution stopped because the configured wall-clock timeout was exceeded."
      : null;
  const outputUsage = result.outputLimitBytes == null
    ? result.outputBytesObserved + " bytes"
    : result.outputBytesObserved + " / " + result.outputLimitBytes + " bytes";
  const values: Array<[string, string | number]> = [
    ["Application ID", result.appId || "—"],
    ["Outcome", outcomeLabels[result.outcome] || "—"],
    ["Runtime", formatDuration(result.runtimeDurationMs)],
    ["Timed out", result.timedOut ? "Yes" : "No"],
    ["Output limited", result.outputLimitExceeded ? "Yes" : "No"],
    ["Output observed", outputUsage],
  ];
  if (result.outcome === "exited" && result.exitCode != null) {
    values.splice(2, 0, ["Exit code", result.exitCode]);
  }
  if (result.outcome === "signaled" && result.terminatingSignal != null) {
    values.splice(2, 0, ["Signal", result.terminatingSignal]);
  }
  return (
    <section className="card results-card">
      <div className="card-title-row">
        <div><span className="eyebrow">Final result</span><h2>Execution Summary</h2></div>
        <span className={"result-mark " + (result.exitCode === 0 ? "success" : "")}>
          {result.exitCode === 0 ? "✓" : "!"}
        </span>
      </div>
      {enforcementMessage && (
        <div className={"outcome-notice " + (result.outcome === "timedOut" ? "timeout" : "")}>
          <strong>{outcomeLabels[result.outcome]}</strong>
          <span>{enforcementMessage}</span>
          {result.outcome === "outputLimitExceeded" && <code>{outputUsage}</code>}
        </div>
      )}
      <div className="summary-grid">
        {values.map(([label, value]) => (
          <div className="summary-item" key={label}><span>{label}</span><strong>{value}</strong></div>
        ))}
      </div>
    </section>
  );
}
