import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import "./App.css";
import { ExecutionSummary } from "./components/ExecutionSummary";
import { FileSelector } from "./components/FileSelector";
import { PolicyViewer } from "./components/PolicyViewer";
import { PolicyBuilder } from "./components/PolicyBuilder";
import { LogsViewer, type LogsFilterRequest } from "./components/LogsViewer";
import { ResourceStats } from "./components/ResourceStats";
import { SecurityCapabilities } from "./components/SecurityCapabilities";
import { Sidebar, type AppView } from "./components/Sidebar";
import { StatusBadge } from "./components/StatusBadge";
import { TerminalPanel } from "./components/TerminalPanel";
import type {
  ExecutionResult,
  OutputEvent,
  RunStatusEvent,
  RuntimeFinishedEvent,
  TerminalChunk,
  UiStatus,
  PolicyDto,
} from "./types";
import { formatError } from "./utils/errors";

function parseArguments(input: string): string[] {
  const trimmed = input.trim();
  return trimmed ? trimmed.split(/\s+/) : [];
}

function App() {
  const [activeView, setActiveView] = useState<AppView>("run");
  const [policyMode, setPolicyMode] = useState<"view" | "builder">("view");
  const [editingPolicy, setEditingPolicy] = useState<PolicyDto | null>(null);
  const [editingPolicyPath, setEditingPolicyPath] = useState("");
  const [policyViewRequestId, setPolicyViewRequestId] = useState(0);
  const [executablePath, setExecutablePath] = useState("");
  const [policyPath, setPolicyPath] = useState("");
  const [argumentText, setArgumentText] = useState("");
  const [status, setStatus] = useState<UiStatus>("idle");
  const [currentRunId, setCurrentRunId] = useState<string | null>(null);
  const [chunks, setChunks] = useState<TerminalChunk[]>([]);
  const [result, setResult] = useState<ExecutionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [logsFilterRequest, setLogsFilterRequest] = useState<LogsFilterRequest | null>(null);

  const activeRunIdRef = useRef<string | null>(null);
  const completedRunIdRef = useRef<string | null>(null);
  const startingRef = useRef(false);
  const chunkIdRef = useRef(0);

  useEffect(() => {
    let disposed = false;
    const unlisteners: UnlistenFn[] = [];

    async function subscribe() {
      const statusUnlisten = await listen<RunStatusEvent>("runtime://status", ({ payload }) => {
        if (!payload?.runId) return;
        if (activeRunIdRef.current === null && startingRef.current) {
          activeRunIdRef.current = payload.runId;
          setCurrentRunId(payload.runId);
        }
        if (activeRunIdRef.current !== payload.runId) return;
        setStatus("running");
      });
      if (disposed) statusUnlisten(); else unlisteners.push(statusUnlisten);

      const outputUnlisten = await listen<OutputEvent>("runtime://output", ({ payload }) => {
        if (!payload || activeRunIdRef.current !== payload.runId) return;
        if (payload.stream !== "stdout" && payload.stream !== "stderr") return;
        setChunks((previous) => [
          ...previous,
          { id: chunkIdRef.current++, stream: payload.stream, text: payload.text ?? "" },
        ]);
      });
      if (disposed) outputUnlisten(); else unlisteners.push(outputUnlisten);

      const finishedUnlisten = await listen<RuntimeFinishedEvent>("runtime://finished", ({ payload }) => {
        if (!payload || activeRunIdRef.current !== payload.runId) return;
        completedRunIdRef.current = payload.runId;
        activeRunIdRef.current = null;
        startingRef.current = false;
        if (payload.status === "failed") {
          setError(payload.error || "The secure runtime reported an unknown error.");
          setResult(null);
          setStatus("failed");
        } else {
          setResult(payload);
          setError(null);
          setStatus("finished");
        }
      });
      if (disposed) finishedUnlisten(); else unlisteners.push(finishedUnlisten);
    }

    void subscribe();
    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, []);

  async function startRun() {
    if (!executablePath || !policyPath || status === "running") return;
    startingRef.current = true;
    activeRunIdRef.current = null;
    completedRunIdRef.current = null;
    setCurrentRunId(null);
    setChunks([]);
    setResult(null);
    setError(null);
    setStatus("running");

    try {
      const runId = await invoke<string>("start_run", {
        executablePath,
        policyPath,
        arguments: parseArguments(argumentText),
      });
      if (completedRunIdRef.current === runId) return;
      if (activeRunIdRef.current && activeRunIdRef.current !== runId) return;
      activeRunIdRef.current = runId;
      setCurrentRunId(runId);
    } catch (runError) {
      startingRef.current = false;
      activeRunIdRef.current = null;
      setStatus("failed");
      setError(formatError(runError));
    }
  }

  const isRunning = status === "running";
  const canRun = Boolean(executablePath && policyPath) && !isRunning;

  function navigate(view: AppView, target: string | null) {
    setActiveView(view);
    if (target) requestAnimationFrame(() => document.getElementById(target)?.scrollIntoView({ behavior: "smooth" }));
  }

  function usePolicyForRun(path: string) {
    setPolicyPath(path);
    setError(null);
    setActiveView("run");
    requestAnimationFrame(() => document.getElementById("run-application")?.scrollIntoView({ behavior: "smooth" }));
  }

  function usePolicyApplication(path: string, appPath: string) {
    setPolicyPath(path);
    setExecutablePath(appPath);
    setError(null);
    setActiveView("run");
  }

  function createPolicy() {
    setEditingPolicy(null);
    setEditingPolicyPath("");
    setPolicyMode("builder");
  }

  function editPolicy(policy: PolicyDto, path: string) {
    setEditingPolicy(policy);
    setEditingPolicyPath(path);
    setPolicyMode("builder");
  }

  function viewPolicy(path: string) {
    setEditingPolicyPath(path);
    setPolicyViewRequestId((value) => value + 1);
    setPolicyMode("view");
    setActiveView("policy");
  }

  function viewRelatedLogs(appId: string) {
    setLogsFilterRequest({ appId, requestId: Date.now() });
    setActiveView("logs");
  }

  function prepareRunAgain() {
    activeRunIdRef.current = null;
    completedRunIdRef.current = null;
    startingRef.current = false;
    setCurrentRunId(null);
    setChunks([]);
    setResult(null);
    setError(null);
    setStatus("idle");
    setActiveView("run");
  }

  const pageLabel = activeView === "run" ? "Run Application" : activeView === "policy" ? "Policy" : "Logs";

  return (
    <div className="app-shell">
      <Sidebar activeView={activeView} onNavigate={navigate} />
      <main className="main-content">
        <header className="topbar">
          <div>
            <span className="eyebrow">Trusted execution workspace</span>
            <h1>Secure Runtime</h1>
            <p>Linux Application Sandbox</p>
          </div>
          <div className="topbar-context"><div><span>Page</span><strong>{pageLabel}</strong></div><StatusBadge status={status} outcome={result?.outcome} /></div>
        </header>

        <section className="page-view" hidden={activeView !== "run"}>
        <div className="dashboard" id="dashboard">
          <section className="intro-row" id="run-application">
            <div>
              <h2>Run an application securely</h2>
              <p>Select a verified executable and its JSON security policy to begin an isolated run.</p>
            </div>
            {currentRunId && <div className="run-id"><span>Run ID</span><code>{currentRunId}</code></div>}
          </section>

          <div className="selector-grid">
            <FileSelector
              title="Application"
              description="Executable to launch inside the sandbox"
              path={executablePath}
              placeholder="No executable selected"
              disabled={isRunning}
              onSelect={setExecutablePath}
              onError={setError}
            />
            <FileSelector
              title="Security Policy"
              description="JSON policy used to enforce runtime controls"
              path={policyPath}
              placeholder="No policy selected"
              jsonOnly
              disabled={isRunning}
              onSelect={setPolicyPath}
              onError={setError}
              actionLabel="View Policy"
              onAction={() => viewPolicy(policyPath)}
            />
          </div>

          <section className="card launch-card">
            <div className="argument-field">
              <label htmlFor="arguments">Application arguments <span>Optional</span></label>
              <input
                id="arguments"
                value={argumentText}
                disabled={isRunning}
                onChange={(event) => setArgumentText(event.currentTarget.value)}
                placeholder="--mode safe --input /path/to/file"
              />
              <small>V1 splits arguments on whitespace; quoted strings are not interpreted.</small>
            </div>
            <button className="run-button" disabled={!canRun} onClick={startRun} type="button">
              <span className={isRunning ? "button-spinner" : "play-icon"}>{isRunning ? "" : "▶"}</span>
              {isRunning ? "Application Running" : "Run Application"}
            </button>
          </section>

          {error && (
            <div className="error-banner" role="alert">
              <span>!</span><div><strong>Execution failed</strong><p>{error}</p></div>
            </div>
          )}

          <TerminalPanel chunks={chunks} onClear={() => setChunks([])} />

          {result && (
            <><div className="results-grid"><ExecutionSummary result={result} /><ResourceStats stats={result.cgroupStats ?? null} /></div><section className="card result-actions"><div><span className="eyebrow">Next actions</span><strong>Execution complete</strong></div><button className="secondary-button" onClick={prepareRunAgain} type="button">Run Again</button>{policyPath && <button className="secondary-button" onClick={() => viewPolicy(policyPath)} type="button">View Policy</button>}{result.appId && <button className="secondary-button" onClick={() => viewRelatedLogs(result.appId)} type="button">View Related Logs</button>}</section></>
          )}

          <SecurityCapabilities />
        </div>
        </section>

        <section className="page-view" hidden={activeView !== "policy"}>
          {policyMode === "builder" ? <PolicyBuilder initialPolicy={editingPolicy} initialPath={editingPolicyPath} onUseForRun={usePolicyForRun} onViewPolicy={viewPolicy} /> : <PolicyViewer key={(editingPolicyPath || policyPath) + ":" + policyViewRequestId} initialPath={editingPolicyPath || policyPath} onUseForRun={usePolicyForRun} onUseApplication={usePolicyApplication} onCreate={createPolicy} onEdit={editPolicy} />}
        </section>

        <section className="page-view" hidden={activeView !== "logs"}>
          <LogsViewer requestedApplication={logsFilterRequest} />
        </section>
      </main>
    </div>
  );
}

export default App;
