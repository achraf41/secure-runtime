import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import type { PolicyViewResponse } from "../types";
import { formatError } from "../utils/errors";

interface PolicyViewerProps {
  initialPath: string;
  onUseForRun: (path: string) => void;
  onUseApplication: (path: string, appPath: string) => void;
  onCreate: () => void;
  onEdit: (policy: PolicyViewResponse["policy"], path: string) => void;
}

function OptionalValue({ value, suffix = "" }: { value: string | number | null; suffix?: string }) {
  return <strong>{value === null ? "Not specified" : value + suffix}</strong>;
}

function ToggleBadge({ label, value }: { label: string; value: boolean | null }) {
  const state = value === null ? "unspecified" : value ? "enabled" : "disabled";
  return <span className={"policy-toggle " + state}><i />{label}: {value === null ? "Not specified" : value ? "Enabled" : "Disabled"}</span>;
}

function PathList({ title, paths }: { title: string; paths: string[] }) {
  return (
    <div className="policy-list-group">
      <div className="policy-list-heading"><span>{title}</span><b>{paths.length}</b></div>
      {paths.length ? <ul>{paths.map((path) => <li key={path}><code>{path}</code></li>)}</ul> : <p>None configured</p>}
    </div>
  );
}

function PortList({ title, ports }: { title: string; ports: number[] | null }) {
  return (
    <div className="policy-list-group">
      <div className="policy-list-heading"><span>{title}</span><b>{ports?.length ?? 0}</b></div>
      {ports?.length ? <div className="policy-chips">{ports.map((port) => <code key={port}>{port}</code>)}</div> : <p>None configured</p>}
    </div>
  );
}

export function PolicyViewer({ initialPath, onUseForRun, onUseApplication, onCreate, onEdit }: PolicyViewerProps) {
  const [path, setPath] = useState(initialPath);
  const [view, setView] = useState<PolicyViewResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadPolicy(selectedPath: string) {
    setPath(selectedPath);
    setLoading(true);
    setError(null);
    setView(null);
    try {
      setView(await invoke<PolicyViewResponse>("load_policy", { path: selectedPath }));
    } catch (loadError) {
      setError(formatError(loadError));
    } finally {
      setLoading(false);
    }
  }

  async function browse() {
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [{ name: "JSON policy", extensions: ["json"] }],
      });
      if (typeof selected === "string") await loadPolicy(selected);
    } catch (browseError) {
      setError(formatError(browseError));
    }
  }

  useEffect(() => {
    if (initialPath) void loadPolicy(initialPath);
  }, []);

  const policy = view?.policy;

  return (
    <div className="dashboard policy-page">
      <section className="intro-row">
        <div><h2>Policy viewer</h2><p>Inspect a parsed and validated secure-runtime policy before execution.</p></div>
        <div className="policy-header-actions"><button className="secondary-button policy-browse" onClick={onCreate} type="button">Create Policy</button><button className="secondary-button policy-browse" onClick={browse} disabled={loading} type="button">{loading ? "Validating…" : "Browse JSON"}</button></div>
      </section>

      <section className="card policy-source-card">
        <div><span>Selected policy</span><code>{path || "No policy selected"}</code></div>
        {policy && <span className="validated-badge"><i />Validated by secure-runtime</span>}
      </section>

      {error && <div className="error-banner" role="alert"><span>!</span><div><strong>Policy could not be loaded</strong><p>{error}</p></div></div>}

      {loading && <section className="card policy-empty loading-state"><span className="button-spinner" /><h2>Loading and validating policy…</h2><p>secure-runtime is parsing the selected JSON document.</p></section>}

      {!policy && !error && !loading && (
        <section className="card policy-empty"><span>◇</span><h2>Select a JSON policy to inspect</h2><p>Parsing, version checks, and policy validation are performed by secure-runtime.</p></section>
      )}

      {policy && (
        <>
          <div className="policy-actions">
            <div><strong>{policy.appId}</strong><span>Validated policy version {policy.policyVersion}</span></div>
            <div className="policy-action-buttons"><button className="secondary-button" onClick={() => onEdit(policy, path)} type="button">Edit Policy</button>{policy.appPath && <button className="secondary-button" onClick={() => onUseApplication(path, policy.appPath)} type="button">Use Policy Application</button>}<button className="run-button" onClick={() => onUseForRun(path)} type="button">Use for Run <span>→</span></button></div>
          </div>

          <div className="policy-grid">
            <section className="card policy-section identity-section">
              <div className="policy-section-title"><span>01</span><div><h2>Application identity</h2><p>Executable identity and policy defaults</p></div></div>
              <div className="policy-field-grid">
                <div><span>Policy version</span><strong>{policy.policyVersion}</strong></div>
                <div><span>Application ID</span><strong>{policy.appId}</strong></div>
                <div className="wide"><span>Executable path</span><code>{policy.appPath}</code></div>
                <div className="wide"><span>SHA-256</span><code>{policy.appHash}</code></div>
                <div><span>Default action</span><strong className="policy-value-badge">{policy.defaultAction}</strong></div>
              </div>
            </section>

            <section className="card policy-section filesystem-section">
              <div className="policy-section-title"><span>02</span><div><h2>Filesystem</h2><p>Path access rules</p></div></div>
              <div className="policy-list-grid">
                <PathList title="Read allow" paths={policy.filesystem.readAllow} />
                <PathList title="Write allow" paths={policy.filesystem.writeAllow} />
                <PathList title="Execute allow" paths={policy.filesystem.execAllow} />
                <PathList title="Deny" paths={policy.filesystem.deny} />
              </div>
            </section>

            {policy.network && (
              <section className="card policy-section">
                <div className="policy-section-title"><span>03</span><div><h2>Network</h2><p>Configured TCP port rules</p></div></div>
                <div className="policy-list-grid"><PortList title="Connect TCP" ports={policy.network.connectTcp} /><PortList title="Bind TCP" ports={policy.network.bindTcp} /></div>
              </section>
            )}

            {policy.seccomp && (
              <section className="card policy-section">
                <div className="policy-section-title"><span>04</span><div><h2>Seccomp</h2><p>System call filtering configuration</p></div></div>
                <div className="policy-field-grid"><div><span>Profile</span><OptionalValue value={policy.seccomp.profile} /></div></div>
                <PathList title="Custom denied syscalls" paths={policy.seccomp.deny ?? []} />
              </section>
            )}

            {policy.namespace && (
              <section className="card policy-section">
                <div className="policy-section-title"><span>05</span><div><h2>Namespaces</h2><p>Linux isolation namespace settings</p></div></div>
                <div className="policy-toggle-row">
                  <ToggleBadge label="IPC" value={policy.namespace.ipc} />
                  <ToggleBadge label="Network" value={policy.namespace.network} />
                  <ToggleBadge label="PID" value={policy.namespace.pid} />
                </div>
                {policy.namespace.uts && <div className="policy-subsection"><h3>UTS</h3><ToggleBadge label="UTS" value={policy.namespace.uts.enabled} /><div className="inline-detail"><span>Hostname</span><OptionalValue value={policy.namespace.uts.hostname} /></div></div>}
                {policy.namespace.mount && <div className="policy-subsection"><h3>Mount</h3><div className="policy-toggle-row"><ToggleBadge label="Mount" value={policy.namespace.mount.enabled} /><ToggleBadge label="Private /tmp" value={policy.namespace.mount.privateTmp} /></div><div className="inline-detail"><span>Temporary filesystem size</span><OptionalValue value={policy.namespace.mount.tmpSizeMb} suffix=" MB" /></div></div>}
              </section>
            )}

            {policy.resources && (
              <section className="card policy-section resources-section">
                <div className="policy-section-title"><span>06</span><div><h2>Resource limits</h2><p>Execution and resource ceilings</p></div></div>
                <div className="policy-field-grid four-columns">
                  <div><span>Timeout</span><OptionalValue value={policy.resources.timeoutSeconds} suffix=" s" /></div>
                  <div><span>Maximum output</span><OptionalValue value={policy.resources.maxOutputKb} suffix=" KB" /></div>
                  <div><span>Memory</span><OptionalValue value={policy.resources.memoryMb} suffix=" MB" /></div>
                  <div><span>Maximum processes</span><OptionalValue value={policy.resources.maxProcesses} /></div>
                </div>
                {policy.resources.rlimit && <div className="policy-subsection"><h3>rlimit</h3><ToggleBadge label="rlimit" value={policy.resources.rlimit.enabled} /><div className="policy-field-grid"><div><span>CPU time</span><OptionalValue value={policy.resources.rlimit.cpuSeconds} suffix=" s" /></div><div><span>Maximum file size</span><OptionalValue value={policy.resources.rlimit.maxFileSizeMb} suffix=" MB" /></div></div></div>}
                {policy.resources.cgroup && <div className="policy-subsection"><h3>cgroup v2</h3><ToggleBadge label="cgroup" value={policy.resources.cgroup.enabled} /><div className="inline-detail"><span>CPU allocation</span><OptionalValue value={policy.resources.cgroup.cpuPercent} suffix="%" /></div></div>}
              </section>
            )}
          </div>

          <details className="card raw-policy">
            <summary>Raw JSON <span>Validated policy document</span></summary>
            <pre>{JSON.stringify(view.rawJson, null, 2)}</pre>
          </details>
        </>
      )}
    </div>
  );
}
