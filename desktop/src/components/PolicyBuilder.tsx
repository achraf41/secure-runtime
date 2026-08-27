import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";
import type { ExecutableHashResult, PolicyDto, PolicyViewResponse } from "../types";
import { formatError } from "../utils/errors";

interface PolicyBuilderProps {
  initialPolicy: PolicyDto | null;
  initialPath: string;
  onUseForRun: (path: string) => void;
  onViewPolicy: (path: string) => void;
}

type ListKey = "readAllow" | "writeAllow" | "execAllow" | "deny";

function TriState({ value, onChange }: { value: boolean | null; onChange: (value: boolean | null) => void }) {
  return <select value={value === null ? "null" : String(value)} onChange={(event) => onChange(event.target.value === "null" ? null : event.target.value === "true")}><option value="null">Not specified</option><option value="true">Enabled</option><option value="false">Disabled</option></select>;
}

function NumberField({ label, value, suffix, onChange }: { label: string; value: number | null; suffix?: string; onChange: (value: number | null) => void }) {
  return <label className="builder-field"><span>{label}</span><div className="number-input"><input min="0" type="number" value={value ?? ""} onChange={(event) => onChange(event.target.value === "" ? null : Number(event.target.value))} />{suffix && <i>{suffix}</i>}</div></label>;
}

function PathEditor({ title, values, executableOnly = false, onChange }: { title: string; values: string[]; executableOnly?: boolean; onChange: (values: string[]) => void }) {
  const [entry, setEntry] = useState("");
  function add(value: string) {
    const trimmed = value.trim();
    if (trimmed && !values.includes(trimmed)) onChange([...values, trimmed]);
    setEntry("");
  }
  async function pick(directory: boolean) {
    const selected = await open({ multiple: false, directory });
    if (typeof selected === "string") add(selected);
  }
  return <div className="builder-list"><div className="builder-list-title"><strong>{title}</strong><span>{values.length}</span></div><div className="builder-add-row"><input value={entry} placeholder="/absolute/path" onChange={(event) => setEntry(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); add(entry); } }} /><button type="button" onClick={() => add(entry)}>Add</button><button type="button" onClick={() => void pick(false)}>File</button>{!executableOnly && <button type="button" onClick={() => void pick(true)}>Folder</button>}</div><div className="builder-chips">{values.map((value) => <span key={value}><code>{value}</code><button aria-label={"Remove " + value} onClick={() => onChange(values.filter((item) => item !== value))} type="button">×</button></span>)}{!values.length && <em>No paths configured</em>}</div></div>;
}

function StringList({ title, values, placeholder, onChange }: { title: string; values: string[]; placeholder: string; onChange: (values: string[]) => void }) {
  const [entry, setEntry] = useState("");
  function add() { const value = entry.trim(); if (value && !values.includes(value)) onChange([...values, value]); setEntry(""); }
  return <div className="builder-list"><div className="builder-list-title"><strong>{title}</strong><span>{values.length}</span></div><div className="builder-add-row"><input value={entry} placeholder={placeholder} onChange={(event) => setEntry(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); add(); } }} /><button onClick={add} type="button">Add</button></div><div className="builder-chips">{values.map((value) => <span key={value}><code>{value}</code><button onClick={() => onChange(values.filter((item) => item !== value))} type="button">×</button></span>)}{!values.length && <em>None configured</em>}</div></div>;
}

function PortEditor({ title, values, onChange }: { title: string; values: number[]; onChange: (values: number[]) => void }) {
  const [entry, setEntry] = useState("");
  const [error, setError] = useState("");
  function add() { const port = Number(entry); if (!Number.isInteger(port) || port < 1 || port > 65535) { setError("Enter a port from 1 to 65535"); return; } if (!values.includes(port)) onChange([...values, port]); setEntry(""); setError(""); }
  return <div className="builder-list"><div className="builder-list-title"><strong>{title}</strong><span>{values.length}</span></div><div className="builder-add-row"><input min="1" max="65535" type="number" value={entry} placeholder="443" onChange={(event) => setEntry(event.target.value)} /><button onClick={add} type="button">Add port</button></div>{error && <small className="field-error">{error}</small>}<div className="builder-chips compact">{values.map((port) => <span key={port}><code>{port}</code><button onClick={() => onChange(values.filter((item) => item !== port))} type="button">×</button></span>)}</div></div>;
}

export function PolicyBuilder({ initialPolicy, initialPath, onUseForRun, onViewPolicy }: PolicyBuilderProps) {
  const [draft, setDraft] = useState<PolicyDto | null>(initialPolicy ? structuredClone(initialPolicy) : null);
  const [path, setPath] = useState(initialPath);
  const [preview, setPreview] = useState("");
  const [status, setStatus] = useState<"dirty" | "valid" | "saved">("dirty");
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (!initialPolicy) void invoke<PolicyDto>("new_policy_draft").then(setDraft).catch((error) => setMessage(formatError(error))); }, [initialPolicy]);

  function update(change: (next: PolicyDto) => void) {
    setDraft((current) => { if (!current) return current; const next = structuredClone(current); change(next); return next; });
    setStatus("dirty"); setMessage(null); setPreview("");
  }

  async function selectExecutable() {
    try {
      const selected = await open({ multiple: false, directory: false });
      if (typeof selected !== "string") return;
      setBusy(true);
      const result = await invoke<ExecutableHashResult>("compute_executable_hash", { path: selected });
      update((next) => { const shouldSuggest = !next.appId.trim(); next.appPath = result.path; next.appHash = result.hash; if (shouldSuggest) next.appId = result.suggestedAppId; });
    } catch (error) { setStatus("dirty"); setMessage(formatError(error)); } finally { setBusy(false); }
  }

  async function validate() {
    if (!draft) return null;
    setBusy(true); setMessage(null);
    try { const result = await invoke<PolicyViewResponse>("validate_policy_draft", { policy: draft }); setDraft(result.policy); setPreview(result.canonicalJson); setStatus("valid"); setMessage("Policy valid — checked by secure-runtime."); return result; }
    catch (error) { setStatus("dirty"); setMessage(formatError(error)); return null; }
    finally { setBusy(false); }
  }

  async function write(destination: string, overwrite: boolean) {
    if (!draft) return;
    setBusy(true); setMessage(null);
    try { const result = await invoke<PolicyViewResponse>("save_policy", { path: destination, policy: draft, overwrite }); setDraft(result.policy); setPreview(result.canonicalJson); setPath(destination); setStatus("saved"); setMessage("Policy saved successfully."); }
    catch (error) { setStatus("dirty"); setMessage(formatError(error)); }
    finally { setBusy(false); }
  }

  async function saveAs() {
    if (!draft) return;
    try {
      const destination = await save({ defaultPath: (draft.appId.trim() || "policy") + ".json", filters: [{ name: "JSON policy", extensions: ["json"] }] });
      if (typeof destination === "string") await write(destination, true);
    } catch (error) { setStatus("dirty"); setMessage(formatError(error)); }
  }

  if (!draft) return <div className="dashboard"><section className="card policy-empty"><h2>Preparing policy builder…</h2>{message && <p>{message}</p>}</section></div>;

  const fs = draft.filesystem;
  const setPaths = (key: ListKey, values: string[]) => update((next) => { next.filesystem[key] = values; });

  return <div className="dashboard builder-page">
    <section className="intro-row"><div><h2>{initialPolicy ? "Edit policy" : "Create policy"}</h2><p>Build the current secure-runtime policy schema. Rust performs authoritative validation.</p></div><div className={"builder-status " + status}><i />{status === "saved" ? "Saved" : status === "valid" ? "Policy valid" : "Not validated"}</div></section>

    <section className="card builder-card"><div className="policy-section-title"><span>01</span><div><h2>Application</h2><p>Executable identity and general policy settings</p></div></div><button className="executable-picker" onClick={() => void selectExecutable()} disabled={busy} type="button"><span>▣</span><div><strong>{draft.appPath || "Select executable"}</strong><small>{draft.appHash || "SHA-256 will be computed by secure-runtime"}</small></div><b>Browse</b></button><div className="builder-form-grid"><label className="builder-field"><span>Policy version</span><input readOnly value={draft.policyVersion} /></label><label className="builder-field"><span>Application ID</span><input value={draft.appId} onChange={(event) => update((next) => { next.appId = event.target.value; })} /></label><label className="builder-field"><span>Default action</span><select value={draft.defaultAction} onChange={(event) => update((next) => { next.defaultAction = event.target.value; })}><option value="deny">deny</option><option value="allow">allow</option></select></label><label className="builder-field wide"><span>SHA-256 from selected executable</span><input className="hash-input" readOnly value={draft.appHash} placeholder="Select an executable to compute its hash" /></label></div></section>

    <section className="card builder-card"><div className="policy-section-title"><span>02</span><div><h2>Filesystem</h2><p>Add files or directories to the exact policy arrays</p></div></div><div className="builder-section-grid"><PathEditor title="Read allow" values={fs.readAllow} onChange={(values) => setPaths("readAllow", values)} /><PathEditor title="Write allow" values={fs.writeAllow} onChange={(values) => setPaths("writeAllow", values)} /><PathEditor executableOnly title="Execute allow" values={fs.execAllow} onChange={(values) => setPaths("execAllow", values)} /><PathEditor title="Deny" values={fs.deny} onChange={(values) => setPaths("deny", values)} /></div></section>

    <section className="card builder-card"><div className="builder-card-header"><div className="policy-section-title"><span>03</span><div><h2>Network</h2><p>Optional TCP port allow lists</p></div></div><button className="section-toggle" onClick={() => update((next) => { next.network = next.network ? null : { connectTcp: [], bindTcp: [] }; })} type="button">{draft.network ? "Remove section" : "Add section"}</button></div>{draft.network && <div className="builder-section-grid"><PortEditor title="Connect TCP" values={draft.network.connectTcp ?? []} onChange={(values) => update((next) => { if (next.network) next.network.connectTcp = values; })} /><PortEditor title="Bind TCP" values={draft.network.bindTcp ?? []} onChange={(values) => update((next) => { if (next.network) next.network.bindTcp = values; })} /></div>}</section>

    <section className="card builder-card"><div className="builder-card-header"><div className="policy-section-title"><span>04</span><div><h2>Seccomp</h2><p>Optional profile and custom denied syscalls</p></div></div><button className="section-toggle" onClick={() => update((next) => { next.seccomp = next.seccomp ? null : { profile: null, deny: [] }; })} type="button">{draft.seccomp ? "Remove section" : "Add section"}</button></div>{draft.seccomp && <><label className="builder-field"><span>Profile</span><select value={draft.seccomp.profile ?? ""} onChange={(event) => update((next) => { if (next.seccomp) next.seccomp.profile = (event.target.value || null) as "none" | "baseline" | "strict" | null; })}><option value="">Not specified</option><option value="none">none</option><option value="baseline">baseline</option><option value="strict">strict</option></select></label><StringList title="Custom denied syscalls" placeholder="ptrace" values={draft.seccomp.deny ?? []} onChange={(values) => update((next) => { if (next.seccomp) next.seccomp.deny = values; })} /></>}</section>

    <section className="card builder-card"><div className="builder-card-header"><div className="policy-section-title"><span>05</span><div><h2>Namespaces</h2><p>Optional namespace configuration with explicit unspecified states</p></div></div><button className="section-toggle" onClick={() => update((next) => { next.namespace = next.namespace ? null : { uts: null, ipc: null, network: null, pid: null, mount: null }; })} type="button">{draft.namespace ? "Remove section" : "Add section"}</button></div>{draft.namespace && <><div className="tri-state-grid"><label><span>IPC</span><TriState value={draft.namespace.ipc} onChange={(value) => update((next) => { if (next.namespace) next.namespace.ipc = value; })} /></label><label><span>Network</span><TriState value={draft.namespace.network} onChange={(value) => update((next) => { if (next.namespace) next.namespace.network = value; })} /></label><label><span>PID</span><TriState value={draft.namespace.pid} onChange={(value) => update((next) => { if (next.namespace) next.namespace.pid = value; })} /></label></div><div className="optional-panels"><div><button className="section-toggle" onClick={() => update((next) => { if (next.namespace) next.namespace.uts = next.namespace.uts ? null : { enabled: null, hostname: null }; })} type="button">{draft.namespace.uts ? "Remove UTS" : "Add UTS"}</button>{draft.namespace.uts && <div className="mini-form"><label><span>Enabled</span><TriState value={draft.namespace.uts.enabled} onChange={(value) => update((next) => { if (next.namespace?.uts) next.namespace.uts.enabled = value; })} /></label><label className="builder-field"><span>Hostname</span><input value={draft.namespace.uts.hostname ?? ""} onChange={(event) => update((next) => { if (next.namespace?.uts) next.namespace.uts.hostname = event.target.value || null; })} /></label></div>}</div><div><button className="section-toggle" onClick={() => update((next) => { if (next.namespace) next.namespace.mount = next.namespace.mount ? null : { enabled: null, privateTmp: null, tmpSizeMb: null }; })} type="button">{draft.namespace.mount ? "Remove Mount" : "Add Mount"}</button>{draft.namespace.mount && <div className="mini-form"><label><span>Enabled</span><TriState value={draft.namespace.mount.enabled} onChange={(value) => update((next) => { if (next.namespace?.mount) next.namespace.mount.enabled = value; })} /></label><label><span>Private /tmp</span><TriState value={draft.namespace.mount.privateTmp} onChange={(value) => update((next) => { if (next.namespace?.mount) next.namespace.mount.privateTmp = value; })} /></label><NumberField label="tmp size" suffix="MB" value={draft.namespace.mount.tmpSizeMb} onChange={(value) => update((next) => { if (next.namespace?.mount) next.namespace.mount.tmpSizeMb = value; })} /></div>}</div></div></>}</section>

    <section className="card builder-card"><div className="builder-card-header"><div className="policy-section-title"><span>06</span><div><h2>Resources</h2><p>Optional runtime, rlimit, and cgroup limits</p></div></div><button className="section-toggle" onClick={() => update((next) => { next.resources = next.resources ? null : { timeoutSeconds: null, maxOutputKb: null, memoryMb: null, maxProcesses: null, rlimit: null, cgroup: null }; })} type="button">{draft.resources ? "Remove section" : "Add section"}</button></div>{draft.resources && <><div className="builder-form-grid four"><NumberField label="Timeout" suffix="seconds" value={draft.resources.timeoutSeconds} onChange={(value) => update((next) => { if (next.resources) next.resources.timeoutSeconds = value; })} /><NumberField label="Maximum output" suffix="KB" value={draft.resources.maxOutputKb} onChange={(value) => update((next) => { if (next.resources) next.resources.maxOutputKb = value; })} /><NumberField label="Memory" suffix="MB" value={draft.resources.memoryMb} onChange={(value) => update((next) => { if (next.resources) next.resources.memoryMb = value; })} /><NumberField label="Maximum processes" value={draft.resources.maxProcesses} onChange={(value) => update((next) => { if (next.resources) next.resources.maxProcesses = value; })} /></div><div className="optional-panels"><div><button className="section-toggle" onClick={() => update((next) => { if (next.resources) next.resources.rlimit = next.resources.rlimit ? null : { enabled: null, cpuSeconds: null, maxFileSizeMb: null }; })} type="button">{draft.resources.rlimit ? "Remove rlimit" : "Add rlimit"}</button>{draft.resources.rlimit && <div className="mini-form"><label><span>Enabled</span><TriState value={draft.resources.rlimit.enabled} onChange={(value) => update((next) => { if (next.resources?.rlimit) next.resources.rlimit.enabled = value; })} /></label><NumberField label="CPU time" suffix="seconds" value={draft.resources.rlimit.cpuSeconds} onChange={(value) => update((next) => { if (next.resources?.rlimit) next.resources.rlimit.cpuSeconds = value; })} /><NumberField label="Maximum file size" suffix="MB" value={draft.resources.rlimit.maxFileSizeMb} onChange={(value) => update((next) => { if (next.resources?.rlimit) next.resources.rlimit.maxFileSizeMb = value; })} /></div>}</div><div><button className="section-toggle" onClick={() => update((next) => { if (next.resources) next.resources.cgroup = next.resources.cgroup ? null : { enabled: null, cpuPercent: null }; })} type="button">{draft.resources.cgroup ? "Remove cgroup" : "Add cgroup"}</button>{draft.resources.cgroup && <div className="mini-form"><label><span>Enabled</span><TriState value={draft.resources.cgroup.enabled} onChange={(value) => update((next) => { if (next.resources?.cgroup) next.resources.cgroup.enabled = value; })} /></label><NumberField label="CPU allocation" suffix="%" value={draft.resources.cgroup.cpuPercent} onChange={(value) => update((next) => { if (next.resources?.cgroup) next.resources.cgroup.cpuPercent = value; })} /></div>}</div></div></>}</section>

    <section className="card builder-card preview-card"><div className="builder-card-header"><div className="policy-section-title"><span>07</span><div><h2>JSON preview</h2><p>Canonical pretty JSON generated by Rust after validation</p></div></div><button className="secondary-button" disabled={busy} onClick={() => void validate()} type="button">Validate Policy</button></div>{message && <div className={status === "valid" || status === "saved" ? "success-banner" : "error-banner"} role="status"><span>{status === "valid" || status === "saved" ? "✓" : "!"}</span><div><strong>{status === "saved" ? "Policy saved" : status === "valid" ? "Policy valid" : "Validation or save error"}</strong><p>{message}</p></div></div>}<pre>{preview || "Validate the draft to generate its canonical JSON preview."}</pre></section>

    <div className="builder-footer"><div><span>Destination</span><code>{path || "Not saved yet"}</code></div><button className="secondary-button" disabled={busy || !path} onClick={() => void write(path, true)} type="button">Save</button><button className="secondary-button" disabled={busy} onClick={() => void saveAs()} type="button">Save As</button>{status === "saved" && <><button className="secondary-button" onClick={() => onViewPolicy(path)} type="button">View Policy</button><button className="run-button" onClick={() => onUseForRun(path)} type="button">Use for Run →</button></>}</div>
  </div>;
}
