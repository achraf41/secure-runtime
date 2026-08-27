use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use secure_runtime::{
    run_with_observer, ExecutionOutcome, ExecutionResult, OutputStream, RunError, RunObserver,
    RunRequest, RuntimeConfig,
};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

mod log_dto;
mod policy_dto;

use log_dto::SecurityLogsResponse;
use policy_dto::{PolicyDto, PolicyViewResponse};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutableHashPayload {
    path: String,
    hash: String,
    suggested_app_id: String,
}

struct RunState {
    active_run: Mutex<Option<String>>,
    next_id: AtomicU64,
}

impl Default for RunState {
    fn default() -> Self {
        Self {
            active_run: Mutex::new(None),
            next_id: AtomicU64::new(1),
        }
    }
}

impl RunState {
    fn new_run_id(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let sequence = self.next_id.fetch_add(1, Ordering::Relaxed);
        format!("run-{timestamp}-{}-{sequence}", std::process::id())
    }
}

struct ActiveRunGuard {
    app: AppHandle,
    run_id: String,
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        let state = self.app.state::<RunState>();
        if let Ok(mut active_run) = state.active_run.lock() {
            if active_run.as_deref() == Some(self.run_id.as_str()) {
                *active_run = None;
            }
        };
    }
}

struct TauriRunObserver {
    app: AppHandle,
    run_id: String,
}

impl RunObserver for TauriRunObserver {
    fn output(&self, stream: OutputStream, bytes: &[u8]) -> Result<(), String> {
        let stream = match stream {
            OutputStream::Stdout => "stdout",
            OutputStream::Stderr => "stderr",
        };

        self.app
            .emit(
                "runtime://output",
                OutputPayload {
                    run_id: self.run_id.clone(),
                    stream,
                    text: String::from_utf8_lossy(bytes).into_owned(),
                },
            )
            .map_err(|error| format!("Failed to emit runtime output: {error}"))
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusPayload {
    run_id: String,
    status: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputPayload {
    run_id: String,
    stream: &'static str,
    text: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CgroupStatsDto {
    memory_peak_bytes: Option<u64>,
    cpu_usage_usec: Option<u64>,
    cpu_user_usec: Option<u64>,
    cpu_system_usec: Option<u64>,
    cpu_nr_throttled: Option<u64>,
    cpu_throttled_usec: Option<u64>,
    pids_peak: Option<u64>,
    oom_count: Option<u64>,
    oom_kill_count: Option<u64>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FinishedPayload {
    run_id: String,
    status: &'static str,
    app_id: String,
    outcome: &'static str,
    exit_code: Option<i32>,
    terminating_signal: Option<i32>,
    timed_out: bool,
    output_limit_exceeded: bool,
    output_bytes_observed: u64,
    output_limit_bytes: Option<u64>,
    runtime_duration_ms: u64,
    cgroup_stats: Option<CgroupStatsDto>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FailedPayload {
    run_id: String,
    status: &'static str,
    error: String,
}

impl FinishedPayload {
    fn from_result(run_id: String, result: ExecutionResult) -> Self {
        let outcome = match result.outcome {
            ExecutionOutcome::Exited => "exited",
            ExecutionOutcome::Signaled => "signaled",
            ExecutionOutcome::TimedOut => "timedOut",
            ExecutionOutcome::OutputLimitExceeded => "outputLimitExceeded",
        };
        let duration_ms = result.runtime_duration.as_millis().min(u64::MAX as u128) as u64;
        let cgroup_stats = result.cgroup_stats.map(|stats| CgroupStatsDto {
            memory_peak_bytes: stats.memory_peak_bytes,
            cpu_usage_usec: stats.cpu_usage_usec,
            cpu_user_usec: stats.cpu_user_usec,
            cpu_system_usec: stats.cpu_system_usec,
            cpu_nr_throttled: stats.cpu_nr_throttled,
            cpu_throttled_usec: stats.cpu_throttled_usec,
            pids_peak: stats.pids_peak,
            oom_count: stats.oom_count,
            oom_kill_count: stats.oom_kill_count,
        });

        Self {
            run_id,
            status: "finished",
            app_id: result.app_id,
            outcome,
            exit_code: result.exit_code,
            terminating_signal: result.terminating_signal,
            timed_out: result.timed_out,
            output_limit_exceeded: result.output_limit_exceeded,
            output_bytes_observed: result.output_bytes_observed,
            output_limit_bytes: result.output_limit_bytes,
            runtime_duration_ms: duration_ms,
            cgroup_stats,
        }
    }
}

fn run_error_message(error: RunError) -> String {
    match error {
        RunError::Logging(reason) => reason,
        RunError::PolicyLoad(reason) => reason,
        RunError::IdentityCheck { app_path, reason } => {
            format!("Identity check failed for app: {app_path}. Reason: {reason}")
        }
        RunError::SandboxPreparation(reason) => {
            format!("Sandbox preparation failed: {reason}")
        }
        RunError::Execution { reason, .. } => format!("Failed to execute app: {reason}"),
    }
}

fn desktop_event_log_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .app_log_dir()
        .map(|directory| directory.join("events.jsonl"))
        .map_err(|error| format!("Failed to resolve application log directory: {error}"))
}

#[tauri::command]
async fn load_security_logs(app: AppHandle) -> Result<SecurityLogsResponse, String> {
    let path = desktop_event_log_path(&app)?;
    tauri::async_runtime::spawn_blocking(move || log_dto::load_security_logs(&path))
        .await
        .map_err(|error| format!("Desktop log reader terminated unexpectedly: {error}"))?
}

#[tauri::command]
fn load_policy(path: String) -> Result<PolicyViewResponse, String> {
    let policy = secure_runtime::policy::load_policy(&path)?;
    PolicyViewResponse::from_policy(&policy)
}

#[tauri::command]
fn new_policy_draft() -> PolicyDto {
    PolicyDto::new()
}

#[tauri::command]
fn compute_executable_hash(path: String) -> Result<ExecutableHashPayload, String> {
    let executable_path = Path::new(&path);
    if !executable_path.is_file() {
        return Err("Executable path is not a regular file".to_string());
    }
    let metadata = executable_path
        .metadata()
        .map_err(|error| format!("Failed to inspect executable: {error}"))?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err("Selected file does not have an executable permission bit".to_string());
    }
    let mut executable = File::open(executable_path)
        .map_err(|error| format!("Failed to open executable for hashing: {error}"))?;
    let hash = secure_runtime::hash::hash_calc(&mut executable)?;
    let suggested_app_id = executable_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("application")
        .to_string();
    Ok(ExecutableHashPayload {
        path,
        hash,
        suggested_app_id,
    })
}

fn validated_policy_document(policy: PolicyDto) -> Result<PolicyViewResponse, String> {
    let policy = policy.into_policy()?;
    secure_runtime::policy::validate_policy(&policy)?;
    PolicyViewResponse::from_policy(&policy)
}

#[tauri::command]
fn validate_policy_draft(policy: PolicyDto) -> Result<PolicyViewResponse, String> {
    validated_policy_document(policy)
}

#[tauri::command]
fn save_policy(
    path: String,
    policy: PolicyDto,
    overwrite: bool,
) -> Result<PolicyViewResponse, String> {
    let document = validated_policy_document(policy)?;
    let destination = Path::new(&path);
    let parent = destination
        .parent()
        .ok_or_else(|| "Policy destination has no parent directory".to_string())?;
    if !parent.is_dir() {
        return Err(format!(
            "Policy destination directory does not exist: {}",
            parent.display()
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(destination).map_err(|error| {
        if !overwrite && destination.exists() {
            format!("Policy file already exists: {}", destination.display())
        } else {
            format!("Failed to create policy file: {error}")
        }
    })?;
    file.write_all(document.canonical_json.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|error| format!("Failed to save policy: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("Failed to finalize policy file: {error}"))?;
    Ok(document)
}

#[tauri::command]
async fn start_run(
    app: AppHandle,
    state: State<'_, RunState>,
    executable_path: String,
    policy_path: String,
    arguments: Vec<String>,
) -> Result<String, String> {
    let event_log_path = desktop_event_log_path(&app)?;
    let run_id = state.new_run_id();
    {
        let mut active_run = state
            .active_run
            .lock()
            .map_err(|_| "Runtime state lock is poisoned".to_string())?;
        if active_run.is_some() {
            return Err("A sandbox execution is already running".to_string());
        }
        *active_run = Some(run_id.clone());
    }

    if let Err(error) = app.emit(
        "runtime://status",
        StatusPayload {
            run_id: run_id.clone(),
            status: "running",
        },
    ) {
        if let Ok(mut active_run) = state.active_run.lock() {
            *active_run = None;
        }
        return Err(format!("Failed to emit runtime status: {error}"));
    }

    let worker_app = app.clone();
    let worker_run_id = run_id.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let active_guard = ActiveRunGuard {
            app: worker_app.clone(),
            run_id: worker_run_id.clone(),
        };
        let observer = TauriRunObserver {
            app: worker_app.clone(),
            run_id: worker_run_id.clone(),
        };
        let request = RunRequest::new(policy_path, executable_path, arguments);
        let runtime_config = RuntimeConfig::new(event_log_path);
        let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_with_observer(request, &observer, runtime_config)
        }));

        drop(active_guard);

        match execution {
            Ok(Ok(result)) => {
                let _ = worker_app.emit(
                    "runtime://finished",
                    FinishedPayload::from_result(worker_run_id, result),
                );
            }
            Ok(Err(error)) => {
                let _ = worker_app.emit(
                    "runtime://finished",
                    FailedPayload {
                        run_id: worker_run_id,
                        status: "failed",
                        error: run_error_message(error),
                    },
                );
            }
            Err(_) => {
                let _ = worker_app.emit(
                    "runtime://finished",
                    FailedPayload {
                        run_id: worker_run_id,
                        status: "failed",
                        error: "Secure runtime terminated unexpectedly".to_string(),
                    },
                );
            }
        }
    });

    Ok(run_id)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(RunState::default())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            start_run,
            load_policy,
            new_policy_draft,
            compute_executable_hash,
            validate_policy_draft,
            save_policy,
            load_security_logs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
