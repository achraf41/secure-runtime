use nix::sys::wait::WaitStatus;
use std::time::{Duration, Instant};

use crate::cgroup::CgroupStats;
use crate::cli::CliArgs;
use crate::identity::check_identity;
use crate::logger::EventLogger;
use crate::output::{ConsoleObserver, RunObserver};
use crate::policy::load_policy;
use crate::runner::{RunnerOutcome, run_app};
use crate::sandbox::{SandboxConfig, prepare_sandbox};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    pub policy_path: String,
    pub app_path: String,
    pub app_args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub event_log_path: std::path::PathBuf,
}

impl RuntimeConfig {
    pub fn new(event_log_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            event_log_path: event_log_path.into(),
        }
    }
}

impl RunRequest {
    pub fn new(policy_path: String, app_path: String, app_args: Vec<String>) -> Self {
        Self {
            policy_path,
            app_path,
            app_args,
        }
    }
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub app_id: String,
    pub outcome: ExecutionOutcome,
    pub exit_code: Option<i32>,
    pub terminating_signal: Option<i32>,
    pub timed_out: bool,
    pub output_limit_exceeded: bool,
    pub output_bytes_observed: u64,
    pub output_limit_bytes: Option<u64>,
    pub runtime_duration: Duration,
    pub cgroup_stats: Option<CgroupStats>,
    pub launcher_status: WaitStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    Exited,
    Signaled,
    TimedOut,
    OutputLimitExceeded,
}

#[derive(Debug)]
pub enum RunError {
    Logging(String),
    PolicyLoad(String),
    IdentityCheck { app_path: String, reason: String },
    SandboxPreparation(String),
    Execution { app_id: String, reason: String },
}

fn log_configured_security(
    logger: &EventLogger,
    app_id: &str,
    config: &SandboxConfig,
) -> Result<(), RunError> {
    let cpu = config
        .resources
        .rlimit
        .cpu_seconds
        .map_or("unlimited".to_string(), |value| format!("{}s", value));
    let memory = config
        .resources
        .rlimit
        .memory_bytes
        .map_or("unlimited".to_string(), |value| {
            format!("{} MB", value / 1024 / 1024)
        });
    let file_size = config
        .resources
        .rlimit
        .max_file_size_bytes
        .map_or("unlimited".to_string(), |value| {
            format!("{} MB", value / 1024 / 1024)
        });
    let processes = config
        .resources
        .rlimit
        .max_processes
        .map_or("unlimited".to_string(), |value| value.to_string());
    let resource_reason = format!(
        "CPU={}, memory={}, file_size={}, processes={}",
        cpu, memory, file_size, processes
    );
    logger
        .log_security_event(
            app_id,
            "resource_limits_configured",
            "allow",
            &resource_reason,
            0.0,
        )
        .map_err(RunError::Logging)?;

    if config.network.enabled {
        let connect_tcp = if config.network.connect_tcp.is_empty() {
            "None".to_string()
        } else {
            format!("{:?}", config.network.connect_tcp)
        };
        let bind_tcp = if config.network.bind_tcp.is_empty() {
            "None".to_string()
        } else {
            format!("{:?}", config.network.bind_tcp)
        };
        let reason = format!("connect tcp : {} ,bind tcp : {}", connect_tcp, bind_tcp);
        logger
            .log_security_event(app_id, "network_policy_configration", "allow", &reason, 0.0)
            .map_err(RunError::Logging)?;
    }

    let seccomp_reason = format!(
        "Seccomp configured with profile {:?}; {} syscalls denied",
        config.seccomp.profile,
        config.seccomp.denied_syscalls.len()
    );
    logger
        .log_security_event(app_id, "seccomp_configured", "allow", &seccomp_reason, 0.0)
        .map_err(RunError::Logging)?;
    Ok(())
}

pub fn run(
    request: RunRequest,
    runtime_config: RuntimeConfig,
) -> Result<ExecutionResult, RunError> {
    run_with_observer(request, &ConsoleObserver, runtime_config)
}

pub fn run_with_observer(
    request: RunRequest,
    observer: &dyn RunObserver,
    runtime_config: RuntimeConfig,
) -> Result<ExecutionResult, RunError> {
    let logger = EventLogger::new(runtime_config.event_log_path);
    let policy = match load_policy(&request.policy_path) {
        Ok(policy) => policy,
        Err(reason) => {
            logger
                .log_security_event("unknown", "policy_load", "deny", &reason, 1.0)
                .map_err(RunError::Logging)?;
            return Err(RunError::PolicyLoad(reason));
        }
    };
    logger
        .log_security_event(
            &policy.app_id,
            "policy_load",
            "allow",
            "Policy loaded successfully",
            0.0,
        )
        .map_err(RunError::Logging)?;

    let executable = match check_identity(&request.app_path, &policy) {
        Ok(executable) => executable,
        Err(reason) => {
            logger
                .log_security_event(&policy.app_id, "identity_check", "deny", &reason, 1.0)
                .map_err(RunError::Logging)?;
            return Err(RunError::IdentityCheck {
                app_path: request.app_path.clone(),
                reason,
            });
        }
    };
    logger
        .log_security_event(
            &policy.app_id,
            "identity_check",
            "allow",
            "Identity verified",
            0.0,
        )
        .map_err(RunError::Logging)?;

    let config = match prepare_sandbox(&policy) {
        Ok(config) => config,
        Err(reason) => {
            logger
                .log_security_event(
                    &policy.app_id,
                    "sandbox_prepare",
                    "deny",
                    &format!("Sandbox faild to prepared : {}", reason),
                    1.0,
                )
                .map_err(RunError::Logging)?;
            return Err(RunError::SandboxPreparation(reason));
        }
    };
    logger
        .log_security_event(
            &policy.app_id,
            "sandbox_prepare",
            "allow",
            "Filesystem sandbox policy prepared successfully",
            0.0,
        )
        .map_err(RunError::Logging)?;

    log_configured_security(&logger, &policy.app_id, &config)?;
    logger
        .log_security_event(
            &policy.app_id,
            "app_spawn_attempt",
            "allow",
            "Executing application",
            0.0,
        )
        .map_err(RunError::Logging)?;

    let cli = CliArgs {
        policy_path: request.policy_path,
        app_path: request.app_path,
        app_arg: request.app_args,
    };
    let app_id = policy.app_id;
    let started_at = Instant::now();
    let run_result = run_app(&cli, config, executable, observer, &logger).map_err(|reason| {
        RunError::Execution {
            app_id: app_id.clone(),
            reason,
        }
    })?;
    let runtime_duration = started_at.elapsed();

    let (outcome, exit_code, terminating_signal, timed_out, output_limit_exceeded) =
        match run_result.outcome {
            RunnerOutcome::Exited(code) => {
                (ExecutionOutcome::Exited, Some(code), None, false, false)
            }
            RunnerOutcome::Signaled(signal) => {
                (ExecutionOutcome::Signaled, None, Some(signal), false, false)
            }
            RunnerOutcome::TimedOut => (ExecutionOutcome::TimedOut, None, None, true, false),
            RunnerOutcome::OutputLimitExceeded => (
                ExecutionOutcome::OutputLimitExceeded,
                None,
                None,
                false,
                true,
            ),
        };

    Ok(ExecutionResult {
        app_id,
        outcome,
        exit_code,
        terminating_signal,
        timed_out,
        output_limit_exceeded,
        output_bytes_observed: run_result.output_bytes_observed,
        output_limit_bytes: run_result.output_limit_bytes,
        runtime_duration,
        cgroup_stats: run_result.cgroup_stats,
        launcher_status: run_result.launcher_status,
    })
}
