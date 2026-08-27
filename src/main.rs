use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;

use secure_runtime::cli::check_cli;
use secure_runtime::logger::EventLogger;
use secure_runtime::{RunError, RunRequest, RuntimeConfig, run};

fn log_or_exit(
    logger: &EventLogger,
    app_id: &str,
    event_type: &str,
    decision: &str,
    reason: &str,
    risk_score: f32,
) {
    if let Err(error) = logger.log_security_event(app_id, event_type, decision, reason, risk_score)
    {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn main() {
    let event_log_path = "logs/events.jsonl";
    let logger = EventLogger::new(event_log_path);
    let args: Vec<String> = std::env::args().collect();
    let cli = match check_cli(&args) {
        Ok(cli) => cli,
        Err(err) => {
            log_or_exit(&logger, "unknown", "cli_check", "deny", &err, 1.0);
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    log_or_exit(
        &logger,
        "unknown",
        "cli_check",
        "allow",
        "CLI arguments validated successfully",
        0.0,
    );

    let request = RunRequest::new(cli.policy_path, cli.app_path, cli.app_arg);
    let result = match run(request, RuntimeConfig::new(event_log_path)) {
        Ok(result) => result,
        Err(RunError::PolicyLoad(err)) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
        Err(RunError::IdentityCheck { app_path, reason }) => {
            eprintln!(
                "Identity check failed for app: {}. Reason: {}",
                app_path, reason
            );
            std::process::exit(1);
        }
        Err(RunError::SandboxPreparation(err)) => {
            eprintln!("Sandbox preparation failed : {}", err);
            std::process::exit(1);
        }
        Err(RunError::Execution { app_id, reason }) => {
            log_or_exit(&logger, &app_id, "app_exit", "deny", &reason, 1.0);
            eprintln!("Failed to execute app: {reason}");
            std::process::exit(1);
        }
        Err(RunError::Logging(error)) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };

    match result.launcher_status {
        WaitStatus::Exited(_, 0) => {
            log_or_exit(
                &logger,
                &result.app_id,
                "app_exit",
                "allow",
                "Application exited successfully",
                0.0,
            );
            println!("Application exited successfully");
        }
        WaitStatus::Exited(_, code) => {
            log_or_exit(
                &logger,
                &result.app_id,
                "app_exit",
                "deny",
                &format!("Application exited with status code: {code}"),
                1.0,
            );
            eprintln!("Application exited with status code: {code}");
            std::process::exit(1);
        }
        WaitStatus::Signaled(_, Signal::SIGXFSZ, _) => {
            log_or_exit(
                &logger,
                &result.app_id,
                "resource_limit_hit",
                "deny",
                "File size limit exceeded",
                0.7,
            );
            eprintln!("Application killed: file size limit exceeded");
            std::process::exit(1);
        }
        WaitStatus::Signaled(_, Signal::SIGXCPU, _) => {
            log_or_exit(
                &logger,
                &result.app_id,
                "resource_limit_hit",
                "deny",
                "CPU limit exceeded",
                0.7,
            );
            eprintln!("Application killed: CPU limit exceeded");
            std::process::exit(1);
        }
        WaitStatus::Signaled(_, Signal::SIGKILL, _) => {
            log_or_exit(
                &logger,
                &result.app_id,
                "resource_limit_hit",
                "deny",
                "Application killed by SIGKILL",
                0.7,
            );
            eprintln!("Application killed by SIGKILL");
            std::process::exit(1);
        }
        WaitStatus::Signaled(_, signal, _) => {
            log_or_exit(
                &logger,
                &result.app_id,
                "app_exit",
                "deny",
                &format!("Application killed by signal: {signal:?}"),
                1.0,
            );
            eprintln!("Application killed by signal: {signal:?}");
            std::process::exit(1);
        }
        other_status => {
            log_or_exit(
                &logger,
                &result.app_id,
                "app_exit",
                "deny",
                &format!("Unexpected application status: {other_status:?}"),
                1.0,
            );
            eprintln!("Unexpected application status: {other_status:?}");
            std::process::exit(1);
        }
    }
}
