use nix::sys::wait::WaitStatus;
use nix::sys::signal::Signal;

mod cli;
mod policy;
mod engine;
mod hash;
mod identity;
mod logger;
mod runner;
mod sandbox;
mod seccomp;
mod namespaces;
mod privileges;
mod cgroup;
mod executor;

use cli::{check_cli};
use policy::load_policy;
use identity::check_identity;
use logger::log_security_event;
use runner::{run_app};
use sandbox::prepare_sandbox;

fn main() {
    
    let args: Vec<String> = std::env::args().collect();
    
    
    let cli  = match check_cli(&args){
        Ok(cli) => cli,
        Err(err) => {
            log_security_event("unknown", "cli_check", "deny", &err, 1.0);
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };
    
    log_security_event("unknown", "cli_check", "allow", "CLI arguments validated successfully", 0.0);

    let policy = match load_policy(&cli.policy_path){
        Ok(policy) => policy,
        Err(err) => {
            log_security_event("unknown", "policy_load", "deny", &err, 1.0);
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };
    
    log_security_event(&policy.app_id, "policy_load", "allow", "Policy loaded successfully", 0.0);
    
    let executable =match check_identity(&cli.app_path, &policy){
        Ok(exe) => {
            log_security_event(&policy.app_id, "identity_check", "allow", "Identity verified", 0.0);
            exe
        },
        Err(err) => {
            eprintln!("Identity check failed for app: {}. Reason: {}", cli.app_path, err);
            log_security_event(&policy.app_id, "identity_check", "deny", &err, 1.0);
            std::process::exit(1);
        }
    };



    let config =match prepare_sandbox(&policy) {
        Ok(config) => {
            log_security_event(&policy.app_id,"sandbox_prepare","allow",&format!("Filesystem sandbox policy prepared successfully"),0.0);
            config
        },
        Err(err) => {
            log_security_event(&policy.app_id,"sandbox_prepare","deny",&format!("Sandbox faild to prepared : {}",err),1.0);
            eprintln!("Sandbox preparation failed : {}",err);
            std::process::exit(1);

        }
    };


// -----------------------------------------------------------------
// ------------------------- BAD LOG -------------------------------


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
    cpu,
    memory,
    file_size,
    processes
    );

    log_security_event(
        &policy.app_id,
        "resource_limits_configured",
        "allow",
        &resource_reason,
        0.0,
    );

    if config.network.enabled {
        
        let connect_tcp = if config.network.connect_tcp.is_empty() {
            "None".to_string()
        } else {
            format!("{:?}",config.network.connect_tcp)
        };
        
        let bind_tcp = if config.network.bind_tcp.is_empty() {
            "None".to_string()
        } else {
            format!("{:?}",config.network.bind_tcp)
        };

        let reason = format!("connect tcp : {} ,bind tcp : {}",connect_tcp ,bind_tcp);

        log_security_event(&policy.app_id, "network_policy_configration", "allow",&reason , 0.0);
    }


// -----------------------  BAD LOG---------------------------------
// -----------------------------------------------------------------

        let seccomp_reason = format!(
        "Seccomp configured with profile {:?}; {} syscalls denied",
        config.seccomp.profile,
        config.seccomp.denied_syscalls.len()
    );

    log_security_event(
        &policy.app_id,
        "seccomp_configured",
        "allow",
        &seccomp_reason,
        0.0,
    );
    log_security_event(&policy.app_id, "app_spawn_attempt", "allow", "Executing application", 0.0);
    
    match run_app(&cli, config, executable) {
        Ok(WaitStatus::Exited(_, 0)) => {
            log_security_event(
                &policy.app_id,
                "app_exit",
                "allow",
                "Application exited successfully",
                0.0,
            );

            println!("Application exited successfully");
        }

        Ok(WaitStatus::Exited(_, code)) => {
            log_security_event(
                &policy.app_id,
                "app_exit",
                "deny",
                &format!("Application exited with status code: {code}"),
                1.0,
            );

            eprintln!("Application exited with status code: {code}");
            std::process::exit(1);
        }

        Ok(WaitStatus::Signaled(_, Signal::SIGXFSZ, _)) => {
            log_security_event(
                &policy.app_id,
                "resource_limit_hit",
                "deny",
                "File size limit exceeded",
                0.7,
            );

            eprintln!("Application killed: file size limit exceeded");
            std::process::exit(1);
        }

        Ok(WaitStatus::Signaled(_, Signal::SIGXCPU, _)) => {
            log_security_event(
                &policy.app_id,
                "resource_limit_hit",
                "deny",
                "CPU limit exceeded",
                0.7,
            );

            eprintln!("Application killed: CPU limit exceeded");
            std::process::exit(1);
        }

        Ok(WaitStatus::Signaled(_, Signal::SIGKILL, _)) => {
            log_security_event(
                &policy.app_id,
                "resource_limit_hit",
                "deny",
                "Application killed by SIGKILL",
                0.7,
            );

            eprintln!("Application killed by SIGKILL");
            std::process::exit(1);
        }

        Ok(WaitStatus::Signaled(_, signal, _)) => {
            log_security_event(
                &policy.app_id,
                "app_exit",
                "deny",
                &format!("Application killed by signal: {signal:?}"),
                1.0,
            );

            eprintln!("Application killed by signal: {signal:?}");
            std::process::exit(1);
        }

        Ok(other_status) => {
            log_security_event(
                &policy.app_id,
                "app_exit",
                "deny",
                &format!("Unexpected application status: {other_status:?}"),
                1.0,
            );

            eprintln!("Unexpected application status: {other_status:?}");
            std::process::exit(1);
        }

        Err(error) => {
            log_security_event(
                &policy.app_id,
                "app_exit",
                "deny",
                &error,
                1.0,
            );

            eprintln!("Failed to execute app: {error}");
            std::process::exit(1);
        }
    }

    


}