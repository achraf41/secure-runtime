use std::os::unix::process::ExitStatusExt;

mod cli;
mod policy;
mod engine;
mod hash;
mod identity;
mod logger;
mod runner;
mod sandbox;

use cli::check_cli;
use landlock::Scope::Signal;
use policy::load_policy;
use identity::check_identity;
use logger::log_security_event;
use runner::run_app_sandboxed;
use sandbox::prepare_sandbox;
fn main() {
    
    let args: Vec<String> = std::env::args().collect();
    
    
    let (policy_path, app_path) = match check_cli(&args){
        Ok(paths) => paths,
        Err(err) => {
            log_security_event("unknown", "cli_check", "deny", &err, 1.0);
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };
    
    log_security_event("unknown", "cli_check", "allow", "CLI arguments validated successfully", 0.0);

    let policy = match load_policy(&policy_path){
        Ok(policy) => policy,
        Err(err) => {
            log_security_event("unknown", "policy_load", "deny", &err, 1.0);
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };
    
    log_security_event(&policy.app_id, "policy_load", "allow", "Policy loaded successfully", 0.0);
    
    match check_identity(&app_path, &policy){
        Ok(()) => {
            log_security_event(&policy.app_id, "identity_check", "allow", "Identity verified", 0.0);
        },
        Err(err) => {
            eprintln!("Identity check failed for app: {}. Reason: {}", app_path, err);
            log_security_event(&policy.app_id, "identity_check", "deny", &err, 1.0);
            std::process::exit(1);
        }
    }


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
        .cpu_seconds
        .map_or("unlimited".to_string(), |value| format!("{}s", value));

    let memory = config
        .resources
        .memory_bytes
        .map_or("unlimited".to_string(), |value| {
            format!("{} MB", value / 1024 / 1024)
        });

    let file_size = config
        .resources
        .max_file_size_bytes
        .map_or("unlimited".to_string(), |value| {
            format!("{} MB", value / 1024 / 1024)
        });

    let processes = config
        .resources
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


// -----------------------------------------------------------------
    log_security_event(&policy.app_id, "app_spawn_attempt", "allow", "Executing application", 0.0);
    
    match run_app_sandboxed(&app_path, config) {
        Ok(status) => {
            if status.success() {
                
                log_security_event(&policy.app_id, "app_exit", "allow", &format!("App executed with status: {}", status), 0.0);
                println!("Application exited with status: {}", status);
            
            } else if let Some(signal) = status.signal() {
                
                match Some(signal) {
                    Some(25) => {
                        log_security_event(&policy.app_id, "resource_limit_hit" , "deny", &format!("Application killed by signal 25 : File size limit exceeded"), 0.7);
                        eprintln!("Application killed by singal : {} : File size limit exceeded ",signal);
                        std::process::exit(1);
                    },
                    Some(9) => {
                        log_security_event(&policy.app_id, "resource_limit_hit" , "deny", &format!("Application killed by signal 9 : Application killed by SIGKILL, possibly hard resource limit "), 0.7);
                        eprintln!("Application killed by singal : {} : Application killed by SIGKILL, possibly hard resource limit",signal);
                        std::process::exit(1);
                    },
                    Some(24) => {
                        log_security_event(&policy.app_id, "resource_limit_hit" , "deny", &format!("Application killed by signal 24 : CPU was limited "), 0.7);
                        eprintln!("Application killed by singal : {} : CPU is limited",signal);
                        std::process::exit(1);
                    },
                    _ => { 
                        log_security_event(&policy.app_id, "app_exit", "deny", &format!("Application killed by signal: {}",signal ), 1.0);
                        eprintln!("Application killed by singal : {} ",signal);
                        std::process::exit(1);
                    }
                }


            } else  {
            
                log_security_event(&policy.app_id, "app_exit", "deny", &format!("App executed with status: {}", status), 1.0);
                eprintln!("Application exited with status: {} ", status);
                std::process::exit(1);
            
            }
        },
        Err(err) => {
            log_security_event(&policy.app_id, "app_exit", "deny", &err, 1.0);
            eprintln!("Failed to execute app: {}", err);
            std::process::exit(1);
        }
    };


    


}