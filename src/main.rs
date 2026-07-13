
mod cli;
mod policy;
mod engine;
mod hash;
mod identity;
mod logger;
mod runner;
mod sandbox;

use cli::check_cli;
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


    log_security_event(&policy.app_id, "app_spawn_attempt", "allow", "Executing application", 0.0);
    
    match run_app_sandboxed(&app_path, config) {
        Ok(status) => {
            if status.success() {
                log_security_event(&policy.app_id, "app_exit", "allow", &format!("App executed with status: {}", status), 0.0);
                println!("Application exited with status: {}", status);
            }else  {
                log_security_event(&policy.app_id, "app_exit", "deny", &format!("App executed with status: {}", status), 1.0);
                eprintln!("Application exited with status: {}", status);
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