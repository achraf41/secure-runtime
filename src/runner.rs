use std::process::Command;
use crate::sandbox::{SandboxConfig, apply_filesystem_sandbox};
use std::os::unix::process::CommandExt;


pub fn run_app_sandboxed(app_path: &str, config: SandboxConfig) -> Result<std::process::ExitStatus,String> {
    
    match unsafe { Command::new(app_path)
    .pre_exec(move || {
        apply_filesystem_sandbox(&config).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    })
    .status() } {
        
        Ok(status) => {   
            return Ok(status);
        }
        
        Err(err) => {
            return Err(format!("Failed to execute app: {}", err));
        }
    }
}
