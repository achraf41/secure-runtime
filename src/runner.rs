use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};
use crate::cli::CliArgs;
use crate::seccomp::apply_seccomp_filter;
use crate::sandbox::{
    apply_landlock_sandbox,
    apply_resource_limits,
    SandboxConfig,
};

pub fn run_app_sandboxed(
    cli: &CliArgs,
    config: SandboxConfig,
) -> Result<ExitStatus, String> {
    let mut command = Command::new(&cli.app_path);

    command.args(&cli.app_arg);

    unsafe {
        command.pre_exec(move || {
            
            apply_resource_limits(&config.resources)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            
            apply_landlock_sandbox(&config)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            
            apply_seccomp_filter(&config.seccomp)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            
            Ok(())
        
        });
    }

    command
        .status()
        .map_err(|err| format!("Failed to execute app: {}", err))
}