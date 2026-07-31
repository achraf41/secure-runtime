use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};
use landlock::Errno;
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::{fork, ForkResult},
};


use crate::cli::CliArgs;
use crate::seccomp::apply_seccomp_filter;
use crate::sandbox::{
    apply_landlock_sandbox,
    apply_resource_limits,
    SandboxConfig,
};
use crate::namespaces::{apply_namespaces, prepare_pid_namespace,mount_private_porc};


pub fn run_app_sandboxed(
    cli: &CliArgs,
    config: SandboxConfig,
) -> Result<ExitStatus, String> {
    let mut command = Command::new(&cli.app_path);

    command.args(&cli.app_arg);

    unsafe {
        command.pre_exec(move || {

            apply_namespaces(&config.namespace)
            .map_err(|errno| {
                eprintln!(
                    "Namespace setup failed: {} (errno {})",
                    errno,
                    errno as i32
                );

                std::io::Error::from_raw_os_error(errno as i32)
            })?;

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

pub fn run_app( cli: &CliArgs, config: SandboxConfig ) -> Result<WaitStatus, String> {

    let mut command = Command::new(&cli.app_path);
    command.args(&cli.app_arg);

    apply_namespaces(&config.namespace)
        .map_err(|error| format!("Namespace setup failed: {error}"))?;

    prepare_pid_namespace(config.namespace.pid)
        .map_err(|error| format!("PID namespace setup failed: {error}"))?;

    match unsafe { fork() }
        .map_err(|error| format!("Fork failed: {error}"))?
    {
        ForkResult::Child => {
            if config.namespace.pid {
                mount_private_porc()
                    .map_err(|error| format!("Failed to mount privat /proc : {error}"))?;
            }
            apply_resource_limits(&config.resources)
                .map_err(|error| format!("Resource limits failed: {error}"))?;

            apply_landlock_sandbox(&config)
                .map_err(|error| format!("Landlock failed: {error}"))?;

            apply_seccomp_filter(&config.seccomp)
                .map_err(|error| format!("Seccomp failed: {error}"))?;

            let error = command.exec();

            Err(format!(
                "Failed to execute application: {error}"
            ))
        }

        ForkResult::Parent { child } => {
            let status = waitpid(child, None)
                .map_err(|error| format!("waitpid failed: {error}"))?;

            match status {
                WaitStatus::Exited(_, code) => {
                    println!("Application exited with code: {code}");
                }

                WaitStatus::Signaled(_, signal, _) => {
                    println!("Application terminated by signal: {signal:?}");
                }

                other => {
                    println!("Application status: {other:?}");
                }
                
            }
            
            Ok(status) 
        }

    }

}