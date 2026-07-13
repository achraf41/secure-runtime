use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};

use crate::sandbox::{apply_filesystem_sandbox, SandboxConfig};

pub fn run_app_sandboxed(
    app_path: &str,
    config: SandboxConfig,
) -> Result<ExitStatus, String> {
    let mut command = Command::new(app_path);

    unsafe {
        command.pre_exec(move || {
            apply_filesystem_sandbox(&config)
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))
        });
    }

    command
        .status()
        .map_err(|err| format!("Failed to execute app: {}", err))
}