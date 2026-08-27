use std::os::fd::OwnedFd;

use nix::{
    errno::Errno,
    fcntl::OFlag,
    unistd::{pipe2, read, write},
};

const OUTPUT_LIMIT_EXCEEDED: u8 = 1;


pub struct ControlReader {
    pub fd: OwnedFd,
}


pub struct ControlWriter {
    pub fd: OwnedFd,
}


pub fn create_control_pipe() -> Result<(ControlReader, ControlWriter), String> {
    
    let (read_fd, write_fd) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .map_err(|error| format!("Failed to create runtime control pipe: {error}"))?;

    Ok((ControlReader {fd: read_fd},ControlWriter {fd: write_fd},))
}


pub fn send_output_limit_exceeded(
    writer: &ControlWriter,
) -> Result<(), String> {
    let command = [OUTPUT_LIMIT_EXCEEDED];

    match write(&writer.fd, &command) {
        Ok(1) => Ok(()),

        Ok(_) => Err(
            "Failed to send complete control command".to_string()
        ),

        Err(Errno::EAGAIN) => Err(
            "Runtime control pipe is full".to_string()
        ),

        Err(error) => Err(format!(
            "Failed to send output-limit control command: {error}"
        )),
    }
}


pub fn output_limit_requested(
    reader: &ControlReader,
) -> Result<bool, String> {
    let mut command = [0u8; 1];

    match read(&reader.fd, &mut command) {
        Ok(0) => Ok(false),

        Ok(_) => {
            Ok(command[0] == OUTPUT_LIMIT_EXCEEDED)
        }

        Err(Errno::EAGAIN) => Ok(false),

        Err(Errno::EINTR) => Ok(false),

        Err(error) => Err(format!(
            "Failed to read runtime control command: {error}"
        )),
    }
}