use std::os::fd::{AsRawFd, OwnedFd,AsFd};

use nix::{
    fcntl::OFlag,
    unistd::{read,pipe2},
};
use nix::poll::{
    poll,
    PollFd,
    PollFlags,
    PollTimeout,
};

use std::io::{self,Read, Write};

pub struct OutputState {
    pub stdout_open: bool,
    pub stderr_open: bool,
    pub total_bytes: u64,
    pub limit_exceeded: bool,
}

impl OutputState {
    pub fn new() -> Self {
        Self { 
            stdout_open: true, 
            stderr_open: true, 
            total_bytes: 0 ,
            limit_exceeded: false,
        }
    }
}

pub struct OutputReader {
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
}

pub struct OutputWriter {
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
}



pub fn create_output_pipes() -> Result<(OutputReader,OutputWriter), String> {
    
    let (stdout_read, stdout_write) = pipe2(OFlag::O_CLOEXEC)
        .map_err(|error| format!("Failed to create stdout pipe {error}"))?;

    let (stderr_read, stderr_write) = pipe2(OFlag::O_CLOEXEC)
        .map_err(|error| format!("Failed to create stderr pipe {error} "))?;

    Ok((OutputReader{stdout: stdout_read, stderr: stderr_read},OutputWriter{stdout: stdout_write, stderr: stderr_write}))
}

pub fn redirect_output_to_pipes(writer: &OutputWriter) -> Result<(),String> {
    
    let stdout_result = unsafe {
        libc::dup2(writer.stdout.as_raw_fd(),libc::STDOUT_FILENO)
    };

    if stdout_result == -1 {
        return Err(format!("Failed to redirect stdout : {}",std::io::Error::last_os_error()));
    }

    let stderr_result = unsafe {
        libc::dup2(writer.stderr.as_raw_fd(),libc::STDERR_FILENO)
    };

    if stderr_result == -1 {
        return Err(format!("Failed to redirect stderr : {}",std::io::Error::last_os_error()));
    }
    Ok(())
}

pub fn drain_available_output(reader: &OutputReader, state: &mut OutputState, max_output_bytes: Option<u64>) -> Result<(), String> {

    let mut poll_fds = [
        PollFd::new(reader.stdout.as_fd(), PollFlags::POLLIN | PollFlags::POLLHUP),
        PollFd::new(reader.stderr.as_fd(), PollFlags::POLLIN | PollFlags::POLLHUP),
    ];

    poll(&mut poll_fds, PollTimeout::from(50u16))
        .map_err(|error| format!("Output poll failed: {error}"))?;

    let stdout_events = poll_fds[0].revents();
    let stderr_events = poll_fds[1].revents();

    if state.stdout_open {
        if let Some(events) = stdout_events {
            if events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                let mut buffer = [0u8; 4096];

                let bytes_read =
                    read(&reader.stdout, &mut buffer)
                        .map_err(|error| format!("Failed to read stdout: {error}"))?;

                if bytes_read == 0 {
                    state.stdout_open = false;
                } else {
                    
                    let previous_total = state.total_bytes;

                    state.total_bytes = state
                        .total_bytes
                        .checked_add(bytes_read as u64)
                        .ok_or_else(|| "Application output byte counter overflow".to_string())?;

                    let bytes_to_forward = match max_output_bytes {
                        Some(limit) => {

                            let remaining = limit.saturating_sub(previous_total);
                            std::cmp::min(bytes_read,remaining as usize,)
                        }

                        None => bytes_read,
                    };

                    if bytes_to_forward > 0 {
                        io::stdout()
                            .write_all(&buffer[..bytes_to_forward])
                            .map_err(|error| format!("Failed to forward stdout: {error}"))?;

                        io::stdout()
                            .flush()
                            .map_err(|error| format!("Failed to flush stdout: {error}"))?;
                    }

                    if let Some(limit) = max_output_bytes {
                        if !state.limit_exceeded
                            && state.total_bytes > limit
                        {
                            state.limit_exceeded = true;

                            eprintln!("\nApplication output limit exceeded: {} > {} bytes",state.total_bytes,limit);
                        }
                    }

                }
            }
        }
    }

    if state.stderr_open {
        if let Some(events) = stderr_events {
            if events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                let mut buffer = [0u8; 4096];

                let bytes_read =
                    read(&reader.stderr, &mut buffer)
                        .map_err(|error| format!("Failed to read stderr: {error}"))?;

                if bytes_read == 0 {
                    state.stderr_open = false;
                } else {
                    let previous_total = state.total_bytes;

                    state.total_bytes = state
                        .total_bytes
                        .checked_add(bytes_read as u64)
                        .ok_or_else(|| "Application output byte counter overflow".to_string())?;

                    let bytes_to_forward = match max_output_bytes {
                        Some(limit) => {
                            let remaining = limit.saturating_sub(previous_total);

                            std::cmp::min(bytes_read,remaining as usize,)
                        }

                        None => bytes_read,
                    };

                    if bytes_to_forward > 0 {
                        io::stderr()
                            .write_all(&buffer[..bytes_to_forward])
                            .map_err(|error| format!("Failed to forward stderr: {error}"))?;

                        io::stderr()
                            .flush()
                            .map_err(|error| format!("Failed to flush stderr: {error}"))?;
                    }

                    if let Some(limit) = max_output_bytes {
                        if !state.limit_exceeded
                            && state.total_bytes > limit
                        {
                            state.limit_exceeded = true;

                            eprintln!("\nApplication output limit exceeded: {} > {} bytes",state.total_bytes,limit);
                        }
                    }
                }
            }
        }
    }

    

    Ok(())
}