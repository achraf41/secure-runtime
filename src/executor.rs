use std::ffi::CString;
use std::os::fd::AsRawFd;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};

use crate::identity::VerifiedExecutable;

pub fn exec_verified(executable: &VerifiedExecutable,app_args: &[String]) -> Result<(), String> {
    let fd = executable.file.as_raw_fd();

    let current_flags = fcntl(&executable.file, FcntlArg::F_GETFD)
    .map_err(|error| format!("Failed to read executable FD flags: {error}"))?;

    let mut flags = FdFlag::from_bits_truncate(current_flags);

    flags.remove(FdFlag::FD_CLOEXEC);

    fcntl(&executable.file, FcntlArg::F_SETFD(flags))
        .map_err(|error| format!("Failed to clear FD_CLOEXEC on executable: {error}"))?;

    let argv0 = CString::new(executable.path.to_string_lossy().as_bytes(),)
        .map_err(|_| "Executable path contains NUL byte".to_string())?;

    let args = app_args
        .iter()
        .map(|arg| CString::new(arg.as_str())
                .map_err(|_| format!("Application argument contains NUL byte: {arg:?}")))
        .collect::<Result<Vec<CString>,String>>()?;
    
    let mut argv: Vec<*const libc::c_char> =
        Vec::with_capacity(args.len() + 2);

    argv.push(argv0.as_ptr());

    for arg in &args {
        argv.push(arg.as_ptr());
    }

    argv.push(std::ptr::null());


    let env: Vec<CString> = std::env::vars_os()
        .map(|(key, value)| {
            let mut entry =
                key.into_encoded_bytes();

            entry.push(b'=');
            entry.extend(value.into_encoded_bytes());

            CString::new(entry)
                .map_err(|_| "Environment variable contains NUL byte".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

   

    let mut envp: Vec<*const libc::c_char> =
        env.iter()
            .map(|entry| entry.as_ptr())
            .collect();

    envp.push(std::ptr::null());

    let empty_path =
        CString::new("")
            .expect("empty CString cannot fail");

    let result = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            empty_path.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };

    if result == -1 {
        return Err(format!(
            "execveat failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    unreachable!("execveat returned successfully");

    
}