use std::ffi::CString;
use std::os::fd::AsRawFd;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use std::fs::OpenOptions;
use crate::identity::VerifiedExecutable;

pub fn exec_verified(executable: &VerifiedExecutable,app_args: &[String]) -> Result<(), String> {
    let fd = executable.file.as_raw_fd();
    
    redirect_stdin_to_dev_null()?;
    
    sanitize_file_descriptors(executable)?;

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


    let env: Vec<CString> = build_safe_environment()?;

   

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


fn sanitize_file_descriptors(executable: &VerifiedExecutable) -> Result<(), String> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    
    if result == -1 {
        return Err(format!("Failed to mark inherited file descriptiors CLOEXEC : {}",std::io::Error::last_os_error()));
    }

    let current_flag = fcntl(&executable.file, FcntlArg::F_GETFD)
        .map_err(|error| format!("Failed to read executable FD flags : {error}"))?;

    let mut flags =FdFlag::from_bits_truncate(current_flag);

    flags.remove(FdFlag::FD_CLOEXEC);

    fcntl(&executable.file, FcntlArg::F_SETFD(flags))
        .map_err(|error| format!("Failed to preserve verified executable FD : {error}"))?;


    Ok(())
}

fn build_safe_environment() -> Result<Vec<CString>, String> {
    let mut env = Vec::new();

    env.push(
        CString::new("PATH=/usr/local/bin:/usr/bin:/bin")
            .map_err(|_| "Invalid PATH".to_string())?
    );

    env.push(
        CString::new("HOME=/tmp")
            .map_err(|_| "Invalid HOME".to_string())?
    );

    if let Ok(lang) = std::env::var("LANG") {
        env.push(
            CString::new(format!("LANG={lang}"))
                .map_err(|_| "Invalid LANG".to_string())?
        );
    }

    if let Ok(term) = std::env::var("TERM") {
        env.push(
            CString::new(format!("TERM={term}"))
                .map_err(|_| "Invalid TERM".to_string())?
        );
    }

    Ok(env)
}

fn redirect_stdin_to_dev_null() -> Result<(), String> {
    let dev_null = OpenOptions::new()
        .read(true)
        .open("/dev/null")
        .map_err(|error| format!("Failed to open /dev/null : {error}"))?;

    let result = unsafe {
        libc::dup2(
            dev_null.as_raw_fd(),
            libc::STDIN_FILENO,
        )
    };

    if result == -1 {
        return Err(format!("Failed to redirect stdin to /dev/null : {}",std::io::Error::last_os_error()));
    }

    Ok(())
}