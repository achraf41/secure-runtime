fn main() {
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };

    if result == -1 {
        let error = std::io::Error::last_os_error();

        println!("ptrace blocked: {}", error);

        if error.raw_os_error() == Some(libc::EPERM) {
            println!("OK: ptrace was blocked by Seccomp");
            std::process::exit(0);
        }

        eprintln!("Unexpected ptrace error: {}", error);
        std::process::exit(1);
    }

    println!("ptrace succeeded");
}
