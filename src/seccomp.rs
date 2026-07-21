use libseccomp::{
    ScmpAction,
    ScmpFilterContext,
    ScmpSyscall,
};

use crate::sandbox::SeccompConfig;

pub fn apply_seccomp_filter(config: &SeccompConfig) -> Result<(),String> {
    
    if !config.enable {
        return Ok(());
    }

    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)
        .map_err(|err| format!("Failed to create Seccomp filter : {}",err))?;

    for syscall_name in &config.denied_syscalls {
        
        let syscall = ScmpSyscall::from_name(syscall_name)
            .map_err(|err| format!("Unknown syscall in Seccomp policy: {}",syscall_name))?;

        filter
            .add_rule(ScmpAction::Errno(libc::EPERM), syscall)
            .map_err(|err| format!("Failed to add Seccomp rule for syscall {} : {}",syscall_name,err))?;
    }

    filter
        .load()
        .map_err(|err| format!("Failed to load the Seccomp filter : {}",err))?;

    Ok(())
}