use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicI32, Ordering};
use nix::{
    errno::Errno,
    sys::{
        signal::{ Signal,killpg},
        wait::{waitpid, WaitStatus,WaitPidFlag},
    },
    unistd::{fork, setpgid, ForkResult, Pid, getpid},
};
use crate::identity::VerifiedExecutable;
use crate::logger::log_resource_usage;
use crate::privileges::{
    apply_no_new_privs,
    drop_all_capabilities,
};
use crate::cli::CliArgs;
use crate::seccomp::apply_seccomp_filter;
use crate::sandbox::{
    apply_landlock_sandbox,
    apply_resource_limits,
    SandboxConfig,
};
use crate::namespaces::{apply_namespaces, prepare_pid_namespace,mount_private_proc};
use nix::sys::signal::{
    sigaction,
    SaFlags,
    SigAction,
    SigHandler,
    SigSet,
};
use crate::cgroup::{
    cleanup_cgroup, move_process_to_cgroup, prepare_cgroup, read_cgroup_stats,
};
use crate::executor::exec_verified;

static RECEIVED_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn handle_signal(signal: libc::c_int) {
    RECEIVED_SIGNAL.store(signal, Ordering::SeqCst);
}



#[derive(Debug)]
enum ApplicationResult {
    Exited(WaitStatus),
    TimedOut,
}



fn install_signal_handlers() -> Result<(),String> {
    let action = SigAction::new(
        SigHandler::Handler(handle_signal),
        SaFlags::empty(), 
        SigSet::empty()
    );

    unsafe {
        sigaction(Signal::SIGINT,&action)
            .map_err(|error| format!("Failed to install SIGINT handler : {error}"))?;
        sigaction(Signal::SIGTERM, &action)
            .map_err(|error| format!("Failed to install SIGTERM handler: {error}"))?;
        sigaction(Signal::SIGHUP, &action)
            .map_err(|error| format!("Failed to install SIGHUB handler : {error} "))?;
    }
    Ok(())

}

fn forward_recived_signal(main_child: Pid) -> Result<(),String> {
    let signal_number = RECEIVED_SIGNAL.swap(0,Ordering::SeqCst);

    if signal_number == 0 {
        return Ok(());
    }

    let signal = Signal::try_from(signal_number)
        .map_err(|_| format!("Invalid received signal: {signal_number}"))?;

    match killpg(main_child, signal) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(error) => {
            return Err(format!("Failed to forward {signal:?} to application {error} "));
        }
    }

    Ok(())
}

fn run_pid1_supervisor(executable: &VerifiedExecutable, app_args: &[String], config: &SandboxConfig) -> Result<ApplicationResult,String> {
    
     mount_private_proc()
        .map_err(|error| format!("Failed to mount private /proc: {error}"))?;
    

    match unsafe { fork() }
        .map_err(|error| format!("Application fork failed : {error}"))?
    {
        ForkResult::Parent { child } => {
            install_signal_handlers()?;

            let main_child = child;
            let mut main_status: Option<WaitStatus> = None;
            let mut shutdown_deadline: Option<Instant> = None;
            let execution_deadline = config.resources.timeout_seconds
                .map(|seconds| Instant::now() + Duration::from_secs(seconds));
            let mut timeout_triggered = false;
            let mut sigkill_sent = false;
            //let process_group = Pid::from_raw(-main_child.as_raw());


            
            
            loop {
                forward_recived_signal(main_child)?;

                if !timeout_triggered && main_status.is_none() {
                    if let Some(deadline) = execution_deadline {
                        if Instant::now() >= deadline {
                            timeout_triggered = true;

                            println!("Application runtime timeout reached");

                            match killpg(main_child, Signal::SIGTERM) {
                                Ok(()) | Err(Errno::ESRCH) => {}
                                Err(error) => {
                                    return Err(format!("Failed to terminate time-out application : {error}"));
                                }
                            }
                            shutdown_deadline = Some(Instant::now() + Duration::from_secs(3));
                        }
                    }
                }

                let flags = if shutdown_deadline.is_some() || execution_deadline.is_some() {
                    Some(WaitPidFlag::WNOHANG)
                } else {
                        None
                };
                match waitpid(Pid::from_raw(-1), flags) {
                    Ok(status) => {
                        match status {
                            WaitStatus::Exited(pid,code ) => {
                                
                                println!("Reaped child {pid} : exited with code {code}");
                                
                                if pid == main_child {
                                    main_status = Some(WaitStatus::Exited(pid, code));
                                
                                    
                                    match killpg(main_child, Signal::SIGTERM) {
                                        Ok(()) | Err(Errno::ESRCH) => {
                                        }
                                        Err(error) => {
                                            return Err(format!("Failed to terminate application process group : {error}"));
                                        }
                                    }
                                    shutdown_deadline = Some(Instant::now() + Duration::from_secs(3));
                                }

                            }
                            WaitStatus::Signaled(pid, signal, core_dumped) => {
                                
                                println!("Reaped chiled {pid} terminated by {signal:?}, core dumped: {core_dumped} ");
                                if pid == main_child {
                                    main_status = Some(WaitStatus::Signaled(pid, signal, core_dumped));
                                    
                                    match killpg(main_child, Signal::SIGTERM) {
                                        Ok(()) | Err(Errno::ESRCH) => {
                                        }
                                        Err(error) => {
                                            return Err(format!("Failed to terminate application process group : {error}"));
                                        }
                                    }

                                    shutdown_deadline = Some(Instant::now() + Duration::from_secs(3));
                                }
                            }
                            WaitStatus::Stopped(pid, signal) => {
                                
                                println!("Child {pid} stopped by signal {signal:?}");

                            }
                            WaitStatus::Continued(pid) => {
                                
                                println!("Child {pid} continued ");
                            }
                            WaitStatus::StillAlive => {
                                if let Some(deadline) = shutdown_deadline {
                                    if Instant::now() >= deadline && !sigkill_sent {
                                        match killpg(main_child , Signal::SIGKILL) {
                                            Ok(()) | Err(Errno::ESRCH) => {}
                                            Err(error) => {
                                                return Err(format!("Failed to kill remaining sandbox processes : {error}"));
                                            }
                                        }
                                        sigkill_sent = true;
                                    }
                                }
                                std::thread::sleep(Duration::from_millis(50));
                            }
                            other => {
                                
                                println!("child status : {other:?} ");
                            }
                        }
                    }
                    Err(Errno::EINTR) => {
                        continue;
                    }
                    Err(Errno::ECHILD) => {
                        break;
                    }
                    Err(error) => {
                        return Err(format!("Failed while reaping processes: {error}"));
                    }

                }
            }
            
            if timeout_triggered {
                return Ok(ApplicationResult::TimedOut);
            }
            
            let status = main_status
                    .ok_or_else(|| "The main application disappeared without a final status".to_string())?;
            
            Ok(ApplicationResult::Exited(status))

        }
        ForkResult::Child => {
            setpgid(Pid::from_raw(0), Pid::from_raw(0))
                .map_err(|error| format!("Failed to create application process group: {error}"))?;
            apply_resource_limits(&config.resources.rlimit)
                    .map_err(|error| format!("Resource limits failed: {error}"))?;

            apply_landlock_sandbox(&config)
                .map_err(|error| format!("Landlock failed: {error}"))?;

            apply_no_new_privs()
                .map_err(|error| format!("no_new_privs failed: {error}"))?;

            drop_all_capabilities()
                .map_err(|error| format!("Capability dropping failed: {error}"))?;

            apply_seccomp_filter(&config.seccomp)
                .map_err(|error| format!("Seccomp failed: {error}"))?;

            exec_verified(executable,app_args)?;

            unreachable!();
        }
    }
}





fn exit_with_child_status(status: WaitStatus) -> ! {
    match status {
        WaitStatus::Exited(_, code) => {
            std::process::exit(code);
        }

        WaitStatus::Signaled(_, signal, _) => {
            // Conventional Unix representation for a process killed by a signal.
            std::process::exit(128 + signal as i32);
        }

        other => {
            eprintln!("Unexpected application status: {other:?}");
            std::process::exit(1);
        }
    }
}

pub fn run_app(cli: &CliArgs, config: SandboxConfig, executable: VerifiedExecutable) -> Result<WaitStatus, String> {
    
    let sandbox_cgroup = prepare_cgroup(&config.resources.cgroup)?;

    match unsafe { fork() }
        .map_err(|error| format!("Launcher fork failed: {error}"))?
    {
        ForkResult::Child => {
            
            if let Some(cgroup_path) = &sandbox_cgroup {
                move_process_to_cgroup(cgroup_path, getpid())
                    .map_err(|error| format!("Failed to move sandbox launcher into cgroup : {error}"))?;
            }

            apply_namespaces(&config.namespace)
                .map_err(|error| format!("Namespace setup failed: {error}"))?;

            prepare_pid_namespace(config.namespace.pid)
                .map_err(|error|format!("PID namespace setup failed: {error}"))?;

            match unsafe { fork() }
                .map_err(|error| format!("Application fork failed: {error}"))?
            {
                
                ForkResult::Parent { child } => {
                    let result = if config.namespace.pid {

                        let status = waitpid(child, None)
                            .map_err(|error| format!("PID1 waitpid failed: {error}"))?;

                        ApplicationResult::Exited(status)
                    } else {
                        wait_with_timeout(child,config.resources.timeout_seconds,)?
                    };

                    match result {
                        ApplicationResult::Exited(status) => {
                            match status {
                                WaitStatus::Exited(_, code) => {
                                    println!("Application exited with code: {code}");
                                }

                                WaitStatus::Signaled(_,signal,_,) => {
                                    println!("Application terminated by signal: {signal:?}");
                                }

                                _ => {}
                            }

                            exit_with_child_status(status);
                        }

                        ApplicationResult::TimedOut => {
                            eprintln!("Application terminated: runtime timeout exceeded");

                            std::process::exit(124);
                        }
                    }
                }

                ForkResult::Child => {
                    
                    if config.namespace.pid {
                        match run_pid1_supervisor(&executable, &cli.app_arg, &config)? {
                            ApplicationResult::Exited(status) => {
                                exit_with_child_status(status)
                            }
                            ApplicationResult::TimedOut => {
                                eprintln!("Application terminated: runtime timeout exceeded");
                                std::process::exit(124);
                            }
                        }
                    }

                    apply_resource_limits(&config.resources.rlimit)
                        .map_err(|error| format!("Resource limits failed: {error}"))?;

                    apply_landlock_sandbox(&config)
                        .map_err(|error| format!("Landlock failed: {error}"))?;

                    apply_no_new_privs()
                        .map_err(|error| format!("no_new_privs failed: {error}"))?;

                    drop_all_capabilities()
                        .map_err(|error| format!("Capability dropping failed: {error}"))?;

                    apply_seccomp_filter(&config.seccomp)
                        .map_err(|error| format!("Seccomp failed: {error}"))?;

                    exec_verified(&executable,&cli.app_arg)?;
                    unreachable!();
                    
                }
            }
        }

      
        ForkResult::Parent { child } => {
            let status = waitpid(child, None)
                .map_err(|error| {
                    format!("Launcher waitpid failed: {error}")
                })?;
            
            if let Some(cgroup_path) = &sandbox_cgroup {
                let stats = read_cgroup_stats(cgroup_path)?;
                println!("Cgroup statistics: {stats:#?}");
                log_resource_usage(&config.app_id, &stats)?;
                cleanup_cgroup(cgroup_path)?;
            }

            Ok(status)
        }
    }
}

fn wait_with_timeout(
    main_child: Pid,
    timeout_seconds: Option<u64>,
) -> Result<ApplicationResult, String> {
    let execution_deadline = timeout_seconds
        .map(|seconds| {
            Instant::now() + Duration::from_secs(seconds)
        });

    let mut timeout_triggered = false;
    let mut shutdown_deadline: Option<Instant> = None;
    let mut sigkill_sent = false;

    loop {
        let use_nonblocking =
            execution_deadline.is_some()
                || shutdown_deadline.is_some();

        let flags = if use_nonblocking {
            Some(WaitPidFlag::WNOHANG)
        } else {
            None
        };

        match waitpid(main_child, flags) {
            Ok(WaitStatus::Exited(pid, code)) => {
                let status = WaitStatus::Exited(pid, code);

                if timeout_triggered {
                    return Ok(ApplicationResult::TimedOut);
                }

                return Ok(ApplicationResult::Exited(status));
            }

            Ok(WaitStatus::Signaled(
                pid,
                signal,
                core_dumped,
            )) => {
                let status = WaitStatus::Signaled(
                    pid,
                    signal,
                    core_dumped,
                );

                if timeout_triggered {
                    return Ok(ApplicationResult::TimedOut);
                }

                return Ok(ApplicationResult::Exited(status));
            }

            Ok(WaitStatus::StillAlive) => {
                if !timeout_triggered {
                    if let Some(deadline) = execution_deadline {
                        if Instant::now() >= deadline {
                            timeout_triggered = true;

                            eprintln!(
                                "Application runtime timeout reached"
                            );

                            match killpg(
                                main_child,
                                Signal::SIGTERM,
                            ) {
                                Ok(())
                                | Err(Errno::ESRCH) => {}

                                Err(error) => {
                                    return Err(format!(
                                        "Failed to terminate timed-out application: {error}"
                                    ));
                                }
                            }

                            shutdown_deadline = Some(
                                Instant::now()
                                    + Duration::from_secs(3),
                            );
                        }
                    }
                }

                if timeout_triggered && !sigkill_sent {
                    if let Some(deadline) = shutdown_deadline {
                        if Instant::now() >= deadline {
                            match killpg(
                                main_child,
                                Signal::SIGKILL,
                            ) {
                                Ok(())
                                | Err(Errno::ESRCH) => {}

                                Err(error) => {
                                    return Err(format!(
                                        "Failed to kill timed-out application: {error}"
                                    ));
                                }
                            }

                            sigkill_sent = true;
                        }
                    }
                }

                std::thread::sleep(
                    Duration::from_millis(50),
                );
            }

            Ok(other) => {
                println!(
                    "Application status: {other:?}"
                );
            }

            Err(Errno::EINTR) => continue,

            Err(error) => {
                return Err(format!(
                    "Application waitpid failed: {error}"
                ));
            }
        }
    }
}