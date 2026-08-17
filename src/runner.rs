use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};
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

static RECEIVED_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn handle_signal(signal: libc::c_int) {
    RECEIVED_SIGNAL.store(signal, Ordering::SeqCst);
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

fn run_pid1_supervisor(command: &mut Command, config: &SandboxConfig) -> Result<WaitStatus,String> {
    
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
            let mut sigkill_sent = false;
            //let process_group = Pid::from_raw(-main_child.as_raw());


            
            
            loop {
                forward_recived_signal(main_child)?;

                let flags = if shutdown_deadline.is_some() {
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
            main_status.ok_or_else(|| "The main application disappeared without a final status".to_string())

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

            let error = command.exec();

            Err(format!("Failed to execute application: {error}"))
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

pub fn run_app(cli: &CliArgs, config: SandboxConfig) -> Result<WaitStatus, String> {
    
    let mut command = Command::new(&cli.app_path);
    command.args(&cli.app_arg);

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
                    let status = waitpid(child, None)
                        .map_err(|error| format!("Application waitpid failed: {error}"))?;

                    match status {
                        WaitStatus::Exited(_, code) => {
                            println!("Application exited with code: {code}");
                        }

                        WaitStatus::Signaled(_, signal, _) => {
                            println!(
                                "Application terminated by signal: {signal:?}"
                            );
                        }

                        other => {
                            println!("Application status: {other:?}");
                        }
                    }

                    exit_with_child_status(status);
                }

                ForkResult::Child => {
                    
                    if config.namespace.pid {
                        let status = run_pid1_supervisor(&mut command, &config)?;
                        exit_with_child_status(status);
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

                    let error = command.exec();

                    Err(format!(
                        "Failed to execute application: {error}"
                    ))
                    
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