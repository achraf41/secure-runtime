use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicI32, Ordering};
use std::os::fd::OwnedFd;
use nix::{
    errno::Errno,
    fcntl::OFlag,
    sys::{
        signal::{kill, Signal,killpg},
        wait::{waitpid, WaitStatus,WaitPidFlag},
    },
    unistd::{fork, pipe2, read, setpgid, write, ForkResult, Pid, getpid},
};
use crate::cgroup::CgroupStats;
use crate::identity::VerifiedExecutable;
use crate::logger::EventLogger;
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

use crate::output::{
     OutputState, OutputWriter, RunObserver, create_output_pipes, drain_available_output, redirect_output_to_pipes,
};
use crate::control::{
    ControlReader,
    create_control_pipe,
    output_limit_requested,
    send_output_limit_exceeded,
};

static RECEIVED_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn handle_signal(signal: libc::c_int) {
    RECEIVED_SIGNAL.store(signal, Ordering::SeqCst);
}

const SUPERVISOR_POLL_INTERVAL: Duration =
    Duration::from_millis(5);

#[derive(Debug)]
enum ApplicationResult {
    Exited(WaitStatus),
    TimedOut,
    OutputLimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerOutcome {
    Exited(i32),
    Signaled(i32),
    TimedOut,
    OutputLimitExceeded,
}

#[derive(Debug)]
pub struct RunAppResult {
    pub launcher_status: WaitStatus,
    pub outcome: RunnerOutcome,
    pub output_bytes_observed: u64,
    pub output_limit_bytes: Option<u64>,
    pub cgroup_stats: Option<CgroupStats>,
}

struct OutcomeReader(OwnedFd);
struct OutcomeWriter(OwnedFd);

fn create_outcome_pipe() -> Result<(OutcomeReader, OutcomeWriter), String> {
    let (reader, writer) = pipe2(OFlag::O_CLOEXEC)
        .map_err(|error| format!("Failed to create runtime outcome pipe: {error}"))?;
    Ok((OutcomeReader(reader), OutcomeWriter(writer)))
}

fn send_outcome(writer: &OutcomeWriter, result: &ApplicationResult) -> Result<(), String> {
    let (tag, value) = match result {
        ApplicationResult::Exited(WaitStatus::Exited(_, code)) => (1u8, *code),
        ApplicationResult::Exited(WaitStatus::Signaled(_, signal, _)) => (2u8, *signal as i32),
        ApplicationResult::TimedOut => (3u8, 0),
        ApplicationResult::OutputLimitExceeded => (4u8, 0),
        ApplicationResult::Exited(status) => {
            return Err(format!("Unexpected final application status: {status:?}"));
        }
    };

    let mut message = [0u8; 5];
    message[0] = tag;
    message[1..].copy_from_slice(&value.to_ne_bytes());
    let mut written = 0;
    while written < message.len() {
        written += write(&writer.0, &message[written..])
            .map_err(|error| format!("Failed to report application outcome: {error}"))?;
    }
    Ok(())
}

fn receive_outcome(reader: &OutcomeReader, launcher_status: WaitStatus) -> Result<RunnerOutcome, String> {
    let mut message = [0u8; 5];
    let mut received = 0;
    while received < message.len() {
        let count = read(&reader.0, &mut message[received..])
            .map_err(|error| format!("Failed to read application outcome: {error}"))?;
        if count == 0 {
            break;
        }
        received += count;
    }

    if received == 0 {
        return match launcher_status {
            WaitStatus::Exited(_, code) => Ok(RunnerOutcome::Exited(code)),
            WaitStatus::Signaled(_, signal, _) => Ok(RunnerOutcome::Signaled(signal as i32)),
            status => Err(format!("Launcher returned unexpected status: {status:?}")),
        };
    }
    if received != message.len() {
        return Err("Application outcome message was incomplete".to_string());
    }

    let value = i32::from_ne_bytes(message[1..].try_into().expect("four-byte outcome value"));
    match message[0] {
        1 => Ok(RunnerOutcome::Exited(value)),
        2 => Ok(RunnerOutcome::Signaled(value)),
        3 => Ok(RunnerOutcome::TimedOut),
        4 => Ok(RunnerOutcome::OutputLimitExceeded),
        tag => Err(format!("Unknown application outcome tag: {tag}")),
    }
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

fn run_pid1_supervisor(executable: &VerifiedExecutable, app_args: &[String], config: &SandboxConfig, output_writer: OutputWriter) -> Result<ApplicationResult,String> {
    
     mount_private_proc()
        .map_err(|error| format!("Failed to mount private /proc: {error}"))?;
    

    match unsafe { fork() }
        .map_err(|error| format!("Application fork failed : {error}"))?
    {
        ForkResult::Parent { child } => {
            drop(output_writer);
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
                                
                                println!("Reaped child {pid} terminated by {signal:?}, core dumped: {core_dumped} ");
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
                                std::thread::sleep(SUPERVISOR_POLL_INTERVAL);
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

            redirect_output_to_pipes(&output_writer)?;
            drop(output_writer);

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

pub fn run_app(cli: &CliArgs, config: SandboxConfig, executable: VerifiedExecutable, observer: &dyn RunObserver, logger: &EventLogger) -> Result<RunAppResult, String> {
    
    let sandbox_cgroup = prepare_cgroup(&config.resources.cgroup)?;

    let (output_reader,output_writer) = create_output_pipes()?;

    let (control_reader, control_writer) = create_control_pipe()?;

    let (outcome_reader, outcome_writer) = create_outcome_pipe()?;

    match unsafe { fork() }
        .map_err(|error| format!("Launcher fork failed: {error}"))?
    {
        ForkResult::Child => {
            drop(output_reader);
            drop(control_writer);
            drop(outcome_reader);
            
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
                    drop(output_writer);
                    let result = if config.namespace.pid {

                        wait_for_pid1(child, &control_reader)?
                    } else {
                        wait_with_timeout(child,config.resources.timeout_seconds,&control_reader)?
                    };

                    if !config.namespace.pid {
                        send_outcome(&outcome_writer, &result)?;
                    }

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
                        ApplicationResult::OutputLimitExceeded => {
                            eprintln!("Application terminated: output limit exceeded");

                            std::process::exit(125);
                        }
                    }
                }

                ForkResult::Child => {
                    drop(control_reader);
                    if config.namespace.pid {
                        let result = run_pid1_supervisor(&executable, &cli.app_arg, &config, output_writer)?;
                        send_outcome(&outcome_writer, &result)?;
                        match result {
                            ApplicationResult::Exited(status) => {
                                exit_with_child_status(status)
                            }
                            ApplicationResult::TimedOut => {
                                eprintln!("Application terminated: runtime timeout exceeded");
                                std::process::exit(124);
                            }
                            ApplicationResult::OutputLimitExceeded => {
                                eprintln!("Application terminated: output limit exceeded");
                                std::process::exit(125);
                            }
                        }
                    }
                    else{
                    setpgid(Pid::from_raw(0),Pid::from_raw(0))
                        .map_err(|error| format!("Failed to create application process group : {error}"))?;
                    
                    redirect_output_to_pipes(&output_writer)?;
                    drop(output_writer);

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
        }

      
        ForkResult::Parent { child } => {
            drop(output_writer);
            drop(control_reader);
            drop(outcome_writer);

            let mut output_state = OutputState::new();
            let mut launcher_status: Option<WaitStatus> = None;
            let mut output_limit_notified = false;
            loop {
                if launcher_status.is_none() {
                    match waitpid(child,Some(WaitPidFlag::WNOHANG)) {
                        Ok(WaitStatus::StillAlive) => {}

                        Ok(status) => {launcher_status = Some(status);}

                        Err(Errno::EINTR) => {}

                        Err(error) => {return Err(format!("Launch waitpid failed: {error}"));}
                    }
                }
            
                drain_available_output(&output_reader, &mut output_state, config.resources.max_output_bytes, observer)?;
                if output_state.limit_exceeded && !output_limit_notified {
                    send_output_limit_exceeded(&control_writer)?;
                    output_limit_notified = true;
                }

                if launcher_status.is_some() && !output_state.stdout_open && !output_state.stderr_open {
                    break
                }

            }

            let status = launcher_status
                .ok_or_else(|| "Mauncher exited without a stuts".to_string())?;

            let reported_outcome = receive_outcome(&outcome_reader, status)?;
            let outcome = if output_state.limit_exceeded {
                RunnerOutcome::OutputLimitExceeded
            } else {
                reported_outcome
            };
            let cgroup_stats = if let Some(cgroup_path) = &sandbox_cgroup {
                let stats = read_cgroup_stats(cgroup_path)?;
                println!("Cgroup statistics: {stats:#?}");
                logger.log_resource_usage(&config.app_id, &stats)?;
                cleanup_cgroup(cgroup_path)?;
                Some(stats)
            } else {
                None
            };

            Ok(RunAppResult {
                launcher_status: status,
                outcome,
                output_bytes_observed: output_state.total_bytes,
                output_limit_bytes: config.resources.max_output_bytes,
                cgroup_stats,
            })
        }
    }
}


fn wait_for_pid1(pid1: Pid,control_reader: &ControlReader) -> Result<ApplicationResult, String> {
    
    let mut output_limit_triggered = false;
    let mut shutdown_deadline: Option<Instant> = None;
    let mut sigkill_sent = false;

    loop {
        if !output_limit_triggered && output_limit_requested(control_reader)? {
            
            output_limit_triggered = true;
            eprintln!("Application output limit exceeded");

            match kill(pid1,Signal::SIGTERM) {
                Ok(())
                | Err(Errno::ESRCH) => {}

                Err(error) => {
                    return Err(format!("Failed to notify PID1 about output limit: {error}"));
                }
            }

            shutdown_deadline = Some(
                Instant::now() + Duration::from_secs(3)
            );
        }

        match waitpid(pid1,Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {
                
                if output_limit_triggered && !sigkill_sent {
                    if let Some(deadline) = shutdown_deadline {
                        if Instant::now() >= deadline {
                            
                            match kill(pid1,Signal::SIGKILL) {
                                Ok(())
                                | Err(Errno::ESRCH) => {}

                                Err(error) => {
                                    return Err(format!("Failed to kill PID1 after output limit: {error}"));
                                }
                            }

                            sigkill_sent = true;
                        }
                    }
                }

                std::thread::sleep(SUPERVISOR_POLL_INTERVAL);
            }

            Ok(status) => {
                if output_limit_triggered {
                    return Ok(ApplicationResult::OutputLimitExceeded);
                }

                return Ok(ApplicationResult::Exited(status));
            }

            Err(Errno::EINTR) => {
                continue;
            }

            Err(error) => {
                return Err(format!("PID1 waitpid failed: {error}"));
            }
        }
    }
}



fn wait_with_timeout(main_child: Pid,timeout_seconds: Option<u64>,control_reader: &ControlReader) -> Result<ApplicationResult, String> {
    let execution_deadline = timeout_seconds
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));

    let mut timeout_triggered = false;
    let mut shutdown_deadline: Option<Instant> = None;
    let mut sigkill_sent = false;

    let mut output_limit_triggered = false;

    loop {
        let use_nonblocking =execution_deadline.is_some() || shutdown_deadline.is_some();

        let flags = if use_nonblocking {
            Some(WaitPidFlag::WNOHANG)
        } else {
            None
        };

        if !output_limit_triggered && !timeout_triggered && output_limit_requested(control_reader)? {
            output_limit_triggered = true;

            eprintln!("Application output limit exceeded");

            match killpg(main_child,Signal::SIGTERM,) {
                Ok(())
                | Err(Errno::ESRCH) => {}

                Err(error) => {
                    return Err(format!("Failed to terminate application after output limit: {error}"));
                }
            }

            shutdown_deadline = Some(
                Instant::now()+ Duration::from_secs(3)
            );
        }

        match waitpid(main_child, flags) {
            Ok(WaitStatus::Exited(pid, code)) => {
                let status = WaitStatus::Exited(pid, code);
                if output_limit_triggered {
                    return Ok(ApplicationResult::OutputLimitExceeded);
                }
                if timeout_triggered {
                    return Ok(ApplicationResult::TimedOut);
                }

                return Ok(ApplicationResult::Exited(status));
            }

            Ok(WaitStatus::Signaled(pid, signal, core_dumped)) => {
                let status = WaitStatus::Signaled(pid,signal,core_dumped);

                if output_limit_triggered {
                    return Ok(ApplicationResult::OutputLimitExceeded);
                }

                if timeout_triggered {
                    return Ok(ApplicationResult::TimedOut);
                }

                return Ok(ApplicationResult::Exited(status));
            }

            Ok(WaitStatus::StillAlive) => {
                if !timeout_triggered && !output_limit_triggered {
                    if let Some(deadline) = execution_deadline {
                        if Instant::now() >= deadline {
                            timeout_triggered = true;

                            eprintln!("Application runtime timeout reached");

                            match killpg(main_child,Signal::SIGTERM) {
                                Ok(())
                                | Err(Errno::ESRCH) => {}

                                Err(error) => {
                                    return Err(format!("Failed to terminate timed-out application: {error}"));
                                }
                            }

                            shutdown_deadline = Some(
                                Instant::now() + Duration::from_secs(3),
                            );
                        }
                    }
                }

                if (timeout_triggered || output_limit_triggered) && !sigkill_sent {
                    if let Some(deadline) = shutdown_deadline {
                        if Instant::now() >= deadline {
                            match killpg(main_child,Signal::SIGKILL) {
                                Ok(())
                                | Err(Errno::ESRCH) => {}

                                Err(error) => {
                                    return Err(format!("Failed to kill timed-out application: {error}"));
                                }
                            }

                            sigkill_sent = true;
                        }
                    }
                }

                std::thread::sleep(SUPERVISOR_POLL_INTERVAL);
            }

            Ok(other) => {
                println!("Application status: {other:?}");
            }

            Err(Errno::EINTR) => continue,

            Err(error) => {
                return Err(format!("Application waitpid failed: {error}"));
            }
        }
    }
}
