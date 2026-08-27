use std::fs;

use nix::{
    errno::Errno,
    mount::{mount, MsFlags},
    sched::{unshare, CloneFlags},
    unistd::{getegid, geteuid, sethostname},
};

use crate::sandbox::{MountConfig, NamespaceConfig};


fn io_error_to_errno(error: std::io::Error) -> Errno {
    Errno::from_raw(
        error
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}


fn write_mapping(path: &str, content: &str) -> Result<(), Errno> {
    fs::write(path, content)
        .map_err(io_error_to_errno)
}

pub fn mount_private_proc() -> Result<(),Errno> {
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC ,
        None::<&str>,
    )?;
    
    Ok(())
}


fn apply_user_namespace() -> Result<(), Errno> {
    
    let host_uid = geteuid().as_raw();
    let host_gid = getegid().as_raw();

    unshare(CloneFlags::CLONE_NEWUSER)?;

    let uid_map = format!("0 {} 1\n",host_uid);
    write_mapping("/proc/self/uid_map", &uid_map)?;


    match fs::write("/proc/self/setgroups", "deny\n") {
        
        Ok(()) => {}
        
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprint!("system do not expose the file SETGROUPS ");
        },

        Err(error) => {
            return Err(io_error_to_errno(error));
        }
    }

    let gid_map = format!("0 {} 1\n",host_gid);
    write_mapping("/proc/self/gid_map", &gid_map)?;
    
    Ok(())

}

fn apply_mount_namespace(config: &MountConfig) -> Result<(),Errno> {


    mount(
        None::<&str>, 
        "/", 
        None::<&str>, 
        MsFlags::MS_REC | MsFlags::MS_PRIVATE, 
        None::<&str>,
    )?;


    if config.private_tmp {
        let mount_options = format!("size={}m,mode=1777",config.tmp_size_mb);
        mount(
            Some("tmpfs"),
            "/tmp",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some(mount_options.as_str()),
        )?;
    }

    Ok(())

}


pub fn apply_namespaces( config: &NamespaceConfig) -> Result<(), Errno> {
    
    if config.user_namespace_required {
        apply_user_namespace()?;
    }

    let mut namespace_flags = CloneFlags::empty();

    if config.uts.enabled {
        namespace_flags |= CloneFlags::CLONE_NEWUTS;
    }
    if config.ipc {
        namespace_flags |= CloneFlags::CLONE_NEWIPC;
    }
    if config.network {
        namespace_flags |= CloneFlags::CLONE_NEWNET;
    }
    if config.mount.enabled {
        namespace_flags |= CloneFlags::CLONE_NEWNS;
    }


    if !namespace_flags.is_empty() {
        unshare(namespace_flags)?;
    }

    if config.mount.enabled {

        apply_mount_namespace(&config.mount)?;
        

    }
    if config.uts.enabled {
        if let Some(hostname) = &config.uts.hostname {
            sethostname(hostname.as_str())?;
        }
    }


    Ok(())
}

pub fn prepare_pid_namespace(enabled: bool) -> Result<(),Errno> {
    if enabled {
        unshare(CloneFlags::CLONE_NEWPID)?;
    }
    Ok(())
}
