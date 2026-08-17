use std::io;

pub fn apply_no_new_privs() -> Result<(), String> {
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1,
            0,
            0,
            0,
        )
    };

    if result == -1 {
        return Err(format!(
            "Failed to enable no_new_privs: {}",
            io::Error::last_os_error()
        ));
    }

    Ok(())
}

pub fn drop_all_capabilities() -> Result<(), String> {
    // Drop capabilities from the bounding set first.
    // This must happen before clearing CAP_SETPCAP.
    for capability in 0..=cap_last_cap() {
        let result = unsafe {
            libc::prctl(
                libc::PR_CAPBSET_DROP,
                capability,
                0,
                0,
                0,
            )
        };

        if result == -1 {
            let error = io::Error::last_os_error();

            // Ignore unsupported capability numbers.
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(format!(
                    "Failed to drop capability {capability} from bounding set: {error}"
                ));
            }
        }
    }

    // Remove all ambient capabilities.
    let result = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };

    if result == -1 {
        let error = io::Error::last_os_error();

        if error.raw_os_error() != Some(libc::EINVAL) {
            return Err(format!(
                "Failed to clear ambient capabilities: {error}"
            ));
        }
    }

    clear_process_capabilities()
}

fn clear_process_capabilities() -> Result<(), String> {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };

    let mut data = [
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapabilityHeader,
            data.as_mut_ptr(),
        )
    };

    if result == -1 {
        return Err(format!(
            "Failed to clear process capabilities: {}",
            io::Error::last_os_error()
        ));
    }

    Ok(())
}

fn cap_last_cap() -> libc::c_ulong {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(40)
}