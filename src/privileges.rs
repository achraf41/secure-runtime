use std::io;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAP_SETPCAP: u32 = 8;

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn apply_no_new_privs() -> Result<(), String> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == -1 {
        return Err(format!(
            "Failed to enable no_new_privs: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Remove every capability usable by the application.
///
/// An unprivileged process may clear its own active capability sets, but
/// PR_CAPBSET_DROP additionally requires effective CAP_SETPCAP. The bounding
/// set is therefore dropped only when authorized. In the ordinary-user case
/// its entries are harmless after the invariant below has been verified.
pub fn drop_all_capabilities() -> Result<(), String> {
    let initial = read_process_capabilities()?;
    if has_effective_capability(&initial, CAP_SETPCAP) {
        drop_bounding_set()?;
    }

    clear_ambient_capabilities()?;
    clear_process_capabilities()?;
    verify_capability_invariant()
}

fn drop_bounding_set() -> Result<(), String> {
    for capability in 0..=cap_last_cap() {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(format!(
                    "Failed to drop capability {capability} from bounding set: {error}"
                ));
            }
        }
    }
    Ok(())
}

fn clear_ambient_capabilities() -> Result<(), String> {
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
        // Kernels predating ambient capabilities report EINVAL and cannot
        // carry an ambient set.
        if error.raw_os_error() != Some(libc::EINVAL) {
            return Err(format!("Failed to clear ambient capabilities: {error}"));
        }
    }
    Ok(())
}

fn read_process_capabilities() -> Result<[CapabilityData; 2], String> {
    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapabilityData::default(), CapabilityData::default()];
    let result = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapabilityHeader,
            data.as_mut_ptr(),
        )
    };
    if result == -1 {
        return Err(format!(
            "Failed to inspect process capabilities: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(data)
}

fn has_effective_capability(data: &[CapabilityData; 2], capability: u32) -> bool {
    let word = (capability / 32) as usize;
    word < data.len() && data[word].effective & (1u32 << (capability % 32)) != 0
}

fn clear_process_capabilities() -> Result<(), String> {
    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapabilityData::default(), CapabilityData::default()];
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

fn verify_capability_invariant() -> Result<(), String> {
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if no_new_privs != 1 {
        let detail = if no_new_privs == -1 {
            io::Error::last_os_error().to_string()
        } else {
            format!("unexpected value {no_new_privs}")
        };
        return Err(format!(
            "Capability invariant requires no_new_privs=1: {detail}"
        ));
    }

    let data = read_process_capabilities()?;
    if data
        .iter()
        .any(|word| word.effective != 0 || word.permitted != 0 || word.inheritable != 0)
    {
        return Err(
            "Capability invariant failed: effective, permitted, or inheritable capabilities remain"
                .to_string(),
        );
    }

    for capability in 0..=cap_last_cap() {
        let result = unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET,
                capability,
                0,
                0,
            )
        };
        if result == 1 {
            return Err(format!(
                "Capability invariant failed: ambient capability {capability} remains"
            ));
        }
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(format!(
                    "Failed to verify ambient capability {capability}: {error}"
                ));
            }
            break;
        }
    }
    Ok(())
}

fn cap_last_cap() -> libc::c_ulong {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(40)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounding_drop_requires_effective_setpcap() {
        let empty = [CapabilityData::default(), CapabilityData::default()];
        assert!(!has_effective_capability(&empty, CAP_SETPCAP));

        let mut authorized = empty;
        authorized[0].effective = 1 << CAP_SETPCAP;
        assert!(has_effective_capability(&authorized, CAP_SETPCAP));
    }

    #[test]
    fn permitted_setpcap_alone_does_not_authorize_bounding_drop() {
        let mut data = [CapabilityData::default(), CapabilityData::default()];
        data[0].permitted = 1 << CAP_SETPCAP;
        assert!(!has_effective_capability(&data, CAP_SETPCAP));
    }
}
