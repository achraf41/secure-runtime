use serde::{Deserialize, Serialize};
use libseccomp::ScmpSyscall;

#[derive(Debug, Serialize, Deserialize)]
pub struct UtsPolicy {
    pub enabled: Option<bool>,
    pub hostname: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MountPolicy {
    pub enabled: Option<bool>,
    pub private_tmp: Option<bool>,
    pub tmp_size_mb: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NamespacePolicy {
    pub uts: Option<UtsPolicy>,
    pub ipc: Option<bool>,
    pub network: Option<bool>,
    pub pid: Option<bool>,
    pub mount: Option<MountPolicy>,
}


#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeccompProfile {
    None,
    Baseline,
    Strict,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct SeccompPolicy{
    pub profile: Option<SeccompProfile>,
    pub deny: Option<Vec<String>>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub connect_tcp: Option<Vec<u16>>,
    pub bind_tcp: Option<Vec<u16>>,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct ResourcePolicy {
    pub cpu_seconds: Option<u64>,
    pub memory_mb: Option<u64>,
    pub max_file_size_mb: Option<u64>,
    pub max_processes: Option<u64>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct FileSystemPolicy {
    pub read_allow: Vec<String>,
    pub write_allow: Vec<String>,
    pub exec_allow: Vec<String>,
    pub deny: Vec<String>,


}
#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    pub policy_version: u32,
    pub app_id: String,
    pub app_path: String,
    pub app_hash: String,
    pub default_action: String,
    pub filesystem: FileSystemPolicy,
    pub resources: Option<ResourcePolicy>,
    pub network: Option<NetworkPolicy>,
    pub seccomp: Option<SeccompPolicy>,
    pub namespace: Option<NamespacePolicy>,
}


pub fn load_policy(path: &str) -> Result<Policy, String> {


    
    let policy_content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            return Err(format!("Failed to read policy file: {}", err));
        }
    };
    
    let policy: Policy = match serde_json::from_str(&policy_content) {
        Ok(policy) => policy,
        Err(err) => {
            return Err(format!("Failed to parse policy JSON: {}", err));
        }
    };
    
   
    validate_policy(&policy)?;
    validate_seccomp_names(&policy)?;
    validate_hostname(&policy)?;
    validate_mount_policy(&policy)?;

    return Ok(policy);
}


fn validate_policy(policy: &Policy) -> Result<(),String> {
    
     if policy.policy_version != 1 {
        return Err(format!("Unsupported policy version: {}. Supported version: 1",policy.policy_version))
    }

    if !policy.default_action.eq("allow") && !policy.default_action.eq("deny") {
        return Err(format!("Invalid default action in policy: {}", policy.default_action));    }
    

    if policy.filesystem.read_allow.is_empty() && policy.filesystem.write_allow.is_empty() && policy.filesystem.deny.is_empty() && policy.filesystem.exec_allow.is_empty() {
        return Err("File system policy is empty".to_string());
    }


    if let Some(resources) = &policy.resources {
        
        if let Some(cpu_s) = resources.cpu_seconds {
            if cpu_s == 0 {
                return Err("Invalid cpue seconds limite".to_string())
            }
        }
        
        if let Some(memory_mb_v) = resources.memory_mb {
            if memory_mb_v == 0 {
                return Err("Invalid memory limite".to_string())
            }
        }

        if let Some(max_filesz) = resources.max_file_size_mb {
            if max_filesz == 0 {
                return Err("Invalide max file size limit".to_string())
            }
        }
        
        if let Some(max_proce) = resources.max_processes {
            if max_proce == 0 {
                return Err("Invalid max process size limit".to_string())
            }
        }

    }


    if let Some(network) = &policy.network {
        if let Some(con_tcp) = &network.connect_tcp {
            if con_tcp.contains(&0) {
                return Err("Invalid port in connect tcp : 0 ".to_string());
            }
        }
        if let Some(bin_tcp) = &network.bind_tcp {
            if bin_tcp.contains(&0) {
                return Err("Invalid port in bind tcp : 0".to_string());
            }
        }
    }


    Ok(())
}

fn validate_seccomp_names(policy: &Policy) -> Result<(),String> {
    
    if let Some(seccomp) = &policy.seccomp {
        
        if let Some(deny_syscall) = &seccomp.deny {
            
            for syscall_name in deny_syscall {
                if syscall_name.trim().is_empty() {
                    return Err("Seccomp syscall name cannot be empty".to_string());
                }
                ScmpSyscall::from_name(syscall_name)
                    .map_err(|_| format!("Invalid syscall name in Seccomp policy : {}",syscall_name))?;
            
            }
        }
    }

    Ok(())
}

fn validate_hostname(policy: &Policy) -> Result<(),String> {

    if let Some(namespacepolicy) = &policy.namespace {
        if let Some(utspolicy) = &namespacepolicy.uts {
            let hostname = utspolicy.hostname.as_ref().ok_or_else(|| 
                {"UTS namespace require a hostname".to_string()}
            )?;

            if hostname.trim().is_empty() {
                return Err("UTS namespace hostname cannot be empty".to_string());
            }

            if hostname.len() > 64 {
                return Err("UTS namespace hostname exceed 63 characters".to_string());
            }

            if hostname.chars().any(char::is_whitespace) {
                return Err("UTS namespace hostname cannot have space ".to_string());
            }

        }
    }

    return Ok(());
}

fn validate_mount_policy(policy: &Policy) -> Result<(),String> {
    if let Some(namespace_policy) = &policy.namespace {
        if let Some(mount_policy) = &namespace_policy.mount {
            
            let mount_enable = mount_policy.enabled.unwrap_or(false);
            let mount_tmp = mount_policy.private_tmp.unwrap_or(false);
            
            if !mount_enable && mount_tmp  {
                return Err("mount private tmp require mount enable ".to_string());
            }
            if let Some(size) = mount_policy.tmp_size_mb {
                if size == 0 {
                    return Err("tmp size can not be 0 ".to_string());
                }
                if size > 1024 {
                    return Err("tmp size can not exceed 1024 MB".to_string());
                }
            }
        }
    }

    Ok(())
}