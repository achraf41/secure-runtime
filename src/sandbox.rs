use std::path::PathBuf;
use rlimit::{setrlimit, Resource};

use crate::{cgroup, namespaces, policy::Policy};

use landlock::{
    ABI, Access, AccessFs, AccessNet, NetPort, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
};

use std::collections::HashSet;

use crate::policy::{SeccompPolicy, SeccompProfile};

#[derive(Debug, Clone)]
pub struct UtsConfig {
    pub enabled: bool,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MountConfig {
    pub enabled: bool,
    pub private_tmp: bool,
    pub tmp_size_mb: u64,
}

#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub user_namespace_required: bool,
    pub uts: UtsConfig,
    pub ipc: bool,
    pub network: bool,
    pub pid: bool,
    pub mount: MountConfig,
}

#[derive(Debug, Clone)]
pub struct SeccompConfig {
    pub enable: bool,
    pub profile: SeccompProfile,
    pub denied_syscalls: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CgroupConfig {
    pub enabled: bool,
    pub memory_bytes: Option<u64>,
    pub max_processes: Option<u64>,
    pub cpu_percent: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RlimitConfig {
    pub enabled: bool,
    pub memory_bytes: Option<u64>,
    pub max_processes: Option<u64>,
    pub cpu_seconds: Option<u64>,
    pub max_file_size_bytes: Option<u64>,
}


#[derive(Debug, Clone)]
pub struct ResourceConfig {
    pub rlimit: RlimitConfig,
    pub cgroup: CgroupConfig,
}


#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub connect_tcp: Vec<u16>,
    pub bind_tcp: Vec<u16>,
}


#[derive(Debug, Clone)]

pub struct SandboxConfig {
    pub app_id: String,
    pub read_allow: Vec<PathBuf>,
    pub write_allow: Vec<PathBuf>,
    pub exec_allow: Vec<PathBuf>,
    pub resources: ResourceConfig,
    pub network: NetworkConfig,
    pub seccomp: SeccompConfig,
    pub namespace: NamespaceConfig,
}


fn baseline_denied_syscalls() -> Vec<String> {
    vec![
        "ptrace",
        "mount",
        "umount2",
        "pivot_root",
        "reboot",
        "kexec_load",
        "kexec_file_load",
        "init_module",
        "finit_module",
        "delete_module",
        "swapon",
        "swapoff",
    ]
    .into_iter()
    .map(String::from)
    .collect()   
}

fn strict_denied_syscalls() -> Vec<String> {
    let mut syscalls = baseline_denied_syscalls();

    syscalls.extend(
        vec![
            "bpf",
            "perf_event_open",
            "userfaultfd",
            "keyctl",
            "add_key",
            "request_key",
            "setns",
            "unshare",
            "clone3",
            "process_vm_readv",
            "process_vm_writev",
            "open_by_handle_at",
            "name_to_handle_at",
        ]
        .into_iter()
        .map(String::from),
    );

    syscalls
}


fn build_denied_syscall(policy: &SeccompPolicy) -> Vec<String> {
    
    let mut denied = HashSet::new();

    match policy.profile.unwrap_or(SeccompProfile::None) {
        
        SeccompProfile::None => {}

        SeccompProfile::Baseline => {
            for syscall in baseline_denied_syscalls() {
                denied.insert(syscall);
            }
        }

        SeccompProfile::Strict => {
            for syscall in strict_denied_syscalls() {
                denied.insert(syscall);
            }
        }
    }

    if let Some(custom_deny) = &policy.deny {
        for syscall in custom_deny {
            denied.insert(syscall.clone());
        }
    }

    let mut denied: Vec<String>  = denied.into_iter().collect();
    denied.sort();

    denied
}

fn canonicalize_path_list(label: &str, paths: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut canonical_paths = Vec::new();

    for path in paths {
        let canonical_path = std::fs::canonicalize(path)
            .map_err(|err| format!("Invalid {} path '{}': {}", label, path, err))?;

        canonical_paths.push(canonical_path);
    }

    Ok(canonical_paths)
}


pub fn prepare_sandbox(policy: &Policy) -> Result<SandboxConfig,String> {
    


    let read_allow = canonicalize_path_list("read_allow", &policy.filesystem.read_allow)? ;
    let write_allow = canonicalize_path_list("write_allow", &policy.filesystem.write_allow)?;
    let exec_allow = canonicalize_path_list("exec_allow", &policy.filesystem.exec_allow)?;

    
    let resources = match &policy.resources {
        Some(resource_policy) => {
            let rlimit = match &resource_policy.rlimit {
                Some(rlimit) => RlimitConfig {
                    enabled: rlimit.enabled.unwrap_or(false),
                    memory_bytes: match resource_policy.memory_mb {
                            Some(mem_by) => {
                                match mem_by.checked_mul(1024) {
                                    Some(mem) => {
                                        match mem.checked_mul(1024) {
                                            Some(mem_f) => Some(mem_f),
                                            None => return Err("Overflow in memory byte".to_string())
                                        }
                                    }
                                    None => return Err("Overflow in memory byte".to_string())
                                }
                            }
                            None => None,
                        },
                    max_processes: resource_policy.max_processes,
                    cpu_seconds: rlimit.cpu_seconds,
                    max_file_size_bytes: match rlimit.max_file_size_mb {
                            Some(max_file) => {
                                match max_file.checked_mul(1024) {
                                    Some(max_file1) => {
                                        match max_file1.checked_mul(1024) {
                                            Some(max_filef) => Some(max_filef),
                                            None => return Err("Overflow in max file size".to_string())
                                        }
                                    },
                                    None => return Err("Overflow in max file size".to_string())
                                }
                            },
                            None => None
                        },

                },
                None => RlimitConfig { 
                    enabled: false, 
                    memory_bytes: None, 
                    max_processes: None, 
                    cpu_seconds: None, 
                    max_file_size_bytes: None 
                }
            
            };
            
            let cgroup = match &resource_policy.cgroup {
                Some(cgroup) => CgroupConfig {
                    enabled: cgroup.enabled.unwrap_or(false),
                    memory_bytes: match resource_policy.memory_mb {
                            Some(mem_by) => {
                                match mem_by.checked_mul(1024) {
                                    Some(mem) => {
                                        match mem.checked_mul(1024) {
                                            Some(mem_f) => Some(mem_f),
                                            None => return Err("Overflow in memory byte".to_string())
                                        }
                                    }
                                    None => return Err("Overflow in memory byte".to_string())
                                }
                            }
                            None => None,
                        },
                    max_processes: resource_policy.max_processes,
                    cpu_percent: cgroup.cpu_percent,
                },
                None => CgroupConfig { 
                    enabled: false, 
                    memory_bytes: None, 
                    max_processes: None, 
                    cpu_percent: None 
                }
            };
            ResourceConfig { rlimit, cgroup }
        }
        None => ResourceConfig { 
            rlimit: RlimitConfig { enabled: false, memory_bytes: None, max_processes: None, cpu_seconds: None, max_file_size_bytes: None }, 
            cgroup: CgroupConfig { enabled: false, memory_bytes: None, max_processes: None, cpu_percent: None } 
        }
    };


    let network: NetworkConfig = match &policy.network {
        Some(network_policy) => NetworkConfig {
            enabled: true,
            connect_tcp: match &network_policy.connect_tcp {
                Some(tcp) => tcp.clone() ,
                None => vec![] 
            },
            bind_tcp: match &network_policy.bind_tcp {
                Some(bind) => bind.clone(),
                None => vec![]}, 
        },
        None => NetworkConfig {
            enabled: false, 
            connect_tcp: vec![],
            bind_tcp: vec![], 
        }   
        
    };

    let seccomp = match &policy.seccomp {
        Some(secomp_policy) => {
            let profile = secomp_policy.profile.unwrap_or(SeccompProfile::None);
            SeccompConfig{
            enable: true,
            profile: profile,
            denied_syscalls: build_denied_syscall(secomp_policy),
        }},
        None => SeccompConfig { 
            enable: false,
            profile: SeccompProfile::None, 
            denied_syscalls: Vec::new(), 
        }
    };

    let uts_config = match &policy.namespace {
        Some(namespace_policy) => {
            match &namespace_policy.uts {
                Some(uts_policy) => UtsConfig {
                    enabled: uts_policy.enabled.unwrap_or(false),
                    hostname: uts_policy.hostname.clone(),
                },

                None => UtsConfig {
                    enabled: false,
                    hostname: None,
                },
            }
        }

        None => UtsConfig {
            enabled: false,
            hostname: None,
        },
    };

    let pid_ = policy.namespace.as_ref().and_then(|namespace| namespace.pid)
        .unwrap_or(false);

    let mount_config = match &policy.namespace {
        Some(namespace_policy) => {
            match &namespace_policy.mount {
                Some(mount_policy) => MountConfig {
                    enabled: mount_policy.enabled.unwrap_or(false) || pid_,
                    private_tmp: mount_policy.private_tmp.unwrap_or(false),
                    tmp_size_mb: mount_policy.tmp_size_mb.unwrap_or(32),
                },
                None => MountConfig { enabled: pid_, private_tmp: false, tmp_size_mb: 32 }
            }
        },
        None => MountConfig { enabled: false, private_tmp: false, tmp_size_mb: 32 }
    };

    let ipc_ = policy.namespace.as_ref().and_then(|namespace| namespace.ipc)
        .unwrap_or(false);
    let network_ = policy.namespace.as_ref().and_then(|namespace| namespace.network)
        .unwrap_or(false);
    

    let name_spaces = NamespaceConfig {
        user_namespace_required: uts_config.enabled || ipc_ || network_ || mount_config.enabled || pid_,
        uts: uts_config,
        ipc: ipc_,
        network: network_,
        pid: pid_,
        mount: mount_config
    };

    Ok(SandboxConfig { app_id: policy.app_id.clone(),read_allow, write_allow, exec_allow, resources, network, seccomp, namespace:name_spaces })
}



pub fn apply_landlock_sandbox(config: &SandboxConfig) -> Result<(), String> {
    let abi = ABI::V4;
    
    let access_write = AccessFs::from_write(abi) | AccessFs::ReadFile | AccessFs::ReadDir;
    let access_all = AccessFs::from_all(abi);
    let access_read = AccessFs::from_read(abi);
    let access_exec = AccessFs::Execute | AccessFs::ReadFile;

    let mut ruleset = Ruleset::default()
        .handle_access(access_all)
        .map_err(|err| format!("Failed to handel filesystem access rights: {}",err))?;

    if config.network.enabled {
        
        ruleset = ruleset
            .handle_access(AccessNet::ConnectTcp)
            .map_err(|err| format!("Failed to handel connect tcp access right : {}",err))?;
        ruleset = ruleset
            .handle_access(AccessNet::BindTcp)
            .map_err(|err| format!("Failed to handel bind tcp access right : {}",err))?;
    }
    
    let mut created = ruleset
        .create()
        .map_err(|err| format!("Failed to create Landlock ruleset : {}",err))?;

    created = created
        .add_rules(path_beneath_rules(
            &config.read_allow,
            access_read,
        ))
        .map_err(|err| format!("Failed to add read rules: {}", err))?
        .add_rules(path_beneath_rules(
            &config.write_allow,
            access_write,
        ))
        .map_err(|err| format!("Failed to add write rules: {}", err))?
        .add_rules(path_beneath_rules(
            &config.exec_allow,
            access_exec,
        ))
        .map_err(|err| format!("Failde to ad execute rules : {}",err))?;
    
    if config.network.enabled {

        for port in &config.network.connect_tcp {
            created = created
                .add_rule( NetPort::new(*port, AccessNet::ConnectTcp))
                .map_err(|err| format!("Failed to add connect TCP rule for port {} : {}",port,err))?;
        }

        for port in &config.network.bind_tcp {
            created = created
                .add_rule(NetPort::new(*port, AccessNet::BindTcp))
                .map_err(|err| format!("Failed to ad a bind TCP rule for port {} : {} ",port,err))?;
        }
    }


    let status = created
        .restrict_self()
        .map_err(|err| format!("Failed to enforce LandLock ruleset : {}",err))?;

    match status.ruleset {
        
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => {
            Err("Landlock ruleset was only partially enforced".to_string())
        }
        RulesetStatus::NotEnforced => {
            Err("Landlock ruleset was not enforced".to_string())
        }
    }

}



pub fn apply_resource_limits(config: &RlimitConfig) -> Result<(),String> {
    if config.enabled {
        if let Some( secondds) = config.cpu_seconds && secondds > 0 {
            setrlimit(Resource::CPU, secondds, secondds)
                .map_err(|err| format!("Failed to set CPU : {}",err))?;
        }

        if let Some(bytes) = config.memory_bytes && bytes > 0{
            setrlimit(Resource::AS, bytes, bytes)
                .map_err(|err| format!("Faild to set memory limit : {}",err))?;
        }

        if let Some(bytes) = config.max_file_size_bytes {
            setrlimit(Resource::FSIZE, bytes, bytes)
                .map_err(|err| format!("Failed to set file size limit : {}",err))?;
        }

        if let Some(processes) = config.max_processes {
            setrlimit(Resource::NPROC, processes, processes)
                .map_err(|err| format!("Failed to set process limit : {}",err))?;
        }
    }

    Ok(())
}




