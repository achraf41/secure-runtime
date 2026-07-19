use std::path::PathBuf;
use rlimit::{setrlimit, Resource};

use crate::policy::Policy;

use landlock::{
    ABI, Access, AccessFs, AccessNet, NetPort, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
};


#[derive(Debug, Clone)]
pub struct ResourceConfig {
    pub cpu_seconds: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub max_file_size_bytes: Option<u64>,
    pub max_processes: Option<u64>,
}


#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub connect_tcp: Vec<u16>,
    pub bind_tcp: Vec<u16>,
}


#[derive(Debug, Clone)]

pub struct SandboxConfig {
    pub read_allow: Vec<PathBuf>,
    pub write_allow: Vec<PathBuf>,
    pub exec_allow: Vec<PathBuf>,
    pub resources: ResourceConfig,
    pub network: NetworkConfig,
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
        Some(resource_policy) => ResourceConfig {
            cpu_seconds: resource_policy.cpu_seconds,
            memory_bytes: match resource_policy.memory_mb {
                Some( mem_by ) => {
                    match mem_by.checked_mul(1024) {
                        Some(mem) => {
                            match mem.checked_mul(1024) {
                                Some(mem_f) => Some(mem_f),
                                None => return Err("Overflow in memory byte".to_string())
                            }
                        }
                        None => return Err("Overflow in memory byte".to_string())
                    }
                },
                None => None
            },
            max_file_size_bytes: match resource_policy.max_file_size_mb {
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
            max_processes: resource_policy.max_processes,
        },
        None => ResourceConfig {
            cpu_seconds: None,
            memory_bytes: None,
            max_file_size_bytes: None,
            max_processes: None,
        },
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


    Ok(SandboxConfig { read_allow, write_allow, exec_allow,resources,network })
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



pub fn apply_resource_limits(config: &ResourceConfig) -> Result<(),String> {
    
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


    Ok(())
}


