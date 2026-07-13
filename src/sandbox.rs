use std::path::PathBuf;

use crate::policy::Policy;

use landlock::{
    path_beneath_rules,
    Access,
    AccessFs,
    ABI,
    Ruleset,
    RulesetAttr,
    RulesetCreatedAttr,
    RulesetStatus,
};
#[derive(Debug, Clone)]

pub struct SandboxConfig {
    pub read_allow: Vec<PathBuf>,
    pub write_allow: Vec<PathBuf>,
    pub exec_allow: Vec<PathBuf>,
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
    let exec_allow = canonicalize_path_list("execute_allow", &policy.filesystem.exec_allow)?;

    
    Ok(SandboxConfig { read_allow, write_allow, exec_allow })
}



pub fn apply_filesystem_sandbox(config: &SandboxConfig) -> Result<(), String> {
    let abi = ABI::V1;
    
    let access_write = AccessFs::from_write(abi) | AccessFs::ReadFile | AccessFs::ReadDir;
    let access_all = AccessFs::from_all(abi);
    let access_read = AccessFs::from_read(abi);
    let access_exec = AccessFs::Execute | AccessFs::ReadFile;

    let status = Ruleset::default()
        .handle_access(access_all)
        .map_err(|err| format!("Failed to handle filesystem access rights: {}", err))?
        .create()
        .map_err(|err| format!("Failed to create Landlock ruleset: {}", err))?
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
        .map_err(|err| format!("Failde to ad execute rules : {}",err))?
        .restrict_self()
        .map_err(|err| format!("Failed to enforce Landlock ruleset: {}", err))?;

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