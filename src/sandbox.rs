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

pub struct SandboxConfig {
    pub read_allow: Vec<String>,
    pub write_allow: Vec<String>,
    pub exec_allow: Vec<String>,
}




pub fn prepare_sandbox(policy: &Policy) -> Result<SandboxConfig,String> {
    valid_path_list("read_allow",&policy.filesystem.read_allow)?;
    valid_path_list("write_allow", &policy.filesystem.write_allow)?;
    valid_path_list("exec_allow",&policy.filesystem.exec_allow)?;
    valid_path_list("deny",&policy.filesystem.deny)?;
    
    let sandbox_config = SandboxConfig {
        read_allow: policy.filesystem.read_allow.clone(),
        write_allow: policy.filesystem.write_allow.clone(),
        exec_allow: policy.filesystem.exec_allow.clone(),
    };

    Ok(sandbox_config)
}

fn valid_path_list(label: &str, paths: &[String]) -> Result<(),String>{
    for path in paths {
        std::fs::canonicalize(path).map_err(|err| format!("Invalid {} path '{}' : {}",label,path,err))?;
    }

    return Ok(());


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