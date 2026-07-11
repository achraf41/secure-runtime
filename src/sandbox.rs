use crate::policy::Policy;
use crate::policy::FileSystemPolicy
use std::path::Path;
use std::fs::exists;

pub fn prepare_sandbox(policy: &Policy) -> Result<(),String> {

    for paths in &policy.filesystem.read_allow {

        if !Path::new(paths).exists() {
            return Err(format!("A path dos not exists in filesystem !"));
        };
    }

    for paths in &policy.filesystem.write_allow {

        if !Path::new(paths).exists() {
            return Err(format!("A path dos not exists in filesystem !"));
        };
    }

    for paths in &policy.filesystem.deny {

        if !Path::new(paths).exists() {
            return Err(format!("A path dos not exists in filesystem !"));
        };
    }        

    return Ok(());
}