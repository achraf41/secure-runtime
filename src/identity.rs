use std::fs::File;
use std::path::PathBuf;

use crate::hash::hash_calc;
use crate::policy::Policy;

pub struct VerifiedExecutable {
    pub file: File,
    pub path: PathBuf
}


pub fn check_identity(app_path: &str, policy: &Policy) -> Result<VerifiedExecutable,String> {
    


    let mut executable: VerifiedExecutable = VerifiedExecutable { 
        file: match File::open(app_path) {
            Ok(file) => file,
            Err(err) => {return Err(format!("Failed to open the executeble : {err}"))}
        }, 
        path: match std::fs::canonicalize(app_path) {
                Ok(path) => path,
                Err(err) => {
                    return Err(format!("Failed to canonicalize app path: {} ",err));
            }
        }
    };

    let canonical_policy_app_path = match std::fs::canonicalize(policy.app_path.clone()) {
        Ok(path) => path,
        Err(err) => {
            return Err(format!("Failed to canonicalize policy app path: {}",err));
            
        }
    };

    if executable.path != canonical_policy_app_path {
    return Err(format!(
        "Path mismatch: expected {}, got {}",
        canonical_policy_app_path.display(),
        executable.path.display()
    ));
    }    
    
    
    
    let actual_hash = match hash_calc( &mut executable.file){
        Ok(hash) => hash,
        Err(err) => {
            return Err(format!("Failed to calculate hash for app {}: {}", app_path, err));
            
        }
    };
    
    if actual_hash != policy.app_hash {
        return Err(format!("Hash mismatch for app {}: expected {}, got {}", app_path, policy.app_hash.clone(), actual_hash));
    }

    return Ok(executable);
    
}
