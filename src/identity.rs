use crate::hash::hash_calc;
use crate::policy::Policy;


pub fn check_identity(app_path: &str, policy: &Policy) -> Result<(),String> {
    
    let canonical_app_path = match std::fs::canonicalize(app_path) {
        Ok(path) => path,
        Err(err) => {
            return Err(format!("Failed to canonicalize app path: {} ",err));
            
        }
    };
    let canonical_policy_app_path = match std::fs::canonicalize(policy.app_path.clone()) {
        Ok(path) => path,
        Err(err) => {
            return Err(format!("Failed to canonicalize policy app path: {}",err));
            
        }
    };

    if canonical_app_path != canonical_policy_app_path {
    return Err(format!(
        "Path mismatch: expected {}, got {}",
        canonical_policy_app_path.display(),
        canonical_app_path.display()
    ));
    }    
    
    
    
    
    let actual_hash = match hash_calc(app_path){
        Ok(hash) => hash,
        Err(err) => {
            return Err(format!("Failed to calculate hash for app {}: {}", app_path, err));
            
        }
    };
    
    if actual_hash != policy.app_hash {
        return Err(format!("Hash mismatch for app {}: expected {}, got {}", app_path, policy.app_hash.clone(), actual_hash));
    }

    return Ok(());
    
}