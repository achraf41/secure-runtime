use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct FileSystemPolicy {
    pub read_allow: Vec<String>,
    pub write_allow: Vec<String>,
    pub exec_allow: Vec<String>,
    pub deny: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Policy {
    pub app_id: String,
    pub app_path: String,
    pub app_hash: String,
    pub default_action: String,
    pub filesystem: FileSystemPolicy,
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
    
    if !policy.default_action.eq("allow") && !policy.default_action.eq("deny") {
        return Err(format!("Invalid default action in policy: {}", policy.default_action));    }
    

    if policy.filesystem.read_allow.is_empty() && policy.filesystem.write_allow.is_empty() && policy.filesystem.deny.is_empty() && policy.filesystem.exec_allow.is_empty() {
        return Err("File system policy is empty".to_string());
    }

    
    return Ok(policy);
}