use std::path::{Path, PathBuf};
use crate::policy::{Policy, FileSystemPolicy};

#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
}

fn default_decision(policy: &Policy) -> Result<Decision, String> {
    match policy.default_action.as_str() {
        "allow" => Ok(Decision::Allow),
        "deny" => Ok(Decision::Deny),
        other => Err(format!("Invalid default action: {}", other)),
    }
}

fn canonicalize_target_for_action(action: &str, target_path: &str) -> Result<PathBuf, String> {
    let target = Path::new(target_path);

    match action {
        "read" => {
            std::fs::canonicalize(target)
                .map_err(|err| format!("Target path can't be canonicalized for read: {}", err))
        }

        "write" => {
            if target.exists() {
                std::fs::canonicalize(target)
                    .map_err(|err| format!("Target path can't be canonicalized for write: {}", err))
            } else {
                let parent = target.parent()
                    .ok_or_else(|| format!("Target path has no parent directory: {}", target_path))?;

                std::fs::canonicalize(parent)
                    .map_err(|err| format!("Parent path can't be canonicalized for write: {}", err))
            }
        }

        other => Err(format!("Unsupported file action: {}", other)),
    }
}

fn path_is_inside_any(candidate: &Path, policy_paths: &[String]) -> Result<bool, String> {
    for policy_path in policy_paths {
        let canonical_policy_path = std::fs::canonicalize(policy_path)
            .map_err(|err| format!("Policy path can't be canonicalized: {} ({})", policy_path, err))?;

        if candidate.starts_with(&canonical_policy_path) {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn decide_file_access(
    action: &str,
    target_path: &str,
    policy: &Policy,
) -> Result<Decision, String> {
    let canonical_target = canonicalize_target_for_action(action, target_path)?;

    if path_is_inside_any(&canonical_target, &policy.filesystem.deny)? {
        return Ok(Decision::Deny);
    }

    match action {
        "read" => {
            if path_is_inside_any(&canonical_target, &policy.filesystem.read_allow)? {
                return Ok(Decision::Allow);
            }
        }

        "write" => {
            if path_is_inside_any(&canonical_target, &policy.filesystem.write_allow)? {
                return Ok(Decision::Allow);
            }
        }

        _ => return Ok(Decision::Deny),
    }

    default_decision(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_allowed_file_returns_allow() {
    
        std::fs::create_dir_all("sandbox/input").unwrap();
        std::fs::create_dir_all("sandbox/output").unwrap();
        std::fs::write("sandbox/input/data.txt", "hello").unwrap();     
        
        let policy = Policy {
            app_id: "test_app".to_string(),
            app_path: "sandbox/test_app".to_string(),
            app_hash: "dummy_hash".to_string(),
            default_action: "deny".to_string(),
            filesystem: FileSystemPolicy {
                read_allow: vec!["sandbox/input".to_string()],
                write_allow: vec!["sandbox/output".to_string()],
                deny: vec![],
            },
        };

        let decision = decide_file_access("read", "sandbox/input/data.txt", &policy).unwrap();
        assert_eq!(decision, Decision::Allow);
    
    
    }
    #[test]
    fn read_denied_file_returns_deny() {

        std::fs::create_dir_all("sandbox/denied").unwrap();
        std::fs::write("sandbox/denied/secret.txt", "secret").unwrap();
        let policy = Policy {
            app_id: "test_app".to_string(),
            app_path: "sandbox/test_app".to_string(),
            app_hash: "dummy_hash".to_string(),
            default_action: "deny".to_string(),
            filesystem: FileSystemPolicy {
                read_allow: vec!["sandbox/input".to_string()],
                write_allow: vec!["sandbox/output".to_string()],
                deny: vec![],
            },
        };
        
        let decision = decide_file_access("read", "sandbox/denied/secret.txt", &policy).unwrap();
        assert_eq!(decision, Decision::Deny);
    }
    #[test]
    fn write_allowed_file_returns_allow() {
        std::fs::create_dir_all("sandbox/output").unwrap();
        let policy = Policy {
            app_id: "test_app".to_string(),
            app_path: "sandbox/test_app".to_string(),
            app_hash: "dummy_hash".to_string(),
            default_action: "deny".to_string(),
            filesystem: FileSystemPolicy {
                read_allow: vec!["sandbox/input".to_string()],
                write_allow: vec!["sandbox/output".to_string()],
                deny: vec![],
            },
        };

        let decision = decide_file_access("write", "sandbox/output/result.txt", &policy).unwrap();
        assert_eq!(decision, Decision::Allow);
    }
    #[test]
    fn write_denied_file_returns_deny() {
        std::fs::create_dir_all("sandbox/denied").unwrap();
        let policy = Policy {
            app_id: "test_app".to_string(),
            app_path: "sandbox/test_app".to_string(),
            app_hash: "dummy_hash".to_string(),
            default_action: "deny".to_string(),
            filesystem: FileSystemPolicy {
                read_allow: vec!["sandbox/input".to_string()],
                write_allow: vec!["sandbox/output".to_string()],
                deny: vec![],
            },
        };
        let decision = decide_file_access("write", "sandbox/denied/result.txt", &policy).unwrap();
        assert_eq!(decision, Decision::Deny);
    }
    
}