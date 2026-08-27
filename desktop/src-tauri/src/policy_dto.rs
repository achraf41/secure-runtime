use secure_runtime::policy::{
    CgroupPolicy, FileSystemPolicy, MountPolicy, NamespacePolicy, NetworkPolicy, Policy,
    ResourcePolicy, RlimitPolicy, SeccompPolicy, SeccompProfile, UtsPolicy,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyViewResponse {
    pub policy: PolicyDto,
    pub raw_json: serde_json::Value,
    pub canonical_json: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDto {
    policy_version: u32,
    app_id: String,
    app_path: String,
    app_hash: String,
    default_action: String,
    filesystem: FileSystemPolicyDto,
    resources: Option<ResourcePolicyDto>,
    network: Option<NetworkPolicyDto>,
    seccomp: Option<SeccompPolicyDto>,
    namespace: Option<NamespacePolicyDto>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileSystemPolicyDto {
    read_allow: Vec<String>,
    write_allow: Vec<String>,
    exec_allow: Vec<String>,
    deny: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkPolicyDto {
    connect_tcp: Option<Vec<u16>>,
    bind_tcp: Option<Vec<u16>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeccompPolicyDto {
    profile: Option<String>,
    deny: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NamespacePolicyDto {
    uts: Option<UtsPolicyDto>,
    ipc: Option<bool>,
    network: Option<bool>,
    pid: Option<bool>,
    mount: Option<MountPolicyDto>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UtsPolicyDto {
    enabled: Option<bool>,
    hostname: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MountPolicyDto {
    enabled: Option<bool>,
    private_tmp: Option<bool>,
    tmp_size_mb: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourcePolicyDto {
    timeout_seconds: Option<u64>,
    max_output_kb: Option<u64>,
    memory_mb: Option<u64>,
    max_processes: Option<u64>,
    rlimit: Option<RlimitPolicyDto>,
    cgroup: Option<CgroupPolicyDto>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RlimitPolicyDto {
    enabled: Option<bool>,
    cpu_seconds: Option<u64>,
    max_file_size_mb: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CgroupPolicyDto {
    enabled: Option<bool>,
    cpu_percent: Option<u64>,
}

impl PolicyViewResponse {
    pub fn from_policy(policy: &Policy) -> Result<Self, String> {
        let raw_json = serde_json::to_value(policy)
            .map_err(|error| format!("Failed to serialize validated policy: {error}"))?;
        let canonical_json = serde_json::to_string_pretty(policy)
            .map_err(|error| format!("Failed to serialize validated policy: {error}"))?;
        Ok(Self {
            policy: PolicyDto::from(policy),
            raw_json,
            canonical_json,
        })
    }
}

impl PolicyDto {
    pub fn new() -> Self {
        Self {
            policy_version: secure_runtime::policy::SUPPORTED_POLICY_VERSION,
            app_id: String::new(),
            app_path: String::new(),
            app_hash: String::new(),
            default_action: "deny".to_string(),
            filesystem: FileSystemPolicyDto {
                read_allow: Vec::new(),
                write_allow: Vec::new(),
                exec_allow: Vec::new(),
                deny: Vec::new(),
            },
            resources: None,
            network: None,
            seccomp: None,
            namespace: None,
        }
    }

    pub fn into_policy(self) -> Result<Policy, String> {
        let seccomp = self
            .seccomp
            .map(|value| {
                let profile = value
                    .profile
                    .map(|profile| match profile.as_str() {
                        "none" => Ok(SeccompProfile::None),
                        "baseline" => Ok(SeccompProfile::Baseline),
                        "strict" => Ok(SeccompProfile::Strict),
                        _ => Err(format!("Unsupported seccomp profile: {profile}")),
                    })
                    .transpose()?;
                Ok::<SeccompPolicy, String>(SeccompPolicy {
                    profile,
                    deny: value.deny,
                })
            })
            .transpose()?;

        Ok(Policy {
            policy_version: self.policy_version,
            app_id: self.app_id,
            app_path: self.app_path,
            app_hash: self.app_hash,
            default_action: self.default_action,
            filesystem: FileSystemPolicy {
                read_allow: self.filesystem.read_allow,
                write_allow: self.filesystem.write_allow,
                exec_allow: self.filesystem.exec_allow,
                deny: self.filesystem.deny,
            },
            resources: self.resources.map(|value| ResourcePolicy {
                timeout_seconds: value.timeout_seconds,
                max_output_kb: value.max_output_kb,
                memory_mb: value.memory_mb,
                max_processes: value.max_processes,
                rlimit: value.rlimit.map(|limit| RlimitPolicy {
                    enabled: limit.enabled,
                    cpu_seconds: limit.cpu_seconds,
                    max_file_size_mb: limit.max_file_size_mb,
                }),
                cgroup: value.cgroup.map(|limit| CgroupPolicy {
                    enabled: limit.enabled,
                    cpu_percent: limit.cpu_percent,
                }),
            }),
            network: self.network.map(|value| NetworkPolicy {
                connect_tcp: value.connect_tcp,
                bind_tcp: value.bind_tcp,
            }),
            seccomp,
            namespace: self.namespace.map(|value| NamespacePolicy {
                uts: value.uts.map(|uts| UtsPolicy {
                    enabled: uts.enabled,
                    hostname: uts.hostname,
                }),
                ipc: value.ipc,
                network: value.network,
                pid: value.pid,
                mount: value.mount.map(|mount| MountPolicy {
                    enabled: mount.enabled,
                    private_tmp: mount.private_tmp,
                    tmp_size_mb: mount.tmp_size_mb,
                }),
            }),
        })
    }
}

impl From<&Policy> for PolicyDto {
    fn from(policy: &Policy) -> Self {
        Self {
            policy_version: policy.policy_version,
            app_id: policy.app_id.clone(),
            app_path: policy.app_path.clone(),
            app_hash: policy.app_hash.clone(),
            default_action: policy.default_action.clone(),
            filesystem: FileSystemPolicyDto::from(&policy.filesystem),
            resources: policy.resources.as_ref().map(ResourcePolicyDto::from),
            network: policy.network.as_ref().map(NetworkPolicyDto::from),
            seccomp: policy.seccomp.as_ref().map(SeccompPolicyDto::from),
            namespace: policy.namespace.as_ref().map(NamespacePolicyDto::from),
        }
    }
}

impl From<&FileSystemPolicy> for FileSystemPolicyDto {
    fn from(policy: &FileSystemPolicy) -> Self {
        Self {
            read_allow: policy.read_allow.clone(),
            write_allow: policy.write_allow.clone(),
            exec_allow: policy.exec_allow.clone(),
            deny: policy.deny.clone(),
        }
    }
}

impl From<&NetworkPolicy> for NetworkPolicyDto {
    fn from(policy: &NetworkPolicy) -> Self {
        Self {
            connect_tcp: policy.connect_tcp.clone(),
            bind_tcp: policy.bind_tcp.clone(),
        }
    }
}

impl From<&SeccompPolicy> for SeccompPolicyDto {
    fn from(policy: &SeccompPolicy) -> Self {
        let profile = policy.profile.map(|profile| match profile {
            SeccompProfile::None => "none".to_string(),
            SeccompProfile::Baseline => "baseline".to_string(),
            SeccompProfile::Strict => "strict".to_string(),
        });
        Self {
            profile,
            deny: policy.deny.clone(),
        }
    }
}

impl From<&NamespacePolicy> for NamespacePolicyDto {
    fn from(policy: &NamespacePolicy) -> Self {
        Self {
            uts: policy.uts.as_ref().map(UtsPolicyDto::from),
            ipc: policy.ipc,
            network: policy.network,
            pid: policy.pid,
            mount: policy.mount.as_ref().map(MountPolicyDto::from),
        }
    }
}

impl From<&UtsPolicy> for UtsPolicyDto {
    fn from(policy: &UtsPolicy) -> Self {
        Self {
            enabled: policy.enabled,
            hostname: policy.hostname.clone(),
        }
    }
}

impl From<&MountPolicy> for MountPolicyDto {
    fn from(policy: &MountPolicy) -> Self {
        Self {
            enabled: policy.enabled,
            private_tmp: policy.private_tmp,
            tmp_size_mb: policy.tmp_size_mb,
        }
    }
}

impl From<&ResourcePolicy> for ResourcePolicyDto {
    fn from(policy: &ResourcePolicy) -> Self {
        Self {
            timeout_seconds: policy.timeout_seconds,
            max_output_kb: policy.max_output_kb,
            memory_mb: policy.memory_mb,
            max_processes: policy.max_processes,
            rlimit: policy.rlimit.as_ref().map(RlimitPolicyDto::from),
            cgroup: policy.cgroup.as_ref().map(CgroupPolicyDto::from),
        }
    }
}

impl From<&RlimitPolicy> for RlimitPolicyDto {
    fn from(policy: &RlimitPolicy) -> Self {
        Self {
            enabled: policy.enabled,
            cpu_seconds: policy.cpu_seconds,
            max_file_size_mb: policy.max_file_size_mb,
        }
    }
}

impl From<&CgroupPolicy> for CgroupPolicyDto {
    fn from(policy: &CgroupPolicy) -> Self {
        Self {
            enabled: policy.enabled,
            cpu_percent: policy.cpu_percent,
        }
    }
}
