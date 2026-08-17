use std::collections::HashMap;
use std::io::SeekFrom::Current;
use std::{
    fs,
    path::PathBuf,
};
use std::process;

use nix::unistd::Pid;
use std::time::{Duration, Instant};
use crate::sandbox::CgroupConfig;


#[derive(Debug, Clone)]
pub struct CgroupStats {
    pub memory_peak_bytes: Option<u64>,

    pub cpu_usage_usec: Option<u64>,
    pub cpu_user_usec: Option<u64>,
    pub cpu_system_usec: Option<u64>,

    pub cpu_nr_throttled: Option<u64>,
    pub cpu_throttled_usec: Option<u64>,

    pub pids_peak: Option<u64>,

    pub oom_count: Option<u64>,
    pub oom_kill_count: Option<u64>,
}

fn read_keyed_u64(path: &PathBuf) -> Result<std::collections::HashMap<String, u64>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read {} : {error} ",path.display()))?;
    let mut values = HashMap::new();

    for line in content.lines() {
        let mut parts = line.split_whitespace();

        let Some(key) = parts.next() else {continue;};
        let Some(value) = parts.next() else {continue;};

        let value = value.parse::<u64>()
            .map_err(|error| format!("Invalid value '{}' in {} : {}",value,path.display(),error))?;

        values.insert(key.to_string(), value);
    }


    Ok(values)
}

fn read_single_u64(path: &PathBuf) -> Result<u64, String> {
    let value = fs::read_to_string(path)
        .map_err(|error| format!("Failed to read {} : {error}",path.display()))?;

    value.trim()
        .parse::<u64>()
        .map_err(|error| format!("Invalid value in {} : {error}",path.display()))

}

pub fn read_cgroup_stats(cgroup: &PathBuf) -> Result<CgroupStats, String> {
    
    let cpu = read_keyed_u64(&cgroup.join("cpu.stat"))?;
    let memory_events = read_keyed_u64(&cgroup.join("memory.events"))?;

    let memory_peak = read_single_u64(&cgroup.join("memory.peak"))?;
    let pids_peak = read_single_u64(&cgroup.join("pids.peak"))?;

    let stats = CgroupStats {
        memory_peak_bytes: Some(memory_peak),

        cpu_usage_usec: cpu.get("usage_usec").copied(),
        cpu_user_usec: cpu.get("user_usec").copied(),
        cpu_system_usec: cpu.get("system_usec").copied(),

        cpu_nr_throttled: cpu.get("nr_throttled").copied(),
        cpu_throttled_usec: cpu.get("throttled_usec").copied(),

        pids_peak: Some(pids_peak),

        oom_count: memory_events.get("oom").copied(),
        oom_kill_count: memory_events.get("oom_kill").copied(),
    };

    Ok(stats)

}


fn current_cgroup_path() -> Result<PathBuf,String> {
    let content = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("Failed to read /proc/self/cgroup : {error}"))?;
    
    match content.strip_prefix("0::") {
        Some(path) => {
            let path = path.trim_start_matches('/');
            let path_buf = PathBuf::from("/sys/fs/cgroup").join(path);
            return Ok(path_buf);

        }
        None =>  Err(format!("Failed to extract cgroup v2 path")), 
    }
}



fn delegated_parent(current: &PathBuf) -> Result<PathBuf,String> {
    current
        .parent()
        .map(|path| path.to_path_buf())
        .ok_or_else(|| "Failed to find delegated cgroup parent".to_string())
}

fn create_sandbox_cgroup(parent: &PathBuf) -> Result<PathBuf, String> {
    let name = format!("sandbox-{}",process::id());
    let sandbox_path = parent.join(name);
    fs::create_dir(&sandbox_path)
        .map_err(|err| format!("Failed to create sandbox cgroup : {err}"))?;
    Ok(sandbox_path)
}

fn write_cgroup_value(cgroup: &PathBuf,file: &str, value: &str) -> Result<(), String> {
    let path = cgroup.join(file);

    fs::write(&path, value)
        .map_err(|error| format!("Failed to write {} to {} : {}",value,path.display(),error))
}

fn apply_memory_limit(path: &PathBuf, config: &CgroupConfig) -> Result<(),String> {
    if let Some(memory) = config.memory_bytes {
        write_cgroup_value(path, "memory.max", &memory.to_string())?;
    }
    Ok(())
}
fn apply_process_limit(path: &PathBuf, config: &CgroupConfig) -> Result<(),String> {
    if let Some(processes) = config.max_processes {
        write_cgroup_value(path, "pids.max", &processes.to_string())?;
    }
    Ok(())
}
fn apply_cpu_limit(path: &PathBuf, config: &CgroupConfig) -> Result<(),String> {
    if let Some(percent) = config.cpu_percent {
        let period: u64 = 100_000;
        
        let quota = period
            .checked_mul(percent)
            .ok_or_else(||"CPU qouta calculation overflow".to_string())? / 100 ;

        let value = format!("{quota} {period}");
        write_cgroup_value(path, "cpu.max", &value)?;
    }
    Ok(())
}
fn apply_cgroup_limits(path: &PathBuf,config: &CgroupConfig) -> Result<(),String> {
    apply_memory_limit(path, config)?;
    apply_process_limit(path, config)?;
    apply_cpu_limit(path, config)?;

    Ok(())
}
pub fn move_process_to_cgroup(cgroup: &PathBuf, pid: Pid) ->Result<(),String> {
    write_cgroup_value(cgroup, "cgroup.procs", &pid.as_raw().to_string())
}

pub fn prepare_cgroup(config: &CgroupConfig) -> Result<Option<PathBuf>, String> {
    if !config.enabled {
        return Ok(None);
    }
    
    let current = current_cgroup_path()?;
    let parent = delegated_parent(&current)?;
    let sandbox = create_sandbox_cgroup(&parent)?;

    apply_cgroup_limits(&sandbox, config)?;

    Ok(Some(sandbox))
}

fn is_cgroup_populated(cgroup: &PathBuf) ->Result<bool, String> {
    let events_path = cgroup.join("cgroup.events");

    let content = fs::read_to_string(&events_path)
        .map_err(|error| format!("Failed to read {} : {error}",events_path.display()))?;

    for line in content.lines() {
        let mut parts = line.split_whitespace();

        if parts.next() == Some("populated") {
            return match parts.next() {
                Some("1") => Ok(true),
                Some("0") => Ok(false),
                Some(value) => Err(format!("Invalid populated value : {value}")),
                None => Err("Missing populated value in cgroup.events".to_string()),
            };

        }
    }

    Err("populated field not found in cgroup.events".to_string())

}

fn kill_cgroup(cgroup: &PathBuf) -> Result<(), String> {
    let kill_file = cgroup.join("cgroup.kill");

    fs::write(&kill_file, "1")
        .map_err(|error| format!("Failed to kill cgroup {} : {error}",kill_file.display()))
}

fn wait_until_cgroup_empty(cgroup: &PathBuf) -> Result<(),String> {
    
    let deadline = Instant::now() + Duration::from_secs(3);

    loop {
        if !is_cgroup_populated(cgroup)? {
            return Ok(());
        }

        if Instant::now() >= deadline {
            return Err("Timed out waiting for cgroup to becom empty".to_string());
        }

        std::thread::sleep(Duration::from_millis(50));
    } 
}

pub fn cleanup_cgroup(cgroup: &PathBuf) -> Result<(), String> {
    if !cgroup.exists() {
        return Ok(());
    }

    if is_cgroup_populated(cgroup)? {
        kill_cgroup(cgroup)?;
        wait_until_cgroup_empty(cgroup)?;
    }

    fs::remove_dir(cgroup)
        .map_err(|error| format!("Failed to remove cgroup {} : {error}",cgroup.display()))?;

    Ok(())
}