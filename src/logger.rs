use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use crate::cgroup::CgroupStats;

#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub app_id: String,
    pub event_type: String,
    pub decision: String,
    pub reason: String,
    pub risk_score: f32,
}

#[derive(Debug, Serialize)]
pub struct ResourceUsageEvent {
    pub timestamp: String,
    pub app_id: String,
    pub event_type: String,

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

fn append_json_event<T: Serialize>(event: &T) -> Result<(), String> {
    let json = serde_json::to_string(event)
        .map_err(|error| format!("Failed to serialize event : {error}"))?;

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("logs/events.jsonl")
        .map_err(|error| format!("Failed to open event log : {error}"))?;

    writeln!(file, "{json}")
        .map_err(|error| format!("Failed to write event log : {error}"))?;

    Ok(())
}


pub fn log_security_event(app_id: &str, event_type: &str,decision: &str, reason: &str, risk_score: f32) {
    let event = SecurityEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        app_id: app_id.to_string(),
        event_type: event_type.to_string(),
        decision: decision.to_string(),
        reason: reason.to_string(),
        risk_score,
    };
        let event_json = match serde_json::to_string(&event) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("Failed to serialize security event: {}", error);
            std::process::exit(1);
        }
    };
    let mut log_file = match OpenOptions::new().append(true).create(true).open("logs/events.jsonl") {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Failed to open log file: {}", error);
            std::process::exit(1);
        }
    };
    match writeln!(log_file, "{}", event_json) {
        Ok(_) => (),
        Err(error) => {
            eprintln!("Failed to write to log file: {}", error);
            std::process::exit(1);
        }
    }
}

pub fn log_resource_usage(app_id: &str,stats: &CgroupStats) -> Result<(), String> {
    let event = ResourceUsageEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        app_id: app_id.to_string(),
        event_type: "resource_usage".to_string(),

        memory_peak_bytes: stats.memory_peak_bytes,

        cpu_usage_usec: stats.cpu_usage_usec,
        cpu_user_usec: stats.cpu_user_usec,
        cpu_system_usec: stats.cpu_system_usec,

        cpu_nr_throttled: stats.cpu_nr_throttled,
        cpu_throttled_usec: stats.cpu_throttled_usec,

        pids_peak: stats.pids_peak,

        oom_count: stats.oom_count,
        oom_kill_count: stats.oom_kill_count,
    };

    append_json_event(&event)
}