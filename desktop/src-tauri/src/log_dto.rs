use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use secure_runtime::logger::{ResourceUsageEvent, SecurityEvent};
use serde::{Deserialize, Serialize};

pub const MAX_LOG_ENTRIES: usize = 1000;

#[derive(Deserialize)]
#[serde(untagged)]
enum StoredLogEvent {
    Security(SecurityEvent),
    ResourceUsage(ResourceUsageEvent),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntryDto {
    timestamp: String,
    app_id: String,
    event_type: String,
    decision: Option<String>,
    reason: Option<String>,
    risk_score: Option<f32>,
    memory_peak_bytes: Option<u64>,
    cpu_usage_usec: Option<u64>,
    cpu_user_usec: Option<u64>,
    cpu_system_usec: Option<u64>,
    cpu_nr_throttled: Option<u64>,
    cpu_throttled_usec: Option<u64>,
    pids_peak: Option<u64>,
    oom_count: Option<u64>,
    oom_kill_count: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityLogsResponse {
    entries: Vec<LogEntryDto>,
    malformed_lines: usize,
    valid_entries_seen: usize,
    max_entries: usize,
    limited: bool,
    source_path: String,
}

impl From<StoredLogEvent> for LogEntryDto {
    fn from(event: StoredLogEvent) -> Self {
        match event {
            StoredLogEvent::Security(event) => Self {
                timestamp: event.timestamp,
                app_id: event.app_id,
                event_type: event.event_type,
                decision: Some(event.decision),
                reason: Some(event.reason),
                risk_score: Some(event.risk_score),
                memory_peak_bytes: None,
                cpu_usage_usec: None,
                cpu_user_usec: None,
                cpu_system_usec: None,
                cpu_nr_throttled: None,
                cpu_throttled_usec: None,
                pids_peak: None,
                oom_count: None,
                oom_kill_count: None,
            },
            StoredLogEvent::ResourceUsage(event) => Self {
                timestamp: event.timestamp,
                app_id: event.app_id,
                event_type: event.event_type,
                decision: None,
                reason: None,
                risk_score: None,
                memory_peak_bytes: event.memory_peak_bytes,
                cpu_usage_usec: event.cpu_usage_usec,
                cpu_user_usec: event.cpu_user_usec,
                cpu_system_usec: event.cpu_system_usec,
                cpu_nr_throttled: event.cpu_nr_throttled,
                cpu_throttled_usec: event.cpu_throttled_usec,
                pids_peak: event.pids_peak,
                oom_count: event.oom_count,
                oom_kill_count: event.oom_kill_count,
            },
        }
    }
}

pub fn load_security_logs(path: &Path) -> Result<SecurityLogsResponse, String> {
    if !path.exists() {
        return Ok(SecurityLogsResponse {
            entries: Vec::new(),
            malformed_lines: 0,
            valid_entries_seen: 0,
            max_entries: MAX_LOG_ENTRIES,
            limited: false,
            source_path: path.display().to_string(),
        });
    }

    let file =
        File::open(path).map_err(|error| format!("Failed to open desktop log file: {error}"))?;
    let mut entries = VecDeque::with_capacity(MAX_LOG_ENTRIES);
    let mut malformed_lines = 0;
    let mut valid_entries_seen = 0;

    for line in BufReader::new(file).lines() {
        let line = match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => line,
            Err(_) => {
                malformed_lines += 1;
                continue;
            }
        };
        match serde_json::from_str::<StoredLogEvent>(&line) {
            Ok(event) => {
                valid_entries_seen += 1;
                if entries.len() == MAX_LOG_ENTRIES {
                    entries.pop_front();
                }
                entries.push_back(LogEntryDto::from(event));
            }
            Err(_) => malformed_lines += 1,
        }
    }

    Ok(SecurityLogsResponse {
        entries: entries.into_iter().collect(),
        malformed_lines,
        valid_entries_seen,
        max_entries: MAX_LOG_ENTRIES,
        limited: valid_entries_seen > MAX_LOG_ENTRIES,
        source_path: path.display().to_string(),
    })
}
