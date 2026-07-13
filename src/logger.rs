use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;


#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    pub timestamp: String,
    pub app_id: String,
    pub event_type: String,
    pub decision: String,
    pub reason: String,
    pub risk_score: f32,
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