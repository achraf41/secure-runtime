use std::fs;
use nix::unistd::{getpid, getppid};


fn show_namespace(name: &str) {
    let path = format!("/proc/self/ns/{name}");

    match fs::read_link(&path) {
        Ok(namespace_id) => {
            println!(
                "{name} namespace: {}",
                namespace_id.display()
            );
        }

        Err(error) => {
            eprintln!(
                "Failed to inspect {name} namespace: {error}"
            );
        }
    }
}

fn show_tmp_filesystem() {
    match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(content) => {
            for line in content.lines() {
                if line.contains(" /tmp ") {
                    println!("/tmp mount: {line}");
                }
            }
        }

        Err(error) => {
            eprintln!("Cannot read mountinfo: {error}");
        }
    }
}

fn main() {
    show_namespace("user");
    show_namespace("uts");
    show_namespace("ipc");
    show_namespace("net");
    show_namespace("mnt");
    show_tmp_filesystem();
    
    println!("PID: {}", getpid());
    println!("Parent PID: {}", getppid());
}