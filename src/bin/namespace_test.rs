use std::fs;

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

fn main() {
    show_namespace("user");
    show_namespace("uts");
    show_namespace("ipc");
    show_namespace("net");
}