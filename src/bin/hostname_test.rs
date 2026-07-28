fn main() {
    match nix::unistd::gethostname() {
        Ok(hostname) => {
            println!("Hostname: {}", hostname.to_string_lossy());
        }

        Err(err) => {
            eprintln!("Failed to read hostname: {err}");
            std::process::exit(1);
        }
    }
}