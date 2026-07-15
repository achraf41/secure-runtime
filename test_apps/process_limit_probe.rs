use std::env;
use std::process::{Command, exit};

fn main() {
    let mut args = env::args();

    let program_path = match args.next() {
        Some(path) => path,
        None => {
            eprintln!("ERROR: could not get program path");
            exit(1);
        }
    };

    if args.any(|arg| arg == "--child") {
        println!("Child process started");
        exit(0);
    }

    println!("Testing process limit");

    match Command::new(&program_path)
        .arg("--child")
        .spawn()
    {
        Ok(mut child) => {
            let status = child.wait();

            eprintln!("ERROR: child process was allowed to start");
            eprintln!("Child status: {:?}", status);

            exit(1);
        }

        Err(err) => {
            println!("OK: child process spawn was blocked: {}", err);
            exit(0);
        }
    }
}
