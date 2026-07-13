use std::fs;

fn main() {
    println!("Hello from compiled sandboxed app");

    println!("Allowed read:");
    match fs::read_to_string("sandbox/input/data.txt") {
        Ok(content) => println!("{}", content),
        Err(err) => {
            eprintln!("ERROR: allowed read failed: {}", err);
            std::process::exit(1);
        }
    }

    println!("Forbidden read test:");
    match fs::read_to_string("/etc/passwd") {
        Ok(_) => {
            eprintln!("ERROR: forbidden read was allowed");
            std::process::exit(1);
        }
        Err(_) => println!("OK: forbidden read was blocked"),
    }

    println!("Allowed write:");
    match fs::write("sandbox/output/result.txt", "result\n") {
        Ok(_) => println!("OK: allowed write worked"),
        Err(err) => {
            eprintln!("ERROR: allowed write failed: {}", err);
            std::process::exit(1);
        }
    }

    println!("Forbidden write test:");
    match fs::write("sandbox/input/bad.txt", "bad\n") {
        Ok(_) => {
            eprintln!("ERROR: forbidden write was allowed");
            std::process::exit(1);
        }
        Err(_) => println!("OK: forbidden write was blocked"),
    }

    std::process::exit(0);
}
