use std::net::TcpListener;
use std::process;

fn main() {
    println!("Testing TCP bind limit");

    match TcpListener::bind("127.0.0.1:8080") {
        Ok(_listener) => {
            eprintln!("ERROR: TCP bind to 127.0.0.1:8080 was allowed");
            process::exit(1);
        }

        Err(err) => {
            println!("OK: TCP bind was blocked: {}", err);
            process::exit(0);
        }
    }
}
