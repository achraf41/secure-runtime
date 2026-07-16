use std::net::{SocketAddr, TcpStream};
use std::process;
use std::time::Duration;

fn main() {
    println!("Testing network connect limit");

    let addr: SocketAddr = "1.1.1.1:80".parse().unwrap();

    match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
        Ok(_) => {
            eprintln!("ERROR: TCP connection to port 80 was allowed");
            process::exit(1);
        }
        Err(err) => {
            println!("OK: TCP connection was blocked or failed: {}", err);
            process::exit(0);
        }
    }
}
