use std::fs::File;
use std::io::Write;

fn main() -> std::io::Result<()> {
    println!("Testing max file size limit");

    let mut file = File::create("sandbox/output/large_file.bin")?;

    let buffer = vec![0u8; 2 * 1024 * 1024];

    match file.write_all(&buffer) {
        Ok(()) => {
            eprintln!("ERROR: large file write was allowed");
            std::process::exit(1);
        }
        Err(err) => {
            println!("OK: large file write was blocked: {}", err);
            std::process::exit(0);
        }
    }
}
