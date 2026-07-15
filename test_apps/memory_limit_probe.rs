use std::process;

fn main() {
    println!("Testing memory limit");

    let target_size: usize = 256 * 1024 * 1024; // 256 MB
    let chunk_size: usize = 1024 * 1024;        // 1 MB

    let mut data: Vec<u8> = Vec::new();

    match data.try_reserve_exact(target_size) {
        Ok(()) => {
            println!("Memory reservation succeeded, now touching memory...");
        }
        Err(err) => {
            println!("OK: memory allocation was blocked: {}", err);
            process::exit(0);
        }
    }

    let chunk = vec![1u8; chunk_size];

    while data.len() < target_size {
        data.extend_from_slice(&chunk);

        if data.len() % (64 * 1024 * 1024) == 0 {
            println!("Allocated and touched {} MB", data.len() / 1024 / 1024);
        }
    }

    eprintln!("ERROR: 256 MB allocation succeeded, memory limit did not block it");
    process::exit(1);
}
