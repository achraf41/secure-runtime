use std::fs::File;
use std::io::Read;
use sha2::{Sha256, Digest};


pub fn hash_calc(app_path: &str) -> Result<String, String> {
    let mut file = match File::open(app_path) {
        Ok(file) => file,
        Err(err) => {
            return Err(format!("Failed to open app file for hashing: {}", err));
        }
    };

    
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];

    loop {
        let bytes_read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) => {
                return Err(format!("Failed to open app file for hashing: {}", err));
            }
        };
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    let actual_hash = format!("{:x}", hash);
    return Ok(actual_hash);
}