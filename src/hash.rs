use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use sha2::{Sha256, Digest};


pub fn hash_calc(file: &mut File) -> Result<String, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("Failed to seek executable : {error}"))?;

    
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

    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("Failed to reset executable position : {error}"))?;
    return Ok(actual_hash);
}