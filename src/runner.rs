use std::process::Command;


pub fn run_app(app_path: &str) -> Result<std::process::ExitStatus,String> {
    
    match Command::new(app_path).status() {
        
        Ok(status) => {   
            return Ok(status);
        }
        
        Err(err) => {
            return Err(format!("Failed to execute app: {}", err));
        }
    }
}