use std::path::Path;

pub struct CliArgs{
    pub policy_path: String,
    pub app_path: String,
    pub app_arg: Vec<String>,
}


pub fn check_cli(args: &[String]) -> Result<CliArgs,String> {
    
    if args.len() < 5 {
        return Err(format!("Usage: secure-run --policy <policy_path>  --app <app_path>"));
    }
    
    if args[1] != "--policy" {
        return Err(format!("Invalid argument. Use --policy <policy_path>"));
    }
    
    if args[3] != "--app" {
        return Err(format!("Invalid argument. Use --app <app_path>"));
    }
    
    let policy_path = &args[2];
    let app_path = &args[4];
    
    if !Path::new(policy_path).is_file() {
        return Err(format!("Policy path is not a valid file: {}", policy_path));
    }
    
    if !Path::new(app_path).is_file() {
        return Err(format!("App path is not a valid file: {}", app_path));
    }
    
    let app_args = if args.len() == 5 {
        Vec::new()
    } else {
        if args[5] != "--" {
            return Err("Application argument must be placed after '--' ".to_string());
        }

        args[6..].to_vec()

    };
    
    return Ok(CliArgs { policy_path: policy_path.clone(), app_path: app_path.clone(), app_arg: app_args });

}
