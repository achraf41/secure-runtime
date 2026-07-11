use std::path::Path;



pub fn check_cli(args: &[String]) -> Result<(String, String),String> {
    if args.len() != 5 {
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
    return Ok((policy_path.clone(), app_path.clone()));
}