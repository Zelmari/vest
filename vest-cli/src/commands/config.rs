use crate::ConfigArgs;
use std::path::PathBuf;

pub async fn run(args: ConfigArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args {
        ConfigArgs::Init => {
            let path = PathBuf::from("vest.toml");
            if path.exists() {
                println!("vest.toml already exists. Use --force to overwrite.");
                return Ok(());
            }
            let default_config = vest_config::default_config();
            let toml_str = toml::to_string_pretty(&default_config)?;
            std::fs::write(&path, toml_str)?;
            println!("Created vest.toml with default configuration");
        }
        ConfigArgs::Show => {
            let config_path = find_config_path();
            match vest_config::load_config(&config_path) {
                Ok(config) => {
                    let toml_str = toml::to_string_pretty(&config)?;
                    println!("Config loaded from: {}", config_path.display());
                    println!("{}", toml_str);
                }
                Err(e) => {
                    println!("Could not load config: {}", e);
                    println!("Showing defaults:");
                    let default = vest_config::default_config();
                    let toml_str = toml::to_string_pretty(&default)?;
                    println!("{}", toml_str);
                }
            }
        }
        ConfigArgs::Validate => {
            let config_path = find_config_path();
            match vest_config::load_config(&config_path) {
                Ok(config) => {
                    println!("Configuration is valid");
                    println!(
                        "  Provider: {}",
                        config
                            .providers
                            .as_ref()
                            .map(|p| &p.default.provider[..])
                            .unwrap_or("not configured")
                    );
                    println!("  Agent pattern: {}", config.agent.default_pattern);
                    println!("  Scanners enabled: memory={}, binary={}, web={}, browser={}, network={}, files={}",
                        config.scanner.memory.enabled,
                        config.scanner.binary.enabled,
                        config.scanner.web.enabled,
                        config.scanner.browser.enabled,
                        config.scanner.network.enabled,
                        config.scanner.files.enabled,
                    );
                }
                Err(e) => {
                    println!("Configuration error: {}", e);
                }
            }
        }
        ConfigArgs::Path => {
            let path = find_config_path();
            if path.exists() {
                println!("{}", path.display());
            } else {
                println!(
                    "No config file found at {}. Run 'vest config init' to create one.",
                    path.display()
                );
            }
        }
        ConfigArgs::Set { key, value } => {
            println!("Setting config key '{}' to '{}'", key, value);
            println!(
                "Note: Direct config modification not yet implemented. Edit vest.toml manually."
            );
        }
    }
    Ok(())
}

fn find_config_path() -> PathBuf {
    let local = PathBuf::from("vest.toml");
    if local.exists() {
        return local;
    }
    let home = dirs_home().unwrap_or_else(|| PathBuf::from("."));
    home.join(".vest").join("vest.toml")
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
}
