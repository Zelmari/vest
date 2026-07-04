use crate::ProvidersArgs;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub async fn run(args: ProvidersArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args {
        ProvidersArgs::List => {
            let config_path = find_vest_toml();
            let config = match vest_config::load_config(&config_path) {
                Ok(c) => c,
                Err(_) => {
                    println!("No config found. Using defaults.");
                    println!("  Default provider: none configured");
                    return Ok(());
                }
            };

            let credentials = load_credentials();
            println!(
                "Credentials: {}",
                if credentials.is_empty() {
                    "none stored"
                } else {
                    "~/.vest/credentials.toml"
                }
            );
            println!();
            println!(
                "{:<15} {:<20} {:<12} {:<25}",
                "Provider", "Model", "Key Set", "API Base"
            );
            println!("{}", "-".repeat(80));

            if let Some(providers) = &config.providers {
                let provider_list = [
                    ("openai", &providers.openai),
                    ("anthropic", &providers.anthropic),
                    ("deepseek", &providers.deepseek),
                    ("google", &providers.google),
                    ("ollama", &providers.ollama),
                    ("groq", &providers.groq),
                    ("openrouter", &providers.openrouter),
                ];

                for (name, config) in &provider_list {
                    let model = config
                        .as_ref()
                        .and_then(|c| c.default_model.as_deref())
                        .unwrap_or("-");
                    let base = config
                        .as_ref()
                        .and_then(|c| c.api_base.as_deref())
                        .unwrap_or("default");
                    let key_status = if get_api_key(name).is_some() || *name == "ollama" {
                        "\u{2705} set"
                    } else {
                        "\u{274c} missing"
                    };
                    println!("{:<15} {:<20} {:<12} {:<25}", name, model, key_status, base);
                }

                if let Some(fallback) = &providers.fallback {
                    println!(
                        "\nFallback chain: {:?} (strategy: {})",
                        fallback.chain, fallback.strategy
                    );
                }
            }
        }
        ProvidersArgs::SetKey { provider, key } => {
            let valid_providers = [
                "openai",
                "deepseek",
                "anthropic",
                "google",
                "groq",
                "openrouter",
            ];
            if !valid_providers.contains(&provider.as_str()) {
                println!(
                    "Unknown provider '{}'. Valid options: {}",
                    provider,
                    valid_providers.join(", ")
                );
                return Ok(());
            }

            let api_key = match key {
                Some(k) => k,
                None => {
                    print!("Enter API key for {}: ", provider);
                    let mut input = String::new();
                    std::io::Write::flush(&mut std::io::stdout())?;
                    std::io::stdin().read_line(&mut input)?;
                    input.trim().to_string()
                }
            };

            if api_key.is_empty() {
                println!("No key provided. Cancelled.");
                return Ok(());
            }

            save_credential(&provider, &api_key)?;
            println!(
                "API key for '{}' saved to {}",
                provider,
                credentials_path().display()
            );
        }
        ProvidersArgs::Test => {
            println!("Testing provider connectivity...");
            println!("  This requires API keys to be configured.");
            println!("  Use 'vest providers set-key <provider>' to store keys.");
        }
        ProvidersArgs::Models { provider } => {
            println!("Available models for {}:", provider);
            println!("  (Model listing requires active API connection)");
        }
        ProvidersArgs::Pull { model } => {
            println!("Pulling model '{}' via Ollama...", model);
            println!("  Make sure Ollama is running (ollama serve)");
            println!("  Then run: ollama pull {}", model);
        }
        ProvidersArgs::Status => {
            println!("Provider status check:");
            println!("  (Status check requires active API connections)");
        }
    }
    Ok(())
}

fn find_vest_toml() -> PathBuf {
    let local = PathBuf::from("vest.toml");
    if local.exists() {
        return local;
    }
    let home = std::env::var("HOME").ok().unwrap_or_else(|| ".".into());
    PathBuf::from(home).join(".vest").join("vest.toml")
}

fn credentials_path() -> PathBuf {
    if let Ok(home) = std::env::var("VEST_HOME") {
        return PathBuf::from(home).join("credentials.toml");
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".vest").join("credentials.toml")
}

fn legacy_credentials_path() -> PathBuf {
    PathBuf::from("credentials.toml")
}

fn load_credentials() -> HashMap<String, String> {
    let mut merged = HashMap::new();
    for path in [legacy_credentials_path(), credentials_path()] {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            if let Ok(creds) = toml::from_str::<HashMap<String, String>>(&contents) {
                merged.extend(creds);
            }
        }
    }
    merged
}

fn save_credential(provider: &str, key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut creds = load_credentials();
    creds.insert(provider.to_string(), key.to_string());
    let contents = toml::to_string(&creds)?;
    let path = credentials_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, contents)?;
    restrict_file_permissions(&path)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

pub fn get_api_key(provider: &str) -> Option<String> {
    // Try env var first
    let env_var = format!("{}_API_KEY", provider.to_uppercase());
    if let Ok(key) = std::env::var(&env_var) {
        if !key.is_empty() {
            return Some(key);
        }
    }
    // Fall back to credentials file
    load_credentials().get(provider).cloned()
}
