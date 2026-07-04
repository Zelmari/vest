use crate::ProvidersArgs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vest_core::error::VestError;
use vest_core::traits::LlmProvider;

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

            println!("Keys are read from environment variables ({{PROVIDER}}_API_KEY).");
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
            let env_var = format!("{}_API_KEY", provider.to_uppercase());
            match key {
                Some(k) => {
                    println!("To set the key persistently, add this to your shell profile:");
                    println!();
                    println!("  export {}={}", env_var, k);
                    println!();
                    println!("Or set it for the current session only:");
                    println!();
                    println!("  export {}={}", env_var, k);
                    println!();
                    println!("Then run your scan as normal. VEST reads keys from environment variables only.");
                }
                None => {
                    println!("Set your API key via the {} environment variable:", env_var);
                    println!();
                    println!("  export {}={{your-key-here}}", env_var);
                    println!();
                    println!("Add the export to your shell profile (~/.zshrc, ~/.bashrc) to make it permanent.");
                    println!("Keys are never stored on disk by VEST.");
                }
            }
        }
        ProvidersArgs::Test { provider } => {
            let config_path = find_vest_toml();
            let config = vest_config::load_config(&config_path)
                .unwrap_or_else(|_| vest_config::default_config());
            let providers = providers_to_check(&config, provider.as_deref());

            if providers.is_empty() {
                println!("No providers configured.");
                return Ok(());
            }

            println!("Testing provider connectivity...");
            println!("Config: {}", config_path.display());
            println!();
            println!("{:<15} {:<28} {:<10} Result", "Provider", "Model", "Key");
            println!("{}", "-".repeat(86));

            let mut failures = 0usize;
            for provider in providers {
                match test_provider(&config, &provider).await {
                    ProviderTestResult::Ok {
                        model,
                        key_status,
                        latency_ms,
                        response_preview,
                    } => {
                        println!(
                            "{:<15} {:<28} {:<10} ok ({} ms) {}",
                            provider, model, key_status, latency_ms, response_preview
                        );
                    }
                    ProviderTestResult::Skipped { model, reason } => {
                        println!(
                            "{:<15} {:<28} {:<10} skipped: {}",
                            provider, model, "missing", reason
                        );
                        failures += 1;
                    }
                    ProviderTestResult::Failed {
                        model,
                        key_status,
                        error,
                    } => {
                        println!(
                            "{:<15} {:<28} {:<10} failed: {}",
                            provider, model, key_status, error
                        );
                        failures += 1;
                    }
                }
            }

            if failures > 0 {
                return Err(format!("{} provider check(s) failed", failures).into());
            }
        }
        ProvidersArgs::Models { provider } => {
            let config_path = find_vest_toml();
            let config = vest_config::load_config(&config_path)
                .unwrap_or_else(|_| vest_config::default_config());
            let model = default_model_for(&config, &provider);
            let provider_client = create_provider(&provider, &model, &config)?;
            println!("Available models for {}:", provider);
            let models =
                tokio::time::timeout(Duration::from_secs(30), provider_client.list_models())
                    .await
                    .map_err(|_| format!("Timed out listing models for {}", provider))??;

            for model in models {
                println!("  {}", model);
            }
        }
        ProvidersArgs::Pull { model } => {
            match std::process::Command::new("which").arg("ollama").output() {
                Ok(output) if output.status.success() => {
                    let mut child = std::process::Command::new("ollama")
                        .arg("pull")
                        .arg(&model)
                        .spawn()?;
                    let status = child.wait()?;
                    if !status.success() {
                        return Err(format!("ollama pull exited with {}", status).into());
                    }
                }
                _ => {
                    println!(
                        "Ollama is not installed. Install from https://ollama.com/ then run: ollama pull {}",
                        model
                    );
                }
            }
        }
        ProvidersArgs::Status => {
            println!("Provider status check:");
            let config_path = find_vest_toml();
            let config = vest_config::load_config(&config_path)
                .unwrap_or_else(|_| vest_config::default_config());
            for provider in providers_to_check(&config, None) {
                let model = default_model_for(&config, &provider);
                let key_status = key_status_for(&provider);
                println!("  {:<15} model={:<28} key={}", provider, model, key_status);
            }
            println!("Run 'vest providers test' to make live API checks.");
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

pub fn get_api_key(provider: &str) -> Option<String> {
    let env_var = format!("{}_API_KEY", provider.to_uppercase());
    std::env::var(&env_var).ok().filter(|k| !k.is_empty())
}

pub(crate) fn create_provider(
    name: &str,
    model: &str,
    config: &vest_config::VestConfig,
) -> Result<Arc<dyn LlmProvider>, VestError> {
    let provider_config = provider_config(config, name);
    let get_key = || get_api_key(name);
    let default_model = Some(model.to_string());

    match name {
        "openai" => {
            let key = get_key().ok_or_else(|| {
                VestError::Config(
                    "OPENAI_API_KEY not set. Run: vest providers set-key openai".into(),
                )
            })?;
            Ok(vest_providers::openai::create_openai_provider(
                Some(key),
                provider_config.and_then(|c| c.api_base.clone()),
                default_model,
            ))
        }
        "deepseek" => {
            let key = get_key().ok_or_else(|| {
                VestError::Config(
                    "DEEPSEEK_API_KEY not set. Run: vest providers set-key deepseek".into(),
                )
            })?;
            Ok(vest_providers::deepseek::create_deepseek_provider(
                Some(key),
                default_model,
            ))
        }
        "anthropic" => {
            let key = get_key().ok_or_else(|| {
                VestError::Config(
                    "ANTHROPIC_API_KEY not set. Run: vest providers set-key anthropic".into(),
                )
            })?;
            Ok(vest_providers::anthropic::create_anthropic_provider(
                key,
                default_model,
            ))
        }
        "google" => {
            let key = get_key().ok_or_else(|| {
                VestError::Config(
                    "GOOGLE_API_KEY not set. Run: vest providers set-key google".into(),
                )
            })?;
            Ok(vest_providers::google::create_google_provider(
                key,
                default_model,
            ))
        }
        "ollama" => Ok(vest_providers::ollama::create_ollama_provider(
            provider_config.and_then(|c| c.api_base.clone()),
            default_model,
        )),
        "groq" => {
            let key = get_key().ok_or_else(|| {
                VestError::Config("GROQ_API_KEY not set. Run: vest providers set-key groq".into())
            })?;
            Ok(vest_providers::groq::create_groq_provider(
                Some(key),
                default_model,
            ))
        }
        "openrouter" => {
            let key = get_key().ok_or_else(|| {
                VestError::Config(
                    "OPENROUTER_API_KEY not set. Run: vest providers set-key openrouter".into(),
                )
            })?;
            Ok(vest_providers::openrouter::create_openrouter_provider(
                Some(key),
                default_model,
            ))
        }
        _ => Err(VestError::Config(format!("Unknown provider: {}", name))),
    }
}

enum ProviderTestResult {
    Ok {
        model: String,
        key_status: &'static str,
        latency_ms: u128,
        response_preview: String,
    },
    Skipped {
        model: String,
        reason: String,
    },
    Failed {
        model: String,
        key_status: &'static str,
        error: String,
    },
}

async fn test_provider(config: &vest_config::VestConfig, name: &str) -> ProviderTestResult {
    let model = default_model_for(config, name);
    let key_status = key_status_for(name);
    let provider = match create_provider(name, &model, config) {
        Ok(provider) => provider,
        Err(e) => {
            return ProviderTestResult::Skipped {
                model,
                reason: e.to_string(),
            }
        }
    };

    let messages = vec![
        serde_json::json!({
            "role": "system",
            "content": "You are VEST's provider connectivity check. Reply with exactly: ok"
        }),
        serde_json::json!({
            "role": "user",
            "content": "Reply with exactly: ok"
        }),
    ];

    let start = Instant::now();
    match tokio::time::timeout(Duration::from_secs(30), provider.chat(&messages, &model)).await {
        Ok(Ok(response)) => ProviderTestResult::Ok {
            model,
            key_status,
            latency_ms: start.elapsed().as_millis(),
            response_preview: truncate(&response.replace('\n', " "), 32),
        },
        Ok(Err(e)) => ProviderTestResult::Failed {
            model,
            key_status,
            error: sanitize_error(name, &e.to_string()),
        },
        Err(_) => ProviderTestResult::Failed {
            model,
            key_status,
            error: "timed out after 30s".into(),
        },
    }
}

fn providers_to_check(config: &vest_config::VestConfig, requested: Option<&str>) -> Vec<String> {
    if let Some(provider) = requested {
        return vec![provider.to_string()];
    }

    let Some(providers) = &config.providers else {
        return Vec::new();
    };

    let mut names = vec![providers.default.provider.clone()];
    names.extend([
        "openai".to_string(),
        "anthropic".to_string(),
        "deepseek".to_string(),
        "google".to_string(),
        "ollama".to_string(),
        "groq".to_string(),
        "openrouter".to_string(),
    ]);
    names.sort();
    names.dedup();
    names
}

fn default_model_for(config: &vest_config::VestConfig, provider: &str) -> String {
    provider_config(config, provider)
        .and_then(|c| c.default_model.clone())
        .or_else(|| {
            config.providers.as_ref().and_then(|providers| {
                (providers.default.provider == provider).then(|| providers.default.model.clone())
            })
        })
        .unwrap_or_else(|| match provider {
            "openai" => "gpt-4o".into(),
            "anthropic" => "claude-sonnet-4-20250514".into(),
            "deepseek" => "deepseek-v4-flash".into(),
            "google" => "gemini-2.5-pro".into(),
            "ollama" => "llama3.2".into(),
            "groq" => "llama-3.3-70b-versatile".into(),
            "openrouter" => "openai/gpt-4o".into(),
            _ => "unknown".into(),
        })
}

fn provider_config<'a>(
    config: &'a vest_config::VestConfig,
    provider: &str,
) -> Option<&'a vest_config::ProviderConfig> {
    let providers = config.providers.as_ref()?;
    match provider {
        "openai" => providers.openai.as_ref(),
        "anthropic" => providers.anthropic.as_ref(),
        "deepseek" => providers.deepseek.as_ref(),
        "google" => providers.google.as_ref(),
        "ollama" => providers.ollama.as_ref(),
        "groq" => providers.groq.as_ref(),
        "openrouter" => providers.openrouter.as_ref(),
        _ => None,
    }
}

fn key_status_for(provider: &str) -> &'static str {
    if provider == "ollama" || get_api_key(provider).is_some() {
        "set"
    } else {
        "missing"
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    let value = value.trim();
    let mut truncated: String = value.chars().take(max_chars).collect();
    if truncated.len() < value.len() {
        truncated.push_str("...");
    }
    truncated
}

fn sanitize_error(provider: &str, error: &str) -> String {
    let mut sanitized = error.to_string();
    if let Some(key) = get_api_key(provider) {
        if !key.is_empty() {
            sanitized = sanitized.replace(&key, "[redacted]");
        }
    }
    truncate(&sanitized.replace('\n', " "), 240)
}
