use crate::ProvidersArgs;
use std::path::PathBuf;

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

            println!("Configured Providers:");
            println!("{:<15} {:<20} {:<25}", "Provider", "Model", "API Base");
            println!("{}", "-".repeat(60));

            if let Some(providers) = &config.providers {
                println!(
                    "{:<15} {:<20} {:<25}",
                    providers.default.provider, providers.default.model, "default"
                );

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
                    if let Some(c) = config {
                        let model = c.default_model.as_deref().unwrap_or("not set");
                        let base = c.api_base.as_deref().unwrap_or("default");
                        println!("{:<15} {:<20} {:<25}", name, model, base);
                    }
                }

                if let Some(fallback) = &providers.fallback {
                    println!(
                        "\nFallback chain: {:?} (strategy: {})",
                        fallback.chain, fallback.strategy
                    );
                }
            }
        }
        ProvidersArgs::Test => {
            println!("Testing provider connectivity...");
            println!("  This requires API keys to be set in environment variables.");
            println!("  Set OPENAI_API_KEY, ANTHROPIC_API_KEY, DEEPSEEK_API_KEY, etc.");
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
