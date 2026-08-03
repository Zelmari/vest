//! `vest doctor` — local diagnostics (no secrets printed).

use std::path::{Path, PathBuf};

use vest_core::error::VestError;

use crate::commands::config::resolve_config_path;
use crate::commands::db;

/// Provider env vars doctor reports presence for (never values).
const PROVIDER_ENV_KEYS: &[(&str, &str)] = &[
    ("openai", "OPENAI_API_KEY"),
    ("anthropic", "ANTHROPIC_API_KEY"),
    ("deepseek", "DEEPSEEK_API_KEY"),
    ("google", "GOOGLE_API_KEY"),
    ("groq", "GROQ_API_KEY"),
    ("openrouter", "OPENROUTER_API_KEY"),
    ("ollama", "OLLAMA_HOST"),
];

pub async fn run(config_path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = resolve_config_path(config_path.as_ref());
    let db = db::db_path();
    let vest_home = vest_home_display();

    println!("VEST doctor");
    println!();

    // --- Paths ---
    println!("Paths");
    println!("  config:     {}", config_path.display());
    println!("  VEST_HOME:  {vest_home}");
    println!("  sqlite:     {}", db.display());
    if let Ok(override_db) = std::env::var("VEST_DB_PATH") {
        if !override_db.is_empty() {
            println!("  VEST_DB_PATH override: set (path above)");
        }
    }
    println!();

    // --- Config validity (fail closed when present but bad) ---
    println!("Config");
    let config = if config_path.exists() {
        match vest_config::load_config(&config_path) {
            Ok(c) => {
                println!("  status:     valid");
                println!("  path:       {}", config_path.display());
                c
            }
            Err(e) => {
                return Err(VestError::Config(format!(
                    "Failed to load config {}: {e}. Refusing silent defaults for a present file.",
                    config_path.display()
                ))
                .into());
            }
        }
    } else {
        println!("  status:     missing (using built-in defaults)");
        println!("  path:       {} (not found)", config_path.display());
        vest_config::default_config()
    };
    println!();

    // --- Provider / offline posture ---
    let configured_provider = config
        .providers
        .as_ref()
        .map(|p| p.default.provider.as_str())
        .unwrap_or("none");
    let configured_model = config
        .providers
        .as_ref()
        .map(|p| p.default.model.as_str())
        .unwrap_or("(n/a)");
    let offline = configured_provider == "none";

    println!("Provider posture");
    println!("  default provider: {configured_provider}");
    println!("  default model:    {configured_model}");
    println!(
        "  posture:          {}",
        if offline {
            "offline / no-ai (scanner-only default)"
        } else {
            "online AI enabled (LLM provider configured)"
        }
    );
    println!("  tip:              use --offline or --no-ai on scan to force provider none");
    println!();

    println!("Provider env keys (presence only)");
    for (name, env_key) in PROVIDER_ENV_KEYS {
        let present = env_key_present(env_key);
        let note = if *name == "ollama" {
            // Ollama is local; host optional
            if present {
                "set"
            } else {
                "unset (default localhost)"
            }
        } else if present {
            "set"
        } else {
            "unset"
        };
        println!("  {name:<12} {env_key:<22} {note}");
    }
    println!();

    // --- Policy / safety summary ---
    let s = &config.safety;
    println!("Policy summary");
    println!("  write_approval:              {}", s.write_approval);
    println!("  exploit_approval:            {}", s.exploit_approval);
    println!(
        "  network_write_approval:      {}",
        s.network_write_approval
    );
    println!("  rate_limit_enabled:          {}", s.rate_limit_enabled);
    println!(
        "  sandbox_enabled (helper):    {} (not an OS sandbox)",
        s.sandbox_enabled
    );
    println!(
        "  egress local_content:        {}",
        s.allow_model_egress_local_content
    );
    println!(
        "  egress process_memory:       {}",
        s.allow_model_egress_process_memory
    );
    println!(
        "  egress target_content:       {}",
        s.allow_model_egress_target_content
    );
    println!(
        "  egress potentially_secret:   {}",
        s.allow_model_egress_potentially_secret_bearing
    );
    println!(
        "  egress evidence:             {}",
        s.allow_model_egress_evidence
    );
    println!();

    println!("Agent");
    println!("  default_pattern: {}", config.agent.default_pattern);
    println!("  max_llm_iterations: {}", config.agent.max_llm_iterations);
    println!();

    println!("Scanners enabled");
    println!(
        "  memory={} binary={} web={} browser={} network={} files={} nuclei={}",
        config.scanner.memory.enabled,
        config.scanner.binary.enabled,
        config.scanner.web.enabled,
        config.scanner.browser.enabled,
        config.scanner.network.enabled,
        config.scanner.files.enabled,
        config.scanner.nuclei.enabled,
    );
    println!(
        "  web.allow_active_probes: {}",
        config.scanner.web.allow_active_probes
    );

    Ok(())
}

fn env_key_present(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
}

fn vest_home_display() -> String {
    if let Ok(home) = std::env::var("VEST_HOME") {
        if !home.is_empty() {
            return home;
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".vest").display().to_string()
}
