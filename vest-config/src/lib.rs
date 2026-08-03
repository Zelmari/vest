pub mod config;
pub mod provider;
pub mod safety;
pub mod scan;

pub use config::*;
pub use provider::*;
pub use safety::*;
pub use scan::*;

use std::path::Path;
use vest_core::error::VestError;

pub fn load_config(path: &Path) -> Result<VestConfig, VestError> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        VestError::Config(format!(
            "Failed to read config file {}: {}",
            path.display(),
            e
        ))
    })?;
    let config: VestConfig = toml::from_str(&contents)
        .map_err(|e| VestError::Config(format!("Failed to parse config: {}", e)))?;
    validate_config(&config)?;
    Ok(config)
}

/// Validate bounds that must be non-zero / known (CFG-1).
pub fn validate_config(config: &VestConfig) -> Result<(), VestError> {
    config
        .safety
        .validate()
        .map_err(|e| VestError::Config(format!("Invalid safety configuration: {e}")))?;
    config.agent.validate().map_err(VestError::Config)?;
    config.scanner.files.validate().map_err(VestError::Config)?;
    config.scanner.web.validate().map_err(VestError::Config)?;
    config
        .scanner
        .network
        .validate()
        .map_err(VestError::Config)?;
    if config.scanner.memory.max_memory_per_scan_mb == 0 {
        return Err(VestError::Config(
            "scanner.memory.max_memory_per_scan_mb must be > 0".into(),
        ));
    }
    if let Some(providers) = &config.providers {
        for (name, cfg) in [
            ("openai", providers.openai.as_ref()),
            ("anthropic", providers.anthropic.as_ref()),
            ("deepseek", providers.deepseek.as_ref()),
            ("google", providers.google.as_ref()),
            ("ollama", providers.ollama.as_ref()),
            ("groq", providers.groq.as_ref()),
            ("openrouter", providers.openrouter.as_ref()),
        ] {
            if let Some(cfg) = cfg {
                cfg.validate(name).map_err(VestError::Config)?;
            }
        }
    }
    for (name, profile) in &config.profiles {
        profile.validate(name).map_err(VestError::Config)?;
    }
    Ok(())
}

/// Load config if the path exists; if missing, return defaults.
/// A present but unreadable or malformed file is always an error (no silent fallback).
pub fn load_config_or_default(path: &Path) -> Result<VestConfig, VestError> {
    if !path.exists() {
        return Ok(default_config());
    }
    load_config(path)
}

pub fn default_config() -> VestConfig {
    VestConfig {
        general: config::GeneralConfig {
            workspace_dir: "~/.vest".to_string(),
            auto_update_sinks: true,
            log_level: "info".to_string(),
            include_report_evidence: false,
        },
        providers: None,
        agent: config::AgentConfig {
            default_pattern: "pipeline".to_string(),
            max_concurrent_agents: 8,
            max_llm_iterations: 200,
            token_budget_per_scan: 1_000_000,
            thinking_enabled: false,
            recon: None,
            hunter: None,
            validator: None,
            reporter: None,
        },
        scanner: config::ScannerConfig {
            memory: config::MemoryScannerConfig::default(),
            binary: config::BinaryScannerConfig::default(),
            web: config::WebScannerConfig::default(),
            browser: config::BrowserScannerConfig::default(),
            network: config::NetworkScannerConfig::default(),
            files: config::FileScannerConfig::default(),
        },
        safety: safety::SafetyConfig::default(),
        profiles: std::collections::HashMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_valid_vest_toml() {
        let tmp = std::env::temp_dir().join("test_valid.toml");
        std::fs::write(
            &tmp,
            r#"
[general]
[agent]
[scanner]
[profiles.quick]
description = "Quick"
pattern = "tool-use"
"#,
        )
        .unwrap();

        let config = load_config(&tmp).unwrap();
        assert!(config.profiles.contains_key("quick"));

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_load_invalid_toml() {
        let tmp = std::env::temp_dir().join("test_invalid.toml");
        std::fs::write(&tmp, "this is not valid toml {{{{{").unwrap();

        let result = load_config(&tmp);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to parse"));

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_default_config_has_all_scanners_enabled() {
        let config = default_config();
        assert!(config.scanner.memory.enabled);
        assert!(config.scanner.binary.enabled);
        assert!(config.scanner.web.enabled);
        assert!(config.scanner.browser.enabled);
        assert!(config.scanner.network.enabled);
        assert!(config.scanner.files.enabled);
    }

    #[test]
    fn test_default_config_safety_settings() {
        let config = default_config();
        assert!(config.safety.write_approval);
        assert_eq!(config.safety.rate_limit_requests_per_second, 10);
    }

    #[test]
    fn test_load_config_with_custom_workspace() {
        let tmp = std::env::temp_dir().join("test_workspace.toml");
        std::fs::write(
            &tmp,
            r#"
[general]
workspace_dir = "/custom/path"
[agent]
[scanner]
"#,
        )
        .unwrap();

        let config = load_config(&tmp).unwrap();
        assert_eq!(config.general.workspace_dir, "/custom/path");

        std::fs::remove_file(&tmp).ok();
    }

    fn write_temp_toml(name: &str, contents: &str) -> std::path::PathBuf {
        let tmp = std::env::temp_dir().join(name);
        std::fs::write(&tmp, contents).unwrap();
        tmp
    }

    #[test]
    fn load_config_rejects_zero_max_concurrent_agents() {
        let tmp = write_temp_toml(
            "test_cfg1_agents.toml",
            r#"
[general]
[agent]
max_concurrent_agents = 0
[scanner]
"#,
        );
        let err = load_config(&tmp).unwrap_err().to_string();
        assert!(
            err.contains("max_concurrent_agents"),
            "expected rejection, got: {err}"
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_config_rejects_zero_max_llm_iterations() {
        let tmp = write_temp_toml(
            "test_cfg1_iters.toml",
            r#"
[general]
[agent]
max_llm_iterations = 0
[scanner]
"#,
        );
        let err = load_config(&tmp).unwrap_err().to_string();
        assert!(
            err.contains("max_llm_iterations"),
            "expected rejection, got: {err}"
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_config_rejects_zero_token_budget() {
        let tmp = write_temp_toml(
            "test_cfg1_budget.toml",
            r#"
[general]
[agent]
token_budget_per_scan = 0
[scanner]
"#,
        );
        let err = load_config(&tmp).unwrap_err().to_string();
        assert!(
            err.contains("token_budget_per_scan"),
            "expected rejection, got: {err}"
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_config_rejects_zero_provider_timeout() {
        let tmp = write_temp_toml(
            "test_cfg1_timeout.toml",
            r#"
[general]
[agent]
[scanner]
[providers.default]
provider = "openai"
model = "gpt-4o"
[providers.openai]
timeout_seconds = 0
"#,
        );
        let err = load_config(&tmp).unwrap_err().to_string();
        assert!(
            err.contains("timeout_seconds"),
            "expected rejection, got: {err}"
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_config_rejects_zero_packet_capture_max_mb() {
        let tmp = write_temp_toml(
            "test_cfg1_network.toml",
            r#"
[general]
[agent]
[scanner]
[scanner.network]
packet_capture_max_mb = 0
"#,
        );
        let err = load_config(&tmp).unwrap_err().to_string();
        assert!(
            err.contains("packet_capture_max_mb"),
            "expected rejection, got: {err}"
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_config_rejects_unknown_provider_field() {
        let tmp = write_temp_toml(
            "test_cfg1_unknown.toml",
            r#"
[general]
[agent]
[scanner]
[providers.default]
provider = "openai"
model = "gpt-4o"
[providers.openai]
typo_timeout = 120
"#,
        );
        let err = load_config(&tmp).unwrap_err().to_string();
        assert!(
            err.contains("Failed to parse") || err.contains("unknown"),
            "expected unknown-field parse error, got: {err}"
        );
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_config_rejects_zero_profile_max_llm_iterations() {
        let tmp = write_temp_toml(
            "test_cfg1_profile.toml",
            r#"
[general]
[agent]
[scanner]
[profiles.quick]
max_llm_iterations = 0
"#,
        );
        let err = load_config(&tmp).unwrap_err().to_string();
        assert!(
            err.contains("max_llm_iterations"),
            "expected rejection, got: {err}"
        );
        std::fs::remove_file(&tmp).ok();
    }
}
