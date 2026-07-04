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
    Ok(config)
}

pub fn default_config() -> VestConfig {
    VestConfig {
        general: config::GeneralConfig {
            workspace_dir: "~/.vest".to_string(),
            auto_update_sinks: true,
            log_level: "info".to_string(),
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
}
