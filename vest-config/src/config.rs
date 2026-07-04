use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::provider::{FallbackConfig, ProviderConfig};
use crate::safety::SafetyConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VestConfig {
    pub general: GeneralConfig,
    pub providers: Option<ProvidersSection>,
    pub agent: AgentConfig,
    pub scanner: ScannerConfig,
    #[serde(default)]
    pub safety: SafetyConfig,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

fn default_workspace_dir() -> String {
    "~/.vest".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    #[serde(default = "default_workspace_dir")]
    pub workspace_dir: String,

    #[serde(default = "default_true")]
    pub auto_update_sinks: bool,

    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvidersSection {
    pub default: ProviderRef,
    pub openai: Option<ProviderConfig>,
    pub anthropic: Option<ProviderConfig>,
    pub deepseek: Option<ProviderConfig>,
    pub google: Option<ProviderConfig>,
    pub ollama: Option<ProviderConfig>,
    pub groq: Option<ProviderConfig>,
    pub openrouter: Option<ProviderConfig>,
    pub fallback: Option<FallbackConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRef {
    pub provider: String,
    pub model: String,
}

fn default_pattern() -> String {
    "pipeline".to_string()
}

fn default_max_concurrent_agents() -> u32 {
    8
}

fn default_max_llm_iterations() -> u32 {
    200
}

fn default_token_budget_per_scan() -> u64 {
    1_000_000
}

fn default_thinking_enabled() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default = "default_pattern")]
    pub default_pattern: String,

    #[serde(default = "default_max_concurrent_agents")]
    pub max_concurrent_agents: u32,

    #[serde(default = "default_max_llm_iterations")]
    pub max_llm_iterations: u32,

    #[serde(default = "default_token_budget_per_scan")]
    pub token_budget_per_scan: u64,

    #[serde(default = "default_thinking_enabled")]
    pub thinking_enabled: bool,

    pub recon: Option<AgentRoleConfig>,
    pub hunter: Option<AgentRoleConfig>,
    pub validator: Option<AgentRoleConfig>,
    pub reporter: Option<AgentRoleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRoleConfig {
    pub model: Option<String>,
    pub model_override: Option<String>,
    pub temperature: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    #[serde(default)]
    pub memory: MemoryScannerConfig,

    #[serde(default)]
    pub binary: BinaryScannerConfig,

    #[serde(default)]
    pub web: WebScannerConfig,

    #[serde(default)]
    pub browser: BrowserScannerConfig,

    #[serde(default)]
    pub network: NetworkScannerConfig,

    #[serde(default)]
    pub files: FileScannerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_per_scan_mb: u64,
    #[serde(default = "default_true")]
    pub pattern_scan_acceleration: bool,
    #[serde(default)]
    pub suspicious_regions: Vec<String>,
    #[serde(default = "default_true")]
    pub hook_detection: bool,
}

fn default_max_memory_mb() -> u64 {
    4096
}

impl Default for MemoryScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_memory_per_scan_mb: 4096,
            pattern_scan_acceleration: true,
            suspicious_regions: vec!["RWX".into(), "PAGE_EXECUTE_READWRITE".into()],
            hook_detection: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub sink_catalogs: Vec<String>,
    #[serde(default = "default_disassembler")]
    pub disassembler: String,
    #[serde(default = "default_true")]
    pub check_mitigations: bool,
    #[serde(default)]
    pub find_rop_gadgets: bool,
}

fn default_disassembler() -> String {
    "capstone".into()
}

impl Default for BinaryScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sink_catalogs: vec![
                "sinks/c.txt".into(),
                "sinks/cpp.txt".into(),
                "sinks/rust.txt".into(),
            ],
            disassembler: "capstone".into(),
            check_mitigations: true,
            find_rop_gadgets: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_crawl_depth")]
    pub crawl_depth: u32,
    #[serde(default = "default_crawl_max_urls")]
    pub crawl_max_urls: u32,
    #[serde(default = "default_true")]
    pub respect_robots_txt: bool,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_true")]
    pub nuclei_enabled: bool,
    #[serde(default)]
    pub nuclei_severity: Vec<String>,
    #[serde(default = "default_nuclei_timeout")]
    pub nuclei_timeout: u32,
}

fn default_crawl_depth() -> u32 {
    10
}
fn default_crawl_max_urls() -> u32 {
    10000
}
fn default_user_agent() -> String {
    "VEST/0.1 Vulnerability Scanner".into()
}
fn default_nuclei_timeout() -> u32 {
    300
}

impl Default for WebScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            crawl_depth: 10,
            crawl_max_urls: 10000,
            respect_robots_txt: true,
            user_agent: "VEST/0.1 Vulnerability Scanner".into(),
            nuclei_enabled: true,
            nuclei_severity: vec!["critical".into(), "high".into(), "medium".into()],
            nuclei_timeout: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub browser_path: String,
    #[serde(default = "default_true")]
    pub headless: bool,
    #[serde(default = "default_viewport_width")]
    pub viewport_width: u32,
    #[serde(default = "default_viewport_height")]
    pub viewport_height: u32,
    #[serde(default = "default_true")]
    pub websocket_intercept: bool,
    #[serde(default = "default_true")]
    pub local_storage_inspect: bool,
    #[serde(default = "default_true")]
    pub indexeddb_inspect: bool,
    #[serde(default = "default_true")]
    pub wasm_inspect: bool,
}

fn default_viewport_width() -> u32 {
    1920
}
fn default_viewport_height() -> u32 {
    1080
}

impl Default for BrowserScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            browser_path: String::new(),
            headless: true,
            viewport_width: 1920,
            viewport_height: 1080,
            websocket_intercept: true,
            local_storage_inspect: true,
            indexeddb_inspect: true,
            wasm_inspect: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub capture_filter: String,
    #[serde(default = "default_packet_capture_mb")]
    pub packet_capture_max_mb: u32,
    #[serde(default = "default_true")]
    pub protocol_analysis_llm: bool,
}

fn default_packet_capture_mb() -> u32 {
    500
}

impl Default for NetworkScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: String::new(),
            capture_filter: String::new(),
            packet_capture_max_mb: 500,
            protocol_analysis_llm: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u32,
    #[serde(default = "default_true")]
    pub extract_archives: bool,
    #[serde(default)]
    pub fuzz_file_formats: bool,
}

fn default_max_file_size_mb() -> u32 {
    500
}

impl Default for FileScannerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_file_size_mb: 500,
            extract_archives: true,
            fuzz_file_formats: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub description: Option<String>,
    pub pattern: Option<String>,
    pub phases: Option<Vec<String>>,
    pub agents: Option<Vec<String>>,
    pub scanners: Option<Vec<String>>,
    pub max_llm_iterations: Option<u32>,
    pub token_budget_per_scan: Option<u64>,
    pub safety: Option<ProfileSafetyOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSafetyOverride {
    pub write_approval: Option<bool>,
    pub exploit_approval: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_vest_config() {
        let config = crate::default_config();
        assert_eq!(config.general.workspace_dir, "~/.vest");
        assert_eq!(config.general.log_level, "info");
        assert!(config.general.auto_update_sinks);
        assert_eq!(config.agent.default_pattern, "pipeline");
        assert_eq!(config.agent.max_concurrent_agents, 8);
        assert_eq!(config.agent.max_llm_iterations, 200);
        assert_eq!(config.agent.token_budget_per_scan, 1_000_000);
        assert!(config.scanner.memory.enabled);
        assert!(config.scanner.binary.enabled);
        assert!(config.scanner.web.enabled);
        assert!(config.providers.is_none());
        assert!(config.profiles.is_empty());
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml_str = r#"
[general]
[agent]
[scanner]
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.general.workspace_dir, "~/.vest");
        assert!(config.general.auto_update_sinks);
        assert_eq!(config.agent.default_pattern, "pipeline");
        assert!(config.providers.is_none());
    }

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
[general]
workspace_dir = "/custom/vest"
auto_update_sinks = false
log_level = "debug"

[providers.default]
provider = "openai"
model = "gpt-4o"

[providers.openai]
api_key_env = "OPENAI_API_KEY"
default_model = "gpt-4o"

[providers.fallback]
enabled = false
chain = ["openai", "deepseek"]
strategy = "next_on_failure"

[agent]
default_pattern = "swarm"
max_concurrent_agents = 4
max_llm_iterations = 100
token_budget_per_scan = 500000

[agent.hunter]
model = "anthropic"
temperature = 0.3

[scanner.memory]
enabled = false

[scanner.web]
enabled = true

[safety]
write_approval = false
rate_limit_requests_per_second = 50
allowed_targets = []
blocked_targets = []
allowed_networks = []

[profiles.quick]
description = "Quick scan"
pattern = "tool-use"
token_budget_per_scan = 100000
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();

        assert_eq!(config.general.workspace_dir, "/custom/vest");
        assert!(!config.general.auto_update_sinks);
        assert_eq!(config.general.log_level, "debug");

        let providers = config.providers.unwrap();
        assert_eq!(providers.default.provider, "openai");
        assert_eq!(providers.default.model, "gpt-4o");
        assert_eq!(providers.openai.unwrap().default_model.unwrap(), "gpt-4o");
        assert!(!providers.fallback.unwrap().enabled);

        assert_eq!(config.agent.default_pattern, "swarm");
        assert_eq!(config.agent.max_concurrent_agents, 4);
        assert!(config.agent.hunter.is_some());

        assert!(!config.scanner.memory.enabled);
        assert!(config.scanner.web.enabled);

        assert!(!config.safety.write_approval);
        assert_eq!(config.safety.rate_limit_requests_per_second, 50);

        assert!(config.profiles.contains_key("quick"));
        let profile = &config.profiles["quick"];
        assert_eq!(profile.description.as_deref(), Some("Quick scan"));
        assert_eq!(profile.pattern.as_deref(), Some("tool-use"));
        assert_eq!(profile.token_budget_per_scan, Some(100000));
    }

    #[test]
    fn test_parse_config_with_profiles() {
        let toml_str = r#"
[general]
[agent]
[scanner]

[profiles.deep]
description = "Deep scan"
pattern = "pipeline"
phases = ["recon", "analyze", "hunt", "report"]
scanners = ["memory", "binary", "web"]

[profiles.game]
description = "Game scan"
pattern = "swarm"
agents = ["memory", "network"]

[profiles.deep.safety]
write_approval = false
exploit_approval = false
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.profiles.len(), 2);

        let deep = &config.profiles["deep"];
        assert_eq!(deep.phases.as_ref().unwrap().len(), 4);
        assert_eq!(deep.scanners.as_ref().unwrap().len(), 3);
        assert!(deep.safety.is_some());
        assert!(!deep.safety.as_ref().unwrap().write_approval.unwrap());
    }

    #[test]
    fn test_parse_empty_config_fails_with_error() {
        let result: Result<VestConfig, _> = toml::from_str("");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_from_file() {
        let tmp = std::env::temp_dir().join("test_vest.toml");
        std::fs::write(
            &tmp,
            r#"
[general]
[agent]
[scanner]
"#,
        )
        .unwrap();

        let config = crate::load_config(&tmp).unwrap();
        assert_eq!(config.general.workspace_dir, "~/.vest");
        assert!(config.scanner.memory.enabled);

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_load_config_nonexistent_file_fails() {
        let result = crate::load_config(std::path::Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn test_safety_config_defaults() {
        let toml_str = r#"
[general]
[agent]
[scanner]
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        assert!(config.safety.write_approval);
        assert!(config.safety.exploit_approval);
        assert!(config.safety.rate_limit_enabled);
        assert_eq!(config.safety.rate_limit_requests_per_second, 10);
        assert_eq!(config.safety.max_scan_duration_seconds, 3600);
        assert_eq!(config.safety.max_concurrent_exploits, 1);
        assert!(config.safety.allowed_targets.is_empty());
    }

    #[test]
    fn test_safety_config_parsing() {
        let toml_str = r#"
[general]
[agent]
[scanner]
[safety]
write_approval = false
rate_limit_enabled = false
sandbox_image = "custom:latest"
allowed_targets = ["test.com"]
blocked_targets = ["evil.com"]
allowed_networks = ["10.0.0.0/8"]
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.safety.write_approval);
        assert!(!config.safety.rate_limit_enabled);
        assert_eq!(config.safety.sandbox_image, "custom:latest");
        assert_eq!(config.safety.allowed_targets, vec!["test.com"]);
        assert_eq!(config.safety.blocked_targets, vec!["evil.com"]);
        assert_eq!(config.safety.allowed_networks, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn test_scanner_config_default_all_enabled() {
        let toml_str = r#"
[general]
[agent]
[scanner]
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        assert!(config.scanner.memory.enabled);
        assert!(config.scanner.binary.enabled);
        assert!(config.scanner.web.enabled);
        assert!(config.scanner.browser.enabled);
        assert!(config.scanner.network.enabled);
        assert!(config.scanner.files.enabled);
    }

    #[test]
    fn test_scanner_config_selective_disable() {
        let toml_str = r#"
[general]
[agent]
[scanner]
[scanner.memory]
enabled = false
[scanner.web]
enabled = false
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        assert!(!config.scanner.memory.enabled);
        assert!(!config.scanner.web.enabled);
        assert!(config.scanner.binary.enabled);
    }

    #[test]
    fn test_agent_role_config_parsing() {
        let toml_str = r#"
[general]
[agent]
[scanner]

[agent.recon]
model = "groq"
temperature = 0.1

[agent.validator]
model = "deepseek"
temperature = 0.0
model_override = "deepseek-v4-flash"
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        let recon = config.agent.recon.unwrap();
        assert_eq!(recon.model.unwrap(), "groq");
        assert_eq!(recon.temperature.unwrap(), 0.1);

        let validator = config.agent.validator.unwrap();
        assert_eq!(validator.model_override.unwrap(), "deepseek-v4-flash");
        assert_eq!(validator.temperature.unwrap(), 0.0);
    }

    #[test]
    fn test_providers_section_full() {
        let toml_str = r#"
[general]
[agent]
[scanner]

[providers.default]
provider = "ollama"
model = "llama3.2"

[providers.openai]
api_key_env = "OPENAI_KEY"
api_base = "https://api.openai.com/v1"
default_model = "gpt-4o"
timeout_seconds = 120
max_retries = 3
retry_delay_ms = 1000

[providers.ollama]
api_base = "http://localhost:11434/v1"
default_model = "llama3.2"

[providers.fallback]
enabled = true
chain = ["openrouter", "deepseek", "ollama"]
strategy = "next_on_failure"
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        let providers = config.providers.unwrap();
        assert_eq!(providers.default.provider, "ollama");
        assert_eq!(providers.ollama.unwrap().default_model.unwrap(), "llama3.2");

        let openai = providers.openai.unwrap();
        assert_eq!(openai.timeout_seconds.unwrap(), 120);
        assert_eq!(openai.max_retries.unwrap(), 3);

        let fallback = providers.fallback.unwrap();
        assert!(fallback.enabled);
        assert_eq!(fallback.chain.len(), 3);
        assert_eq!(fallback.strategy, "next_on_failure");
    }

    #[test]
    fn test_parse_toml_with_extreme_numeric_values() {
        let toml_str = r#"
[general]
[agent]
max_concurrent_agents = 4294967295
max_llm_iterations = 4294967295
token_budget_per_scan = 9223372036854775807
[scanner]
[safety]
rate_limit_requests_per_second = 4294967295
max_scan_duration_seconds = 9223372036854775807
allowed_targets = []
blocked_targets = []
allowed_networks = []
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.agent.max_concurrent_agents, u32::MAX);
        assert_eq!(config.safety.rate_limit_requests_per_second, u32::MAX);
    }

    #[test]
    fn test_parse_toml_with_zero_values() {
        let toml_str = r#"
[general]
[agent]
max_concurrent_agents = 0
max_llm_iterations = 0
token_budget_per_scan = 0
[scanner]
[safety]
rate_limit_requests_per_second = 0
max_scan_duration_seconds = 0
allowed_targets = []
blocked_targets = []
allowed_networks = []
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.agent.max_concurrent_agents, 0);
        assert_eq!(config.safety.max_scan_duration_seconds, 0);
    }

    #[test]
    fn test_parse_toml_with_unicode_section_names() {
        let toml_str = r#"
[general]
[agent]
[scanner]
[profiles."🎮game"]
description = "Game profile"
pattern = "swarm"
"#;
        let result: Result<VestConfig, _> = toml::from_str(toml_str);
        let _ = result;
    }

    #[test]
    fn test_parse_toml_missing_scanner_uses_defaults() {
        let toml_str = r#"
[general]
[agent]
[scanner]
"#;
        let config: VestConfig = toml::from_str(toml_str).unwrap();
        assert!(config.scanner.memory.enabled);
        assert!(config.scanner.web.enabled);
    }

    #[test]
    fn test_fuzz_config_parser_100_iterations() {
        for _ in 0..100 {
            let patterns = ["pipeline", "swarm", "tool-use", "hierarchical"];
            let enabled = rand::random::<bool>();

            let toml_str = format!(
                r#"
[general]
workspace_dir = "~/.vest"

[agent]
default_pattern = "{}"

[scanner]
[scanner.memory]
enabled = {}

[safety]
write_approval = {}
"#,
                patterns[rand::random::<usize>() % patterns.len()],
                enabled,
                rand::random::<bool>()
            );

            let result: Result<VestConfig, _> = toml::from_str(&toml_str);
            let _ = result;
        }
    }
}
