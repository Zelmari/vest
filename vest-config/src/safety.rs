use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

fn default_rate_limit_rps() -> u32 {
    10
}

fn default_rate_limit_burst() -> u32 {
    30
}

fn default_sandbox_image() -> String {
    "vest-sandbox:latest".to_string()
}

fn default_max_scan_duration_seconds() -> u64 {
    3600
}

fn default_max_concurrent_exploits() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfig {
    #[serde(default = "default_true")]
    pub write_approval: bool,

    #[serde(default = "default_true")]
    pub exploit_approval: bool,

    #[serde(default = "default_true")]
    pub network_write_approval: bool,

    #[serde(default = "default_true")]
    pub rate_limit_enabled: bool,

    #[serde(default = "default_rate_limit_rps")]
    pub rate_limit_requests_per_second: u32,

    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u32,

    #[serde(default = "default_true")]
    pub sandbox_enabled: bool,

    #[serde(default = "default_sandbox_image")]
    pub sandbox_image: String,

    #[serde(default = "default_max_scan_duration_seconds")]
    pub max_scan_duration_seconds: u64,

    #[serde(default = "default_max_concurrent_exploits")]
    pub max_concurrent_exploits: u32,

    pub allowed_targets: Vec<String>,
    pub blocked_targets: Vec<String>,
    pub allowed_networks: Vec<String>,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            write_approval: true,
            exploit_approval: true,
            network_write_approval: true,
            rate_limit_enabled: true,
            rate_limit_requests_per_second: 10,
            rate_limit_burst: 30,
            sandbox_enabled: true,
            sandbox_image: "vest-sandbox:latest".to_string(),
            max_scan_duration_seconds: 3600,
            max_concurrent_exploits: 1,
            allowed_targets: Vec::new(),
            blocked_targets: Vec::new(),
            allowed_networks: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_config_default() {
        let config = SafetyConfig::default();
        assert!(config.write_approval);
        assert!(config.exploit_approval);
        assert!(config.network_write_approval);
        assert!(config.rate_limit_enabled);
        assert_eq!(config.rate_limit_requests_per_second, 10);
        assert_eq!(config.rate_limit_burst, 30);
        assert!(config.sandbox_enabled);
        assert_eq!(config.sandbox_image, "vest-sandbox:latest");
        assert_eq!(config.max_scan_duration_seconds, 3600);
        assert_eq!(config.max_concurrent_exploits, 1);
        assert!(config.allowed_targets.is_empty());
        assert!(config.blocked_targets.is_empty());
        assert!(config.allowed_networks.is_empty());
    }

    #[test]
    fn test_safety_config_to_string() {
        let config = SafetyConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("write_approval"));
    }
}
