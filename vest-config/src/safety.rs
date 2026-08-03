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

/// Safety configuration.
///
/// Unknown fields in `[safety]` are rejected so typos cannot silently disable policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// When true, the CLI may offer Docker sandbox helpers. This is not an OS sandbox for agent tools.
    #[serde(default = "default_true")]
    pub sandbox_enabled: bool,

    #[serde(default = "default_sandbox_image")]
    pub sandbox_image: String,

    #[serde(default = "default_max_scan_duration_seconds")]
    pub max_scan_duration_seconds: u64,

    #[serde(default = "default_max_concurrent_exploits")]
    pub max_concurrent_exploits: u32,

    #[serde(default)]
    pub allowed_targets: Vec<String>,
    #[serde(default)]
    pub blocked_targets: Vec<String>,
    #[serde(default)]
    pub allowed_networks: Vec<String>,

    /// When true, agent tools may return local file contents to a remote model after policy allow.
    /// Default false (action auth ≠ egress auth).
    #[serde(default)]
    pub allow_model_egress_local_content: bool,

    /// When true, process-memory bytes may be sent to a remote model. Default false.
    #[serde(default)]
    pub allow_model_egress_process_memory: bool,

    /// When true, HTTP/crawl response bodies may be sent to a remote model (still bounded + redacted).
    /// Default false — action auth for PassiveNetworkRequest ≠ TargetContent egress.
    #[serde(default)]
    pub allow_model_egress_target_content: bool,

    /// When true, command/write tool output may be sent to a remote model (still bounded + redacted).
    /// Default false.
    #[serde(default)]
    pub allow_model_egress_potentially_secret_bearing: bool,

    /// When true, bounded finding evidence excerpts may be included in validator prompts.
    #[serde(default)]
    pub allow_model_egress_evidence: bool,
}

impl SafetyConfig {
    /// Validate safety-critical bounds. Malformed present configs must not become permissive defaults.
    pub fn validate(&self) -> Result<(), String> {
        if self.rate_limit_enabled {
            if self.rate_limit_requests_per_second == 0 {
                return Err("safety.rate_limit_requests_per_second must be > 0".into());
            }
            if self.rate_limit_burst == 0 {
                return Err("safety.rate_limit_burst must be > 0".into());
            }
        }
        if self.max_scan_duration_seconds == 0 {
            return Err("safety.max_scan_duration_seconds must be > 0".into());
        }
        if self.max_concurrent_exploits == 0 {
            return Err("safety.max_concurrent_exploits must be > 0".into());
        }
        if self.sandbox_image.trim().is_empty() {
            return Err("safety.sandbox_image must not be empty".into());
        }
        Ok(())
    }
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
            allow_model_egress_local_content: false,
            allow_model_egress_process_memory: false,
            allow_model_egress_target_content: false,
            allow_model_egress_potentially_secret_bearing: false,
            allow_model_egress_evidence: false,
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
