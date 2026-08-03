use serde::{Deserialize, Serialize};

/// Per-provider settings.
///
/// Unknown fields are rejected so typos cannot silently disable timeouts/retries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub api_key_env: Option<String>,
    pub api_base: Option<String>,
    pub default_model: Option<String>,
    pub organization_id: Option<String>,
    pub timeout_seconds: Option<u64>,
    pub max_retries: Option<u32>,
    pub retry_delay_ms: Option<u64>,
    pub max_tokens_default: Option<u32>,
    pub thinking_enabled: Option<bool>,
}

impl ProviderConfig {
    /// Reject zero timeouts / token defaults that would hang or no-op requests.
    pub fn validate(&self, name: &str) -> Result<(), String> {
        if self.timeout_seconds == Some(0) {
            return Err(format!(
                "providers.{name}.timeout_seconds must be non-zero when set"
            ));
        }
        if self.max_tokens_default == Some(0) {
            return Err(format!(
                "providers.{name}.max_tokens_default must be non-zero when set"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackConfig {
    pub enabled: bool,
    pub chain: Vec<String>,
    pub strategy: String,
}
