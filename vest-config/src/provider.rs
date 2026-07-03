use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackConfig {
    pub enabled: bool,
    pub chain: Vec<String>,
    pub strategy: String,
}
