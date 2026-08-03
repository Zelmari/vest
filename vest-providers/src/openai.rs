use std::sync::Arc;
use vest_core::LlmProvider;

use crate::openai_compat::OpenAiCompatProvider;

pub fn create_openai_provider(
    api_key: Option<String>,
    base_url: Option<String>,
    default_model: Option<String>,
    timeout_seconds: Option<u64>,
) -> Arc<dyn LlmProvider> {
    Arc::new(OpenAiCompatProvider::with_timeout(
        "openai".to_string(),
        api_key,
        base_url.unwrap_or_else(|| "https://api.openai.com/v1".to_string()),
        default_model.unwrap_or_else(|| "gpt-4o".to_string()),
        timeout_seconds,
    ))
}
