use std::sync::Arc;
use vest_core::LlmProvider;

use crate::openai_compat::OpenAiCompatProvider;

pub fn create_openrouter_provider(
    api_key: Option<String>,
    default_model: Option<String>,
    timeout_seconds: Option<u64>,
) -> Arc<dyn LlmProvider> {
    Arc::new(OpenAiCompatProvider::with_timeout(
        "openrouter".to_string(),
        api_key,
        "https://openrouter.ai/api/v1".to_string(),
        default_model.unwrap_or_else(|| "openai/gpt-4o".to_string()),
        timeout_seconds,
    ))
}
