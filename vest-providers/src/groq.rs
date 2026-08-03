use std::sync::Arc;
use vest_core::LlmProvider;

use crate::openai_compat::OpenAiCompatProvider;

pub fn create_groq_provider(
    api_key: Option<String>,
    default_model: Option<String>,
    timeout_seconds: Option<u64>,
) -> Arc<dyn LlmProvider> {
    Arc::new(OpenAiCompatProvider::with_timeout(
        "groq".to_string(),
        api_key,
        "https://api.groq.com/openai/v1".to_string(),
        default_model.unwrap_or_else(|| "llama-3.3-70b-versatile".to_string()),
        timeout_seconds,
    ))
}
