use std::sync::Arc;
use vest_core::LlmProvider;

use crate::openai_compat::OpenAiCompatProvider;

pub fn create_ollama_provider(
    base_url: Option<String>,
    default_model: Option<String>,
) -> Arc<dyn LlmProvider> {
    Arc::new(OpenAiCompatProvider::new(
        "ollama".to_string(),
        None,
        base_url.unwrap_or_else(|| "http://localhost:11434/v1".to_string()),
        default_model.unwrap_or_else(|| "llama3".to_string()),
    ))
}
