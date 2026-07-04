use std::sync::Arc;
use vest_core::LlmProvider;

use crate::openai_compat::OpenAiCompatProvider;

pub fn create_deepseek_provider(
    api_key: Option<String>,
    default_model: Option<String>,
) -> Arc<dyn LlmProvider> {
    Arc::new(OpenAiCompatProvider::new(
        "deepseek".to_string(),
        api_key,
        "https://api.deepseek.com/v1".to_string(),
        default_model.unwrap_or_else(|| "deepseek-v4-flash".to_string()),
    ))
}
