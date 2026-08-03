use std::sync::Arc;
use vest_core::LlmProvider;

pub struct ProviderBuilder;

impl ProviderBuilder {
    pub fn build_openai(
        api_key: Option<String>,
        base_url: Option<String>,
        default_model: Option<String>,
    ) -> Arc<dyn LlmProvider> {
        Self::build_openai_with_timeout(api_key, base_url, default_model, None)
    }

    pub fn build_openai_with_timeout(
        api_key: Option<String>,
        base_url: Option<String>,
        default_model: Option<String>,
        timeout_seconds: Option<u64>,
    ) -> Arc<dyn LlmProvider> {
        crate::openai::create_openai_provider(api_key, base_url, default_model, timeout_seconds)
    }

    pub fn build_deepseek(
        api_key: Option<String>,
        default_model: Option<String>,
    ) -> Arc<dyn LlmProvider> {
        Self::build_deepseek_with_timeout(api_key, default_model, None)
    }

    pub fn build_deepseek_with_timeout(
        api_key: Option<String>,
        default_model: Option<String>,
        timeout_seconds: Option<u64>,
    ) -> Arc<dyn LlmProvider> {
        crate::deepseek::create_deepseek_provider(api_key, default_model, timeout_seconds)
    }

    pub fn build_ollama(
        base_url: Option<String>,
        default_model: Option<String>,
    ) -> Arc<dyn LlmProvider> {
        Self::build_ollama_with_timeout(base_url, default_model, None)
    }

    pub fn build_ollama_with_timeout(
        base_url: Option<String>,
        default_model: Option<String>,
        timeout_seconds: Option<u64>,
    ) -> Arc<dyn LlmProvider> {
        crate::ollama::create_ollama_provider(base_url, default_model, timeout_seconds)
    }

    pub fn build_anthropic(api_key: String, default_model: Option<String>) -> Arc<dyn LlmProvider> {
        Self::build_anthropic_with_timeout(api_key, default_model, None)
    }

    pub fn build_anthropic_with_timeout(
        api_key: String,
        default_model: Option<String>,
        timeout_seconds: Option<u64>,
    ) -> Arc<dyn LlmProvider> {
        crate::anthropic::create_anthropic_provider(api_key, default_model, timeout_seconds)
    }

    pub fn build_google(api_key: String, default_model: Option<String>) -> Arc<dyn LlmProvider> {
        Self::build_google_with_timeout(api_key, default_model, None)
    }

    pub fn build_google_with_timeout(
        api_key: String,
        default_model: Option<String>,
        timeout_seconds: Option<u64>,
    ) -> Arc<dyn LlmProvider> {
        crate::google::create_google_provider(api_key, default_model, timeout_seconds)
    }

    pub fn build_groq(
        api_key: Option<String>,
        default_model: Option<String>,
    ) -> Arc<dyn LlmProvider> {
        Self::build_groq_with_timeout(api_key, default_model, None)
    }

    pub fn build_groq_with_timeout(
        api_key: Option<String>,
        default_model: Option<String>,
        timeout_seconds: Option<u64>,
    ) -> Arc<dyn LlmProvider> {
        crate::groq::create_groq_provider(api_key, default_model, timeout_seconds)
    }

    pub fn build_openrouter(
        api_key: Option<String>,
        default_model: Option<String>,
    ) -> Arc<dyn LlmProvider> {
        Self::build_openrouter_with_timeout(api_key, default_model, None)
    }

    pub fn build_openrouter_with_timeout(
        api_key: Option<String>,
        default_model: Option<String>,
        timeout_seconds: Option<u64>,
    ) -> Arc<dyn LlmProvider> {
        crate::openrouter::create_openrouter_provider(api_key, default_model, timeout_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ollama_no_api_key_needed() {
        let provider =
            ProviderBuilder::build_ollama(Some("http://localhost:11434/v1".into()), None);
        assert_eq!(Arc::strong_count(&provider), 1);
    }
}
