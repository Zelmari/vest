use serde_json::Value;
use std::sync::Arc;
use vest_core::error::VestError;
use vest_core::LlmProvider;

pub struct FallbackChain {
    providers: Vec<(String, Arc<dyn LlmProvider>)>,
    strategy: FallbackStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackStrategy {
    NextOnFailure,
    NextOnRateLimit,
    TryAllParallel,
}

impl FallbackChain {
    pub fn new(strategy: FallbackStrategy) -> Self {
        Self {
            providers: Vec::new(),
            strategy,
        }
    }

    pub fn add_provider(&mut self, name: impl Into<String>, provider: Arc<dyn LlmProvider>) {
        self.providers.push((name.into(), provider));
    }

    pub fn with_providers(mut self, providers: Vec<(String, Arc<dyn LlmProvider>)>) -> Self {
        self.providers = providers;
        self
    }

    pub async fn chat(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        match self.strategy {
            FallbackStrategy::NextOnFailure | FallbackStrategy::NextOnRateLimit => {
                let mut last_error = VestError::Provider("All providers exhausted".into());
                for (name, provider) in &self.providers {
                    match provider.chat(messages, model).await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            tracing::warn!("Provider {} failed: {} — trying next", name, e);
                            last_error = e;
                            continue;
                        }
                    }
                }
                Err(last_error)
            }
            FallbackStrategy::TryAllParallel => {
                let handles: Vec<_> = self
                    .providers
                    .iter()
                    .map(|(_name, provider)| {
                        let provider = Arc::clone(provider);
                        let messages: Vec<Value> = messages.to_vec();
                        let model = model.to_string();
                        async move { provider.chat(&messages, &model).await }
                    })
                    .collect();

                let mut last_error = VestError::Provider("All providers exhausted".into());
                for handle in handles {
                    match handle.await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            last_error = e;
                        }
                    }
                }
                Err(last_error)
            }
        }
    }

    pub async fn chat_stream(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        match self.strategy {
            FallbackStrategy::NextOnFailure | FallbackStrategy::NextOnRateLimit => {
                let mut last_error = VestError::Provider("All providers exhausted".into());
                for (name, provider) in &self.providers {
                    match provider.chat_stream(messages, model).await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            tracing::warn!(
                                "Provider {} streaming failed: {} — trying next",
                                name,
                                e
                            );
                            last_error = e;
                            continue;
                        }
                    }
                }
                Err(last_error)
            }
            FallbackStrategy::TryAllParallel => {
                let handles: Vec<_> = self
                    .providers
                    .iter()
                    .map(|(_name, provider)| {
                        let provider = Arc::clone(provider);
                        let messages: Vec<Value> = messages.to_vec();
                        let model = model.to_string();
                        async move { provider.chat_stream(&messages, &model).await }
                    })
                    .collect();

                let mut last_error = VestError::Provider("All providers exhausted".into());
                for handle in handles {
                    match handle.await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            last_error = e;
                        }
                    }
                }
                Err(last_error)
            }
        }
    }

    pub async fn list_models(&self) -> Result<Vec<String>, VestError> {
        let mut all_models = Vec::new();
        for (_name, provider) in &self.providers {
            if let Ok(models) = provider.list_models().await {
                all_models.extend(models);
            }
        }
        Ok(all_models)
    }

    pub async fn check_model(&self, model: &str) -> Result<bool, VestError> {
        for (_name, provider) in &self.providers {
            if let Ok(true) = provider.check_model(model).await {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn embed(&self, text: &str, model: &str) -> Result<Vec<f32>, VestError> {
        let mut last_error = VestError::Provider("All providers exhausted for embeddings".into());
        for (name, provider) in &self.providers {
            match provider.embed(text, model).await {
                Ok(embeddings) => return Ok(embeddings),
                Err(e) => {
                    tracing::warn!("Provider {} embed failed: {} — trying next", name, e);
                    last_error = e;
                    continue;
                }
            }
        }
        Err(last_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;
    use vest_core::error::VestError;
    use vest_core::traits::LlmProvider;

    struct FakeProvider {
        name: String,
    }

    #[async_trait]
    impl LlmProvider for FakeProvider {
        async fn chat(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            Ok(format!("response from {}", self.name))
        }
        async fn chat_stream(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            Ok(format!("stream from {}", self.name))
        }
        async fn list_models(&self) -> Result<Vec<String>, VestError> {
            Ok(vec![self.name.clone()])
        }
        async fn check_model(&self, _model: &str) -> Result<bool, VestError> {
            Ok(true)
        }
        async fn embed(&self, _text: &str, _model: &str) -> Result<Vec<f32>, VestError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_fallback_strategy_variants() {
        let strat = FallbackStrategy::NextOnFailure;
        assert_eq!(strat, FallbackStrategy::NextOnFailure);
        let strat = FallbackStrategy::NextOnRateLimit;
        assert_eq!(strat, FallbackStrategy::NextOnRateLimit);
        let strat = FallbackStrategy::TryAllParallel;
        assert_eq!(strat, FallbackStrategy::TryAllParallel);
    }

    #[test]
    fn test_fallback_chain_creation() {
        let chain = FallbackChain::new(FallbackStrategy::NextOnFailure);
        assert!(chain.providers.is_empty());
        assert_eq!(chain.strategy, FallbackStrategy::NextOnFailure);
    }

    #[test]
    fn test_fallback_chain_add_provider() {
        let mut chain = FallbackChain::new(FallbackStrategy::NextOnFailure);
        let provider: Arc<dyn LlmProvider> = Arc::new(FakeProvider {
            name: "test".into(),
        });
        chain.add_provider("test", provider);
        assert_eq!(chain.providers.len(), 1);
    }
}
