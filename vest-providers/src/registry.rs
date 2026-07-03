use std::collections::HashMap;
use std::sync::Arc;
use vest_core::LlmProvider;

pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn LlmProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: impl Into<String>, provider: Arc<dyn LlmProvider>) {
        self.providers.insert(name.into(), provider);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn LlmProvider>> {
        self.providers.get(name).cloned()
    }

    pub fn list_names(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
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
            Ok(vec![1.0, 2.0])
        }
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = ProviderRegistry::new();
        let provider: Arc<dyn LlmProvider> = Arc::new(FakeProvider {
            name: "fake1".into(),
        });
        registry.register("fake1", provider);

        let found = registry.get("fake1");
        assert!(found.is_some());
    }

    #[test]
    fn test_registry_get_nonexistent() {
        let registry = ProviderRegistry::new();
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_registry_list_names() {
        let mut registry = ProviderRegistry::new();
        registry.register(
            "openai",
            Arc::new(FakeProvider {
                name: "openai".into(),
            }),
        );
        registry.register(
            "ollama",
            Arc::new(FakeProvider {
                name: "ollama".into(),
            }),
        );

        let names = registry.list_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"openai".to_string()));
        assert!(names.contains(&"ollama".to_string()));
    }

    #[test]
    fn test_registry_register_overwrites() {
        let mut registry = ProviderRegistry::new();
        registry.register("test", Arc::new(FakeProvider { name: "v1".into() }));
        registry.register("test", Arc::new(FakeProvider { name: "v2".into() }));

        let names = registry.list_names();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn test_registry_default_is_empty() {
        let registry = ProviderRegistry::default();
        assert!(registry.list_names().is_empty());
    }
}
