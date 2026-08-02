use futures::stream::{FuturesUnordered, StreamExt};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use vest_core::error::VestError;
pub use vest_core::types::FallbackStrategy;
use vest_core::LlmProvider;

/// Default per-provider timeout for parallel fan-out.
const DEFAULT_PER_PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);

/// Multi-provider fallback chain.
///
/// # `TryAllParallel` semantics
///
/// - All providers are polled concurrently (`FuturesUnordered`).
/// - The **first successful** response wins; remaining in-flight futures are dropped
///   (cancellation via drop — cooperative for `tokio::time::timeout` wrappers).
/// - Each provider call is wrapped in an optional per-provider timeout.
/// - An optional overall timeout wraps the entire fan-out.
/// - On total failure, errors are aggregated with **provider names only** (no request
///   body / secret contents).
pub struct FallbackChain {
    providers: Vec<(String, Arc<dyn LlmProvider>)>,
    strategy: FallbackStrategy,
    per_provider_timeout: Option<Duration>,
    overall_timeout: Option<Duration>,
}

impl FallbackChain {
    pub fn new(strategy: FallbackStrategy) -> Self {
        Self {
            providers: Vec::new(),
            strategy,
            per_provider_timeout: Some(DEFAULT_PER_PROVIDER_TIMEOUT),
            overall_timeout: None,
        }
    }

    pub fn add_provider(&mut self, name: impl Into<String>, provider: Arc<dyn LlmProvider>) {
        self.providers.push((name.into(), provider));
    }

    pub fn with_providers(mut self, providers: Vec<(String, Arc<dyn LlmProvider>)>) -> Self {
        self.providers = providers;
        self
    }

    /// Per-provider timeout for `TryAllParallel` (and optionally used as a bound).
    /// Pass `None` to disable.
    pub fn with_per_provider_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.per_provider_timeout = timeout;
        self
    }

    /// Optional wall-clock timeout for the entire parallel attempt.
    pub fn with_overall_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.overall_timeout = timeout;
        self
    }

    pub async fn chat(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        match self.strategy {
            FallbackStrategy::NextOnFailure => {
                let mut last_error = VestError::Provider("All providers exhausted".into());
                let mut errors: Vec<String> = Vec::new();
                for (name, provider) in &self.providers {
                    match provider.chat(messages, model).await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            tracing::warn!("Provider {} failed: {} — trying next", name, e);
                            errors.push(format!("{name}: {e}"));
                            last_error = e;
                            continue;
                        }
                    }
                }
                if !errors.is_empty() {
                    return Err(VestError::Provider(format!(
                        "All providers exhausted [{}]",
                        errors.join("; ")
                    )));
                }
                Err(last_error)
            }
            FallbackStrategy::NextOnRateLimit => {
                let mut last_error = VestError::Provider("All providers exhausted".into());
                for (name, provider) in &self.providers {
                    match provider.chat(messages, model).await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            if matches!(e, VestError::RateLimited(_)) {
                                tracing::warn!("Provider {} rate limited — trying next", name);
                                last_error = e;
                                continue;
                            }
                            return Err(e);
                        }
                    }
                }
                Err(last_error)
            }
            FallbackStrategy::TryAllParallel => self.chat_parallel(messages, model, false).await,
        }
    }

    pub async fn chat_stream(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        match self.strategy {
            FallbackStrategy::NextOnFailure => {
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
            FallbackStrategy::NextOnRateLimit => {
                let mut last_error = VestError::Provider("All providers exhausted".into());
                for (name, provider) in &self.providers {
                    match provider.chat_stream(messages, model).await {
                        Ok(response) => return Ok(response),
                        Err(e) => {
                            if matches!(e, VestError::RateLimited(_)) {
                                tracing::warn!(
                                    "Provider {} streaming rate limited — trying next",
                                    name
                                );
                                last_error = e;
                                continue;
                            }
                            return Err(e);
                        }
                    }
                }
                Err(last_error)
            }
            FallbackStrategy::TryAllParallel => self.chat_parallel(messages, model, true).await,
        }
    }

    /// Concurrent fan-out: first success wins; remaining futures are dropped.
    async fn chat_parallel(
        &self,
        messages: &[Value],
        model: &str,
        stream: bool,
    ) -> Result<String, VestError> {
        if self.providers.is_empty() {
            return Err(VestError::Provider("No providers configured".into()));
        }

        let fut = self.chat_parallel_inner(messages, model, stream);
        match self.overall_timeout {
            Some(overall) => match tokio::time::timeout(overall, fut).await {
                Ok(result) => result,
                Err(_) => Err(VestError::Timeout(format!(
                    "overall parallel fallback timed out after {}ms",
                    overall.as_millis()
                ))),
            },
            None => fut.await,
        }
    }

    async fn chat_parallel_inner(
        &self,
        messages: &[Value],
        model: &str,
        stream: bool,
    ) -> Result<String, VestError> {
        let mut futures = FuturesUnordered::new();

        for (name, provider) in &self.providers {
            let provider = Arc::clone(provider);
            let messages: Vec<Value> = messages.to_vec();
            let model = model.to_string();
            let name = name.clone();
            let per_timeout = self.per_provider_timeout;

            futures.push(async move {
                let call = async {
                    if stream {
                        provider.chat_stream(&messages, &model).await
                    } else {
                        provider.chat(&messages, &model).await
                    }
                };

                let outcome = match per_timeout {
                    Some(t) => match tokio::time::timeout(t, call).await {
                        Ok(inner) => inner,
                        Err(_) => Err(VestError::Timeout(format!(
                            "provider {name} timed out after {}ms",
                            t.as_millis()
                        ))),
                    },
                    None => call.await,
                };

                (name, outcome)
            });
        }

        let mut errors: Vec<String> = Vec::new();
        while let Some((name, outcome)) = futures.next().await {
            match outcome {
                Ok(response) => {
                    // Dropping `futures` cancels remaining in-flight provider calls.
                    return Ok(response);
                }
                Err(e) => {
                    // Aggregate error text with provider name only — never request contents.
                    tracing::warn!(provider = %name, error = %e, "parallel provider failed");
                    errors.push(format!("{name}: {e}"));
                }
            }
        }

        Err(VestError::Provider(format!(
            "All providers exhausted [{}]",
            errors.join("; ")
        )))
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Notify;
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

    /// Controllable mock that signals start and waits before returning.
    struct ControllableProvider {
        name: String,
        started: Arc<Notify>,
        gate: Arc<Notify>,
        ok_response: Option<String>,
        active: Arc<AtomicBool>,
    }

    #[async_trait]
    impl LlmProvider for ControllableProvider {
        async fn chat(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            self.active.store(true, Ordering::SeqCst);
            self.started.notify_one();
            self.gate.notified().await;
            self.active.store(false, Ordering::SeqCst);
            match &self.ok_response {
                Some(s) => Ok(s.clone()),
                None => Err(VestError::Provider(format!("{} failed", self.name))),
            }
        }
        async fn chat_stream(
            &self,
            messages: &[serde_json::Value],
            model: &str,
        ) -> Result<String, VestError> {
            self.chat(messages, model).await
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

    struct ImmediateProvider {
        name: String,
        ok_response: Option<String>,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl LlmProvider for ImmediateProvider {
        async fn chat(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.ok_response {
                Some(s) => Ok(s.clone()),
                None => Err(VestError::Provider(format!("{}-fail", self.name))),
            }
        }
        async fn chat_stream(
            &self,
            messages: &[serde_json::Value],
            model: &str,
        ) -> Result<String, VestError> {
            self.chat(messages, model).await
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

    struct DelayedFailProvider {
        started: Arc<Notify>,
        delay: Duration,
    }

    #[async_trait]
    impl LlmProvider for DelayedFailProvider {
        async fn chat(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            self.started.notify_one();
            tokio::time::sleep(self.delay).await;
            Err(VestError::Provider("slow fail".into()))
        }
        async fn chat_stream(
            &self,
            messages: &[serde_json::Value],
            model: &str,
        ) -> Result<String, VestError> {
            self.chat(messages, model).await
        }
        async fn list_models(&self) -> Result<Vec<String>, VestError> {
            Ok(vec!["slow".into()])
        }
        async fn check_model(&self, _model: &str) -> Result<bool, VestError> {
            Ok(true)
        }
        async fn embed(&self, _text: &str, _model: &str) -> Result<Vec<f32>, VestError> {
            Ok(vec![])
        }
    }

    struct FastSuccessProvider {
        started: Arc<Notify>,
        delay: Duration,
    }

    #[async_trait]
    impl LlmProvider for FastSuccessProvider {
        async fn chat(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            self.started.notify_one();
            tokio::time::sleep(self.delay).await;
            Ok("fast-ok".into())
        }
        async fn chat_stream(
            &self,
            messages: &[serde_json::Value],
            model: &str,
        ) -> Result<String, VestError> {
            self.chat(messages, model).await
        }
        async fn list_models(&self) -> Result<Vec<String>, VestError> {
            Ok(vec!["fast".into()])
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

    #[tokio::test]
    async fn test_parallel_slow_fail_fast_success_overlap() {
        let slow_started = Arc::new(Notify::new());
        let fast_started = Arc::new(Notify::new());

        let slow: Arc<dyn LlmProvider> = Arc::new(DelayedFailProvider {
            started: Arc::clone(&slow_started),
            delay: Duration::from_millis(200),
        });
        let fast: Arc<dyn LlmProvider> = Arc::new(FastSuccessProvider {
            started: Arc::clone(&fast_started),
            delay: Duration::from_millis(20),
        });

        let chain = FallbackChain::new(FallbackStrategy::TryAllParallel)
            .with_per_provider_timeout(Some(Duration::from_secs(2)))
            .with_providers(vec![("slow".into(), slow), ("fast".into(), fast)]);

        let start = tokio::time::Instant::now();
        let result = chain.chat(&[], "m").await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(result, "fast-ok");
        // Overlap proof: both must have started, and total time << slow delay alone
        // (if sequential: ~200ms+; concurrent: ~20ms).
        assert!(
            elapsed < Duration::from_millis(150),
            "expected concurrent completion, elapsed={elapsed:?}"
        );
    }

    #[tokio::test]
    async fn test_parallel_all_fail_aggregates_provider_names() {
        let a: Arc<dyn LlmProvider> = Arc::new(ImmediateProvider {
            name: "alpha".into(),
            ok_response: None,
            calls: Arc::new(AtomicUsize::new(0)),
        });
        let b: Arc<dyn LlmProvider> = Arc::new(ImmediateProvider {
            name: "beta".into(),
            ok_response: None,
            calls: Arc::new(AtomicUsize::new(0)),
        });

        let chain = FallbackChain::new(FallbackStrategy::TryAllParallel)
            .with_per_provider_timeout(None)
            .with_providers(vec![("alpha".into(), a), ("beta".into(), b)]);

        let err = chain.chat(&[], "m").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("alpha"), "{msg}");
        assert!(msg.contains("beta"), "{msg}");
        // Must not leak fabricated request contents
        assert!(!msg.contains("role"));
    }

    #[tokio::test]
    async fn test_parallel_per_provider_timeout() {
        let gate = Arc::new(Notify::new());
        let started = Arc::new(Notify::new());
        // Never open the gate — provider hangs until timeout.
        let hanging: Arc<dyn LlmProvider> = Arc::new(ControllableProvider {
            name: "hang".into(),
            started: Arc::clone(&started),
            gate: Arc::clone(&gate),
            ok_response: Some("never".into()),
            active: Arc::new(AtomicBool::new(false)),
        });
        let ok: Arc<dyn LlmProvider> = Arc::new(ImmediateProvider {
            name: "ok".into(),
            ok_response: Some("ok-resp".into()),
            calls: Arc::new(AtomicUsize::new(0)),
        });

        let chain = FallbackChain::new(FallbackStrategy::TryAllParallel)
            .with_per_provider_timeout(Some(Duration::from_millis(50)))
            .with_providers(vec![("hang".into(), hanging), ("ok".into(), ok)]);

        let result = chain.chat(&[], "m").await.unwrap();
        assert_eq!(result, "ok-resp");
    }

    #[tokio::test]
    async fn test_parallel_overall_timeout() {
        let gate = Arc::new(Notify::new());
        let started = Arc::new(Notify::new());
        let hanging: Arc<dyn LlmProvider> = Arc::new(ControllableProvider {
            name: "hang".into(),
            started,
            gate,
            ok_response: Some("never".into()),
            active: Arc::new(AtomicBool::new(false)),
        });

        let chain = FallbackChain::new(FallbackStrategy::TryAllParallel)
            .with_per_provider_timeout(None)
            .with_overall_timeout(Some(Duration::from_millis(40)))
            .with_providers(vec![("hang".into(), hanging)]);

        let err = chain.chat(&[], "m").await.unwrap_err();
        assert!(matches!(err, VestError::Timeout(_)), "{err}");
    }

    #[tokio::test]
    async fn test_sequential_next_on_failure_still_sequential() {
        let order = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));

        struct OrderedProvider {
            mark: Arc<AtomicUsize>,
            calls: Arc<AtomicUsize>,
            fail: bool,
            slot: usize,
        }

        #[async_trait]
        impl LlmProvider for OrderedProvider {
            async fn chat(
                &self,
                _messages: &[serde_json::Value],
                _model: &str,
            ) -> Result<String, VestError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let prev = self.mark.fetch_add(1, Ordering::SeqCst);
                assert_eq!(
                    prev, self.slot,
                    "providers must be tried sequentially in order"
                );
                if self.fail {
                    Err(VestError::Provider("fail".into()))
                } else {
                    Ok("seq-ok".into())
                }
            }
            async fn chat_stream(
                &self,
                messages: &[serde_json::Value],
                model: &str,
            ) -> Result<String, VestError> {
                self.chat(messages, model).await
            }
            async fn list_models(&self) -> Result<Vec<String>, VestError> {
                Ok(vec![])
            }
            async fn check_model(&self, _model: &str) -> Result<bool, VestError> {
                Ok(true)
            }
            async fn embed(&self, _text: &str, _model: &str) -> Result<Vec<f32>, VestError> {
                Ok(vec![])
            }
        }

        let a: Arc<dyn LlmProvider> = Arc::new(OrderedProvider {
            mark: Arc::clone(&order),
            calls: Arc::clone(&first_calls),
            fail: true,
            slot: 0,
        });
        let b: Arc<dyn LlmProvider> = Arc::new(OrderedProvider {
            mark: Arc::clone(&order),
            calls: Arc::clone(&second_calls),
            fail: false,
            slot: 1,
        });

        let chain = FallbackChain::new(FallbackStrategy::NextOnFailure)
            .with_providers(vec![("a".into(), a), ("b".into(), b)]);

        let result = chain.chat(&[], "m").await.unwrap();
        assert_eq!(result, "seq-ok");
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }
}
