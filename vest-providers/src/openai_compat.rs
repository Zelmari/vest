use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use vest_core::error::VestError;
use vest_core::traits::LlmProvider;
use vest_core::SecretString;

use crate::http_client::build_provider_client;

#[derive(Debug)]
pub struct OpenAiCompatProvider {
    pub name: String,
    pub api_key: Option<SecretString>,
    pub base_url: String,
    pub default_model: String,
    client: Client,
}

impl OpenAiCompatProvider {
    pub fn new(
        name: String,
        api_key: Option<String>,
        base_url: String,
        default_model: String,
    ) -> Self {
        Self::with_timeout(name, api_key, base_url, default_model, None)
    }

    pub fn with_timeout(
        name: String,
        api_key: Option<String>,
        base_url: String,
        default_model: String,
        timeout_seconds: Option<u64>,
    ) -> Self {
        Self {
            name,
            api_key: api_key.map(SecretString::new),
            base_url,
            default_model,
            client: build_provider_client(timeout_seconds),
        }
    }
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
    #[allow(dead_code)]
    model: Option<String>,
    #[allow(dead_code)]
    usage: Option<UsageBody>,
}

#[derive(Deserialize)]
struct Choice {
    message: MessageBody,
}

#[derive(Deserialize)]
struct MessageBody {
    content: Option<String>,
}

#[derive(Deserialize)]
struct UsageBody {
    #[allow(dead_code)]
    prompt_tokens: u32,
    #[allow(dead_code)]
    completion_tokens: u32,
    #[allow(dead_code)]
    total_tokens: u32,
}

#[derive(Deserialize)]
struct ModelListResponse {
    data: Vec<ModelData>,
}

#[derive(Deserialize)]
struct ModelData {
    id: String,
}

#[derive(Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

#[derive(Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

#[derive(Deserialize)]
struct StreamChunk {
    choices: Vec<StreamChoice>,
}

#[derive(Deserialize)]
struct StreamChoice {
    delta: StreamDelta,
}

#[derive(Deserialize)]
struct StreamDelta {
    content: Option<String>,
}

#[async_trait]
impl LlmProvider for OpenAiCompatProvider {
    async fn chat(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        let body = serde_json::json!({
            "model": model,
            "messages": messages,
        });

        let mut http_req = self.client.post(&url).json(&body);
        if let Some(ref api_key) = self.api_key {
            http_req = http_req.bearer_auth(api_key.expose());
        }

        let resp = http_req.send().await.map_err(|e| {
            VestError::Provider(format!("{}: HTTP request failed: {}", self.name, e))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let err = if status.as_u16() == 429 {
                VestError::RateLimited(format!("{}: rate limited", self.name))
            } else {
                VestError::Provider(format!("{}: HTTP {}: {}", self.name, status, body))
            };
            return Err(err);
        }

        let completion: ChatCompletionResponse = resp.json().await.map_err(|e| {
            VestError::Provider(format!("{}: Failed to parse response: {}", self.name, e))
        })?;

        let content = completion
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();

        Ok(content)
    }

    async fn chat_stream(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        let body = serde_json::json!({
            "model": model,
            "messages": messages,
            "stream": true,
        });

        let mut http_req = self.client.post(&url).json(&body);
        if let Some(ref api_key) = self.api_key {
            http_req = http_req.bearer_auth(api_key.expose());
        }

        let resp = http_req.send().await.map_err(|e| {
            VestError::Provider(format!("{}: Streaming request failed: {}", self.name, e))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let err = if status.as_u16() == 429 {
                VestError::RateLimited(format!("{}: rate limited", self.name))
            } else {
                VestError::Provider(format!("{}: HTTP {}: {}", self.name, status, body))
            };
            return Err(err);
        }

        let full_body = resp.text().await.map_err(|e| {
            VestError::Provider(format!("{}: Failed to read stream: {}", self.name, e))
        })?;

        let mut full_content = String::new();
        for line in full_body.lines() {
            let line = line.trim();
            if line.is_empty() || line == "data: [DONE]" {
                continue;
            }
            if let Some(data) = line.strip_prefix("data: ") {
                if let Ok(c) = serde_json::from_str::<StreamChunk>(data) {
                    if let Some(content) =
                        c.choices.first().and_then(|ch| ch.delta.content.as_ref())
                    {
                        full_content.push_str(content);
                    }
                }
            }
        }

        Ok(full_content)
    }

    async fn list_models(&self) -> Result<Vec<String>, VestError> {
        let url = format!("{}/models", self.base_url.trim_end_matches('/'));

        let mut http_req = self.client.get(&url);
        if let Some(ref api_key) = self.api_key {
            http_req = http_req.bearer_auth(api_key.expose());
        }

        let resp = http_req.send().await.map_err(|e| {
            VestError::Provider(format!("{}: Failed to list models: {}", self.name, e))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let err = if status.as_u16() == 429 {
                VestError::RateLimited(format!("{}: rate limited", self.name))
            } else {
                VestError::Provider(format!("{}: HTTP {}: {}", self.name, status, body))
            };
            return Err(err);
        }

        let model_list: ModelListResponse = resp.json().await.map_err(|e| {
            VestError::Provider(format!("{}: Failed to parse model list: {}", self.name, e))
        })?;

        Ok(model_list.data.into_iter().map(|m| m.id).collect())
    }

    async fn check_model(&self, model: &str) -> Result<bool, VestError> {
        let models = self.list_models().await?;
        Ok(models.iter().any(|m| m == model))
    }

    async fn embed(&self, text: &str, model: &str) -> Result<Vec<f32>, VestError> {
        let url = format!("{}/embeddings", self.base_url.trim_end_matches('/'));

        let body = serde_json::json!({
            "model": model,
            "input": text,
        });

        let mut http_req = self.client.post(&url).json(&body);
        if let Some(ref api_key) = self.api_key {
            http_req = http_req.bearer_auth(api_key.expose());
        }

        let resp = http_req.send().await.map_err(|e| {
            VestError::Provider(format!("{}: Embedding request failed: {}", self.name, e))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let err = if status.as_u16() == 429 {
                VestError::RateLimited(format!("{}: rate limited", self.name))
            } else {
                VestError::Provider(format!("{}: HTTP {}: {}", self.name, status, body))
            };
            return Err(err);
        }

        let emb_resp: EmbeddingResponse = resp.json().await.map_err(|e| {
            VestError::Provider(format!("{}: Failed to parse embeddings: {}", self.name, e))
        })?;

        emb_resp
            .data
            .into_iter()
            .next()
            .map(|d| d.embedding)
            .ok_or_else(|| VestError::Provider(format!("{}: No embedding returned", self.name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL_KEY: &str = "VEST_OPENAI_COMPAT_SENTINEL_KEY_PROV2_DO_NOT_LEAK";

    #[test]
    fn debug_never_contains_api_key() {
        let provider = OpenAiCompatProvider::new(
            "test".into(),
            Some(SENTINEL_KEY.into()),
            "https://example.invalid/v1".into(),
            "test-model".into(),
        );
        let debug = format!("{provider:?}");
        assert!(
            !debug.contains(SENTINEL_KEY),
            "Debug must not contain API key: {debug}"
        );
        assert!(
            debug.contains("REDACTED"),
            "expected redaction marker: {debug}"
        );
    }

    #[tokio::test]
    async fn transport_error_does_not_echo_key() {
        let provider = OpenAiCompatProvider::new(
            "test".into(),
            Some(SENTINEL_KEY.into()),
            "http://127.0.0.1:1/v1".into(),
            "test-model".into(),
        );
        let messages = vec![serde_json::json!({"role":"user","content":"hi"})];
        let err = provider.chat(&messages, "test-model").await.unwrap_err();
        let text = err.to_string();
        assert!(
            !text.contains(SENTINEL_KEY),
            "VestError must not contain API key: {text}"
        );
    }
}
