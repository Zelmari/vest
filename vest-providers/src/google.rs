use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use vest_core::error::VestError;
use vest_core::LlmProvider;

pub struct GoogleProvider {
    pub api_key: String,
    pub default_model: String,
    pub base_url: String,
    client: Client,
}

#[derive(Serialize, Deserialize)]
struct GeminiPart {
    text: String,
}

#[derive(Serialize, Deserialize)]
struct GeminiContent {
    role: String,
    parts: Vec<GeminiPart>,
}

#[derive(Serialize)]
struct GeminiRequest {
    contents: Vec<GeminiContent>,
}

#[derive(Deserialize)]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    content: GeminiContent,
}

#[derive(Deserialize)]
struct GeminiModelListResponse {
    models: Vec<GeminiModelInfo>,
}

#[derive(Deserialize)]
struct GeminiModelInfo {
    name: String,
}

fn map_role(role: &str) -> &str {
    match role {
        "assistant" => "model",
        "system" => "user",
        _ => "user",
    }
}

impl GoogleProvider {
    pub fn new(api_key: String, default_model: Option<String>) -> Self {
        Self {
            api_key,
            default_model: default_model.unwrap_or_else(|| "gemini-2.5-pro".into()),
            base_url: "https://generativelanguage.googleapis.com/v1beta".into(),
            client: Client::new(),
        }
    }

    fn convert_messages(&self, messages: &[Value]) -> Vec<GeminiContent> {
        let system_content: Option<String> = messages
            .iter()
            .find(|m| m["role"].as_str() == Some("system"))
            .and_then(|m| m["content"].as_str().map(|s| s.to_string()));

        let non_system: Vec<&Value> = messages
            .iter()
            .filter(|m| m["role"].as_str() != Some("system"))
            .collect();

        non_system
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let role = m["role"].as_str().unwrap_or("user");
                let content = m["content"].as_str().unwrap_or("");

                let text = if i == 0 && role == "user" {
                    if let Some(ref sys) = system_content {
                        format!(
                            "System instructions:\n{}\n\nUser message:\n{}",
                            sys, content
                        )
                    } else {
                        content.to_string()
                    }
                } else {
                    content.to_string()
                };

                GeminiContent {
                    role: map_role(role).to_string(),
                    parts: vec![GeminiPart { text }],
                }
            })
            .collect()
    }
}

#[async_trait]
impl LlmProvider for GoogleProvider {
    async fn chat(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        let contents = self.convert_messages(messages);

        let model = if model.is_empty() {
            &self.default_model
        } else {
            model
        };

        let req = GeminiRequest { contents };

        let url = format!(
            "{}/models/{}:generateContent?key={}",
            self.base_url.trim_end_matches('/'),
            model,
            self.api_key
        );

        let resp = self
            .client
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| VestError::Provider(format!("Google: HTTP request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(VestError::Provider(format!(
                "Google: HTTP {}: {}",
                status, body
            )));
        }

        let completion: GeminiResponse = resp
            .json()
            .await
            .map_err(|e| VestError::Provider(format!("Google: Failed to parse response: {}", e)))?;

        let candidate = completion
            .candidates
            .into_iter()
            .next()
            .ok_or_else(|| VestError::Provider("Google: No candidates in response".into()))?;

        let content = candidate
            .content
            .parts
            .into_iter()
            .map(|p| p.text)
            .collect::<Vec<_>>()
            .join("");

        Ok(content)
    }

    async fn chat_stream(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        self.chat(messages, model).await
    }

    async fn list_models(&self) -> Result<Vec<String>, VestError> {
        let url = format!(
            "{}/models?key={}",
            self.base_url.trim_end_matches('/'),
            self.api_key
        );

        let resp =
            self.client.get(&url).send().await.map_err(|e| {
                VestError::Provider(format!("Google: Failed to list models: {}", e))
            })?;

        if !resp.status().is_success() {
            return Ok(vec![self.default_model.clone()]);
        }

        let list: GeminiModelListResponse = resp.json().await.map_err(|e| {
            VestError::Provider(format!("Google: Failed to parse model list: {}", e))
        })?;

        let models: Vec<String> = list
            .models
            .iter()
            .map(|m| {
                m.name
                    .strip_prefix("models/")
                    .unwrap_or(&m.name)
                    .to_string()
            })
            .collect();

        if models.is_empty() {
            Ok(vec![self.default_model.clone()])
        } else {
            Ok(models)
        }
    }

    async fn check_model(&self, model: &str) -> Result<bool, VestError> {
        Ok(model == self.default_model || model.is_empty())
    }

    async fn embed(&self, _text: &str, _model: &str) -> Result<Vec<f32>, VestError> {
        Err(VestError::Provider(
            "Google: Embeddings not yet implemented".into(),
        ))
    }
}

pub fn create_google_provider(
    api_key: String,
    default_model: Option<String>,
) -> Arc<dyn LlmProvider> {
    Arc::new(GoogleProvider::new(api_key, default_model))
}
