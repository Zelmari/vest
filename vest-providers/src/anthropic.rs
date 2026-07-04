use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use vest_core::error::VestError;
use vest_core::LlmProvider;

pub struct AnthropicProvider {
    pub api_key: String,
    pub default_model: String,
    pub base_url: String,
    pub anthropic_version: String,
    client: Client,
}

#[derive(Serialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: Vec<AnthropicContentBlock>,
}

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicResponseContent>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AnthropicResponseContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

impl AnthropicProvider {
    pub fn new(api_key: String, default_model: Option<String>) -> Self {
        Self {
            api_key,
            default_model: default_model.unwrap_or_else(|| "claude-sonnet-4-20250514".into()),
            base_url: "https://api.anthropic.com/v1".into(),
            anthropic_version: "2023-06-01".into(),
            client: Client::new(),
        }
    }

    fn convert_messages(&self, messages: &[Value]) -> (Option<String>, Vec<AnthropicMessage>) {
        let mut system_content: Option<String> = None;
        let mut msg_bodies: Vec<AnthropicMessage> = Vec::new();

        for msg in messages {
            let role = msg["role"].as_str().unwrap_or("user");
            let content = msg["content"].as_str().unwrap_or("");

            if role == "system" {
                system_content = Some(content.to_string());
            } else {
                let anthropic_role = match role {
                    "assistant" => "assistant",
                    _ => "user",
                };

                msg_bodies.push(AnthropicMessage {
                    role: anthropic_role.to_string(),
                    content: vec![AnthropicContentBlock {
                        content_type: "text".into(),
                        text: content.to_string(),
                    }],
                });
            }
        }

        (system_content, msg_bodies)
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    async fn chat(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        let (system, msg_bodies) = self.convert_messages(messages);

        let model = if model.is_empty() {
            &self.default_model
        } else {
            model
        };

        let req = AnthropicRequest {
            model: model.to_string(),
            max_tokens: 4096,
            messages: msg_bodies,
            system,
            temperature: None,
            top_p: None,
            stop_sequences: None,
        };

        let url = format!("{}/messages", self.base_url.trim_end_matches('/'));

        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", &self.anthropic_version)
            .json(&req)
            .send()
            .await
            .map_err(|e| VestError::Provider(format!("Anthropic: HTTP request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let err = if status.as_u16() == 429 {
                VestError::RateLimited("Anthropic: rate limited".into())
            } else {
                VestError::Provider(format!("Anthropic: HTTP {}: {}", status, body))
            };
            return Err(err);
        }

        let completion: AnthropicResponse = resp.json().await.map_err(|e| {
            VestError::Provider(format!("Anthropic: Failed to parse response: {}", e))
        })?;

        let content = completion
            .content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default();

        Ok(content)
    }

    async fn chat_stream(&self, messages: &[Value], model: &str) -> Result<String, VestError> {
        self.chat(messages, model).await
    }

    async fn list_models(&self) -> Result<Vec<String>, VestError> {
        Ok(vec![self.default_model.clone()])
    }

    async fn check_model(&self, model: &str) -> Result<bool, VestError> {
        Ok(model == self.default_model || model.is_empty())
    }

    async fn embed(&self, _text: &str, _model: &str) -> Result<Vec<f32>, VestError> {
        Err(VestError::Provider(
            "Anthropic: Embeddings not supported via this API".into(),
        ))
    }
}

pub fn create_anthropic_provider(
    api_key: String,
    default_model: Option<String>,
) -> Arc<dyn LlmProvider> {
    Arc::new(AnthropicProvider::new(api_key, default_model))
}
