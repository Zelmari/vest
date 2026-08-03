use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use vest_core::error::VestError;
use vest_core::LlmProvider;
use vest_core::SecretString;

use crate::http_client::build_provider_client;

/// Google AI / Gemini API key header (preferred over `?key=` query params).
const GOOGLE_API_KEY_HEADER: &str = "x-goog-api-key";

#[derive(Debug)]
pub struct GoogleProvider {
    pub api_key: SecretString,
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

/// Redact the API key from any string that may surface in VestError / logs.
fn scrub_api_key(message: &str, api_key: &str) -> String {
    if api_key.is_empty() {
        return message.to_string();
    }
    message.replace(api_key, "[REDACTED]")
}

impl GoogleProvider {
    pub fn new(api_key: String, default_model: Option<String>) -> Self {
        Self::with_timeout(api_key, default_model, None)
    }

    pub fn with_timeout(
        api_key: String,
        default_model: Option<String>,
        timeout_seconds: Option<u64>,
    ) -> Self {
        Self {
            api_key: SecretString::new(api_key),
            default_model: default_model.unwrap_or_else(|| "gemini-2.5-pro".into()),
            base_url: "https://generativelanguage.googleapis.com/v1beta".into(),
            client: build_provider_client(timeout_seconds),
        }
    }

    fn provider_err(&self, message: impl AsRef<str>) -> VestError {
        VestError::Provider(scrub_api_key(message.as_ref(), self.api_key.expose()))
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
            "{}/models/{}:generateContent",
            self.base_url.trim_end_matches('/'),
            model
        );

        let resp = self
            .client
            .post(&url)
            .header(GOOGLE_API_KEY_HEADER, self.api_key.expose())
            .json(&req)
            .send()
            .await
            .map_err(|e| self.provider_err(format!("Google: HTTP request failed: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let err = if status.as_u16() == 429 {
                VestError::RateLimited(scrub_api_key("Google: rate limited", self.api_key.expose()))
            } else {
                self.provider_err(format!("Google: HTTP {}: {}", status, body))
            };
            return Err(err);
        }

        let completion: GeminiResponse = resp
            .json()
            .await
            .map_err(|e| self.provider_err(format!("Google: Failed to parse response: {}", e)))?;

        let candidate = completion
            .candidates
            .into_iter()
            .next()
            .ok_or_else(|| self.provider_err("Google: No candidates in response"))?;

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
        let url = format!("{}/models", self.base_url.trim_end_matches('/'));

        let resp = self
            .client
            .get(&url)
            .header(GOOGLE_API_KEY_HEADER, self.api_key.expose())
            .send()
            .await
            .map_err(|e| self.provider_err(format!("Google: Failed to list models: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(self.provider_err(format!("Google: HTTP {}: {}", status, body)));
        }

        let list: GeminiModelListResponse = resp
            .json()
            .await
            .map_err(|e| self.provider_err(format!("Google: Failed to parse model list: {}", e)))?;

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
    timeout_seconds: Option<u64>,
) -> Arc<dyn LlmProvider> {
    Arc::new(GoogleProvider::with_timeout(
        api_key,
        default_model,
        timeout_seconds,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use vest_core::LlmProvider;

    const SENTINEL_KEY: &str = "VEST_GOOGLE_SENTINEL_KEY_PROV1_DO_NOT_LEAK";

    async fn spawn_capture_server(
        status: u16,
        body: Vec<u8>,
    ) -> (u16, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = captured.clone();
        let body = Arc::new(body);
        tokio::spawn(async move {
            while !flag.load(Ordering::Relaxed) {
                let Ok((mut socket, _)) =
                    tokio::time::timeout(Duration::from_millis(50), listener.accept())
                        .await
                        .unwrap_or(Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "timeout",
                        )))
                else {
                    continue;
                };
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                captured_clone.lock().unwrap().push(req);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let mut bytes = resp.into_bytes();
                bytes.extend_from_slice(&body);
                let _ = socket.write_all(&bytes).await;
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        (port, stop, captured)
    }

    fn provider_for(base: &str) -> GoogleProvider {
        let mut p = GoogleProvider::new(SENTINEL_KEY.to_string(), Some("gemini-test".into()));
        p.base_url = base.to_string();
        p
    }

    #[test]
    fn scrub_api_key_redacts_sentinel() {
        let msg = format!("error for url (https://example/?key={SENTINEL_KEY}): boom");
        let scrubbed = scrub_api_key(&msg, SENTINEL_KEY);
        assert!(!scrubbed.contains(SENTINEL_KEY));
        assert!(scrubbed.contains("[REDACTED]"));
    }

    #[test]
    fn debug_never_contains_api_key() {
        let provider = GoogleProvider::new(SENTINEL_KEY.to_string(), Some("gemini-test".into()));
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
    async fn generate_content_uses_header_not_query() {
        let body =
            br#"{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]}}]}"#.to_vec();
        let (port, stop, captured) = spawn_capture_server(200, body).await;
        let base = format!("http://127.0.0.1:{port}/v1beta");
        let provider = provider_for(&base);

        let messages = vec![serde_json::json!({"role":"user","content":"hi"})];
        let out = provider.chat(&messages, "gemini-test").await.unwrap();
        assert_eq!(out, "ok");

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        let first_line = req.lines().next().unwrap_or("");
        assert!(
            first_line.contains("generateContent"),
            "request line: {first_line}"
        );
        assert!(
            !first_line.contains(SENTINEL_KEY),
            "sentinel must not appear in request line/query: {first_line}"
        );
        assert!(
            !first_line.contains("?key="),
            "must not use ?key= query auth: {first_line}"
        );
        let header_line = format!("{GOOGLE_API_KEY_HEADER}: {SENTINEL_KEY}");
        assert!(
            req.to_ascii_lowercase()
                .contains(&header_line.to_ascii_lowercase()),
            "missing {GOOGLE_API_KEY_HEADER} header in:\n{req}"
        );

        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn list_models_uses_header_not_query() {
        let body = br#"{"models":[{"name":"models/gemini-test"}]}"#.to_vec();
        let (port, stop, captured) = spawn_capture_server(200, body).await;
        let base = format!("http://127.0.0.1:{port}/v1beta");
        let provider = provider_for(&base);

        let models = provider.list_models().await.unwrap();
        assert_eq!(models, vec!["gemini-test".to_string()]);

        let reqs = captured.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        let first_line = req.lines().next().unwrap_or("");
        assert!(first_line.contains("/models"), "request line: {first_line}");
        assert!(
            !first_line.contains(SENTINEL_KEY),
            "sentinel must not appear in request line/query: {first_line}"
        );
        assert!(
            !first_line.contains("?key="),
            "must not use ?key= query auth: {first_line}"
        );
        let header_line = format!("{GOOGLE_API_KEY_HEADER}: {SENTINEL_KEY}");
        assert!(
            req.to_ascii_lowercase()
                .contains(&header_line.to_ascii_lowercase()),
            "missing {GOOGLE_API_KEY_HEADER} header in:\n{req}"
        );

        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn http_error_body_echoing_key_is_scrubbed() {
        // Server echoes the key in the error body (as some APIs / proxies do).
        let leak_body = format!(r#"{{"error":"bad key {SENTINEL_KEY}"}}"#).into_bytes();
        let (port, stop, _captured) = spawn_capture_server(401, leak_body).await;
        let base = format!("http://127.0.0.1:{port}/v1beta");
        let provider = provider_for(&base);

        let messages = vec![serde_json::json!({"role":"user","content":"hi"})];
        let err = provider.chat(&messages, "gemini-test").await.unwrap_err();
        let text = err.to_string();
        assert!(
            !text.contains(SENTINEL_KEY),
            "VestError must not echo API key: {text}"
        );
        assert!(
            text.contains("[REDACTED]"),
            "expected redaction marker: {text}"
        );

        stop.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn transport_error_does_not_echo_key() {
        // Point at a closed port so reqwest fails; URL must not embed the key.
        let provider = provider_for("http://127.0.0.1:1/v1beta");
        let messages = vec![serde_json::json!({"role":"user","content":"hi"})];
        let err = provider.chat(&messages, "gemini-test").await.unwrap_err();
        let text = err.to_string();
        assert!(
            !text.contains(SENTINEL_KEY),
            "transport VestError must not contain API key: {text}"
        );

        let err2 = provider.list_models().await.unwrap_err();
        let text2 = err2.to_string();
        assert!(
            !text2.contains(SENTINEL_KEY),
            "list_models transport VestError must not contain API key: {text2}"
        );
    }

    #[tokio::test]
    async fn list_models_fail_closed_on_http_error() {
        let leak_body = format!(r#"{{"error":"bad key {SENTINEL_KEY}"}}"#).into_bytes();
        let (port, stop, _captured) = spawn_capture_server(503, leak_body).await;
        let base = format!("http://127.0.0.1:{port}/v1beta");
        let provider = provider_for(&base);

        let err = provider.list_models().await.unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("HTTP 503") || text.contains("503"),
            "expected HTTP error, got: {text}"
        );
        assert!(
            !text.contains(SENTINEL_KEY),
            "list_models HTTP VestError must not contain API key: {text}"
        );
        assert!(
            text.contains("[REDACTED]"),
            "expected redaction marker: {text}"
        );

        stop.store(true, Ordering::Relaxed);
    }
}
