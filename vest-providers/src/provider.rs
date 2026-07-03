use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationConfig {
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub top_p: Option<f64>,
    pub stop_sequences: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub content: String,
    pub model: String,
    pub usage: Option<UsageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChunk {
    pub content: String,
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageInfo {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelStatus {
    pub available: bool,
    pub model: String,
}

impl ChatMessage {
    pub fn new(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: content.into(),
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::new("user", content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new("assistant", content)
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self::new("system", content)
    }
}

impl Default for GenerationConfig {
    fn default() -> Self {
        Self {
            temperature: Some(0.7),
            max_tokens: Some(4096),
            top_p: None,
            stop_sequences: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_message_constructors() {
        let msg = ChatMessage::user("Hello");
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content, "Hello");

        let msg = ChatMessage::assistant("Hi there");
        assert_eq!(msg.role, "assistant");

        let msg = ChatMessage::system("You are helpful");
        assert_eq!(msg.role, "system");

        let msg = ChatMessage::new("custom_role", "content");
        assert_eq!(msg.role, "custom_role");
    }

    #[test]
    fn test_generation_config_defaults() {
        let config = GenerationConfig::default();
        assert_eq!(config.temperature, Some(0.7));
        assert_eq!(config.max_tokens, Some(4096));
        assert!(config.top_p.is_none());
        assert!(config.stop_sequences.is_none());
    }

    #[test]
    fn test_chat_response_creation() {
        let resp = ChatResponse {
            content: "Hello".into(),
            model: "gpt-4o".into(),
            usage: Some(UsageInfo {
                prompt_tokens: 10,
                completion_tokens: 5,
                total_tokens: 15,
            }),
        };
        assert_eq!(resp.content, "Hello");
        assert_eq!(resp.model, "gpt-4o");
        assert_eq!(resp.usage.as_ref().unwrap().total_tokens, 15);
    }

    #[test]
    fn test_model_info() {
        let info = ModelInfo {
            id: "gpt-4o".into(),
            provider: "openai".into(),
        };
        assert_eq!(info.id, "gpt-4o");
        assert_eq!(info.provider, "openai");
    }

    #[test]
    fn test_model_status() {
        let status = ModelStatus {
            available: true,
            model: "gpt-4o".into(),
        };
        assert!(status.available);
        let status = ModelStatus {
            available: false,
            model: "claude".into(),
        };
        assert!(!status.available);
    }

    #[test]
    fn test_tool_definition() {
        let tool = ToolDefinition {
            name: "read_memory".into(),
            description: "Read process memory".into(),
            parameters: serde_json::json!({"address": "string"}),
        };
        assert_eq!(tool.name, "read_memory");
        assert!(tool.parameters.is_object());
    }

    #[test]
    fn test_chat_chunk() {
        let chunk = ChatChunk {
            content: "Hello".into(),
            finish_reason: Some("stop".into()),
        };
        assert_eq!(chunk.content, "Hello");
        assert_eq!(chunk.finish_reason, Some("stop".into()));

        let chunk = ChatChunk {
            content: "".into(),
            finish_reason: None,
        };
        assert!(chunk.content.is_empty());
    }
}
