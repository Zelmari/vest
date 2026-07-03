use vest_providers::fallback::*;
use vest_providers::provider::*;

#[test]
fn test_chat_message_empty_content() {
    let msg = ChatMessage::user("");
    assert_eq!(msg.content, "");
    assert_eq!(msg.role, "user");
}

#[test]
fn test_chat_message_very_long_content() {
    let content = "A".repeat(1_000_000);
    let msg = ChatMessage::user(&content);
    assert_eq!(msg.content.len(), 1_000_000);
}

#[test]
fn test_generation_config_all_none() {
    let config = GenerationConfig {
        temperature: None,
        max_tokens: None,
        top_p: None,
        stop_sequences: None,
    };
    assert!(config.temperature.is_none());
}

#[test]
fn test_generation_config_extreme_values() {
    let config = GenerationConfig {
        temperature: Some(0.0),
        max_tokens: Some(u32::MAX),
        top_p: Some(1.0),
        stop_sequences: Some(vec![]),
    };
    assert_eq!(config.temperature, Some(0.0));
    assert_eq!(config.max_tokens, Some(u32::MAX));
}

#[test]
fn test_fallback_chain_empty_handles_chat() {
    let chain = FallbackChain::new(FallbackStrategy::NextOnFailure);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(chain.chat(&[], "test-model"));
    assert!(result.is_err());
}

#[test]
fn test_tool_definition_empty_fields() {
    let tool = ToolDefinition {
        name: String::new(),
        description: String::new(),
        parameters: serde_json::json!(null),
    };
    assert_eq!(tool.name, "");
    assert_eq!(tool.description, "");
    assert!(tool.parameters.is_null());
}

#[test]
fn test_chat_response_serialization() {
    let resp = ChatResponse {
        content: "Hello, world!".into(),
        model: "test-model-v2".into(),
        usage: Some(UsageInfo {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
        }),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let deser: ChatResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.content, resp.content);
    assert_eq!(deser.model, resp.model);
    assert_eq!(deser.usage.unwrap().total_tokens, 150);
}

#[test]
fn test_usage_info_zero_tokens() {
    let usage = UsageInfo {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0,
    };
    assert_eq!(usage.total_tokens, 0);
}

#[test]
fn test_model_info_empty_provider() {
    let info = ModelInfo {
        id: "".into(),
        provider: String::new(),
    };
    assert!(info.id.is_empty());
    assert!(info.provider.is_empty());
}
