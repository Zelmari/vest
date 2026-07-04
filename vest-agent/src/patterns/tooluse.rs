use crate::context::AgentContext;
use crate::safety::SafetyChecker;
use crate::tool_registry::ToolRegistry;
use std::sync::Arc;
use tokio::sync::RwLock;
use vest_core::error::VestError;
use vest_core::traits::{AgentStatus, LlmProvider};
use vest_core::types::{Finding, Target};

pub struct ToolUseRunner {
    provider: Arc<dyn LlmProvider>,
    registry: Arc<ToolRegistry>,
    model: String,
    max_iterations: u32,
    system_prompt: String,
    safety: Arc<SafetyChecker>,
    status: RwLock<AgentStatus>,
}

impl ToolUseRunner {
    pub fn new(
        provider: Arc<dyn LlmProvider>,
        registry: Arc<ToolRegistry>,
        model: impl Into<String>,
        system_prompt: impl Into<String>,
        safety: Arc<SafetyChecker>,
    ) -> Self {
        Self {
            provider,
            registry,
            model: model.into(),
            max_iterations: 200,
            system_prompt: system_prompt.into(),
            safety,
            status: RwLock::new(AgentStatus::Idle),
        }
    }

    pub fn with_max_iterations(mut self, max: u32) -> Self {
        self.max_iterations = max;
        self
    }

    pub async fn run(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        self.set_status(AgentStatus::Running).await;

        let mut ctx = AgentContext::new()
            .with_target(target.clone())
            .with_system_prompt(self.build_system_prompt(target))
            .with_max_iterations(self.max_iterations);

        for tool_def in self.registry.get_all_definitions() {
            ctx.add_tool(tool_def);
        }

        ctx.add_observation(format!("Starting scan of target: {}", target.name));

        loop {
            if *self.status.read().await == AgentStatus::Stopped {
                break;
            }

            if !ctx.increment_iteration() {
                ctx.add_observation("Maximum iterations reached");
                break;
            }

            let messages = self.build_messages(&ctx);

            match self.provider.chat(&messages, &self.model).await {
                Ok(response) => {
                    if let Some(tool_call) = self.parse_tool_call(&response) {
                        let tool_name = &tool_call.name;

                        let tool_def = self.registry.get_tool(tool_name);
                        if let Some(def) = tool_def {
                            if def.definition.requires_approval {
                                match self
                                    .safety
                                    .approve_tool_call(tool_name, &tool_call.arguments)
                                {
                                    Ok(true) => {}
                                    Ok(false) => {
                                        ctx.add_message(
                                            "assistant",
                                            format!("Tool call rejected by safety gate: {}", tool_name),
                                        );
                                        ctx.add_message(
                                            "user",
                                            format!(
                                                "The tool call '{}' was rejected by the safety system. Try a different approach.",
                                                tool_name
                                            ),
                                        );
                                        continue;
                                    }
                                    Err(e) => {
                                        ctx.add_observation(format!(
                                            "Safety check error for '{}': {}",
                                            tool_name, e
                                        ));
                                        ctx.add_message(
                                            "user",
                                            format!(
                                                "Safety check failed for '{}': {}. Try a different approach.",
                                                tool_name, e
                                            ),
                                        );
                                        continue;
                                    }
                                }
                            }
                        }

                        // Rate limit check before execution
                        if let Err(e) = self.safety.check_rate_limit().await {
                            ctx.add_observation(format!("Rate limited: {}", e));
                            ctx.add_message(
                                "user",
                                format!(
                                    "Rate limit reached: {}. Slow down and retry.",
                                    e
                                ),
                            );
                            continue;
                        }

                        ctx.add_message(
                            "assistant",
                            format!(
                                "Calling tool: {} with args: {}",
                                tool_name, tool_call.arguments
                            ),
                        );

                        match self
                            .registry
                            .execute(tool_name, tool_call.arguments.clone())
                        {
                            Ok(result) => {
                                let result_str = serde_json::to_string(&result).unwrap_or_default();
                                ctx.add_message(
                                    "user",
                                    format!("Tool '{}' result: {}", tool_name, result_str),
                                );
                                ctx.add_observation(format!(
                                    "Tool '{}' executed successfully",
                                    tool_name
                                ));
                            }
                            Err(err) => {
                                ctx.add_message(
                                    "user",
                                    format!("Tool '{}' error: {}", tool_name, err),
                                );
                                ctx.add_observation(format!(
                                    "Tool '{}' failed: {}",
                                    tool_name, err
                                ));
                            }
                        }
                    } else {
                        ctx.add_message("assistant", &response);
                        ctx.add_observation(format!(
                            "Agent response: {}",
                            &response[..response.len().min(200)]
                        ));

                        let lower = response.to_lowercase();
                        if lower.contains("scan complete")
                            || lower.contains("finished scanning")
                            || lower.contains("final report")
                            || lower.contains("no findings")
                        {
                            break;
                        }
                    }
                }
                Err(e) => {
                    ctx.add_observation(format!("LLM error: {}", e));
                    ctx.add_message(
                        "user",
                        format!(
                            "Error: {}. Please continue or report what you found so far.",
                            e
                        ),
                    );
                }
            }
        }

        self.set_status(AgentStatus::Completed).await;
        Ok(ctx.findings)
    }

    fn build_system_prompt(&self, target: &Target) -> String {
        let mut prompt = self.system_prompt.clone();

        prompt.push_str(&format!(
            "\n\nYou are scanning: {}\nTarget type: {:?}\n",
            target.name, target.target_type
        ));
        if let Some(path) = &target.path {
            prompt.push_str(&format!("Path: {}\n", path));
        }
        if let Some(url) = &target.url_str {
            prompt.push_str(&format!("URL: {}\n", url));
        }
        if let Some(pid) = target.pid {
            prompt.push_str(&format!("PID: {}\n", pid));
        }
        if let Some(host) = &target.host {
            prompt.push_str(&format!("Host: {}\n", host));
        }

        let tools = self.registry.get_all_definitions();
        if !tools.is_empty() {
            prompt.push_str("\nAvailable tools:\n");
            for tool in &tools {
                prompt.push_str(&format!(
                    "- {}: {} (risk: {:?}, approval: {})\n",
                    tool.name, tool.description, tool.risk_level, tool.requires_approval
                ));
            }
        }

        prompt.push_str(
            "\nTo call a tool, respond with a JSON object: {\"tool\": \"tool_name\", \"args\": {...}}",
        );
        prompt.push_str(
            "\nWhen done scanning, respond with: \"Scan complete. Final report:\" followed by your findings.",
        );
        prompt.push_str(
            "\nYou can also respond with observations, questions, or analysis without calling a tool.",
        );

        prompt
    }

    fn build_messages(&self, ctx: &AgentContext) -> Vec<serde_json::Value> {
        ctx.get_messages_with_system()
    }

    fn parse_tool_call(&self, response: &str) -> Option<ToolCallRequest> {
        let trimmed = response.trim();

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(tool_name) = json.get("tool").and_then(|v| v.as_str()) {
                let args = json.get("args").cloned().unwrap_or(serde_json::json!({}));
                return Some(ToolCallRequest {
                    name: tool_name.to_string(),
                    arguments: args,
                });
            }
        }

        if let Some(json_str) = extract_json_block(trimmed) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                if let Some(tool_name) = json.get("tool").and_then(|v| v.as_str()) {
                    let args = json.get("args").cloned().unwrap_or(serde_json::json!({}));
                    return Some(ToolCallRequest {
                        name: tool_name.to_string(),
                        arguments: args,
                    });
                }
            }
        }

        None
    }

    pub async fn stop(&self) {
        self.set_status(AgentStatus::Stopped).await;
    }

    async fn set_status(&self, s: AgentStatus) {
        let mut status = self.status.write().await;
        *status = s;
    }
}

struct ToolCallRequest {
    name: String,
    arguments: serde_json::Value,
}

fn extract_json_block(text: &str) -> Option<String> {
    if let Some(start) = text.find("```json") {
        let start = start + 7;
        if let Some(end) = text[start..].find("```") {
            return Some(text[start..start + end].trim().to_string());
        }
    }
    if let Some(start) = text.find("```") {
        let start = start + 3;
        if let Some(end) = text[start..].find("```") {
            return Some(text[start..start + end].trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tool_call_pure_json() {
        let runner = ToolUseRunner::new(
            Arc::new(MockProvider),
            Arc::new(ToolRegistry::new()),
            "test-model",
            "test prompt",
            Arc::new(SafetyChecker::new_allowing(true)),
        );
        let json = r#"{"tool": "read_memory", "args": {"address": "0x1234", "size": 1024}}"#;
        let result = runner.parse_tool_call(json);
        assert!(result.is_some());
        let call = result.unwrap();
        assert_eq!(call.name, "read_memory");
        assert_eq!(call.arguments["address"], "0x1234");
    }

    #[test]
    fn test_parse_tool_call_code_fence() {
        let runner = ToolUseRunner::new(
            Arc::new(MockProvider),
            Arc::new(ToolRegistry::new()),
            "test-model",
            "test prompt",
            Arc::new(SafetyChecker::new_allowing(true)),
        );
        let response = r#"I'll check the memory now.
```json
{"tool": "read_memory", "args": {"address": "0x5678"}}
```"#;
        let result = runner.parse_tool_call(response);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "read_memory");
    }

    #[test]
    fn test_parse_tool_call_not_a_tool() {
        let runner = ToolUseRunner::new(
            Arc::new(MockProvider),
            Arc::new(ToolRegistry::new()),
            "test-model",
            "test prompt",
            Arc::new(SafetyChecker::new_allowing(true)),
        );
        let response = "I think this looks like a buffer overflow.";
        let result = runner.parse_tool_call(response);
        assert!(result.is_none());
    }

    use async_trait::async_trait;
    use vest_core::traits::LlmProvider;

    struct MockProvider;

    #[async_trait]
    impl LlmProvider for MockProvider {
        async fn chat(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            Ok(r#"{"tool": "read_memory", "args": {"address": "0x1000"}}"#.into())
        }
        async fn chat_stream(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            Ok("streamed".into())
        }
        async fn list_models(&self) -> Result<Vec<String>, VestError> {
            Ok(vec!["test-model".into()])
        }
        async fn check_model(&self, _model: &str) -> Result<bool, VestError> {
            Ok(true)
        }
        async fn embed(&self, _text: &str, _model: &str) -> Result<Vec<f32>, VestError> {
            Ok(vec![0.0])
        }
    }
}
