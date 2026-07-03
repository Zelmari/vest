use serde::{Deserialize, Serialize};
use vest_core::types::{Finding, Target};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    pub requires_approval: bool,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    ReadOnly,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    pub target: Option<Target>,
    pub findings: Vec<Finding>,
    pub observations: Vec<String>,
    pub conversation_history: Vec<serde_json::Value>,
    pub tool_definitions: Vec<ToolDefinition>,
    pub iteration_count: u32,
    pub max_iterations: u32,
    pub system_prompt: String,
}

impl AgentContext {
    pub fn new() -> Self {
        Self {
            target: None,
            findings: Vec::new(),
            observations: Vec::new(),
            conversation_history: Vec::new(),
            tool_definitions: Vec::new(),
            iteration_count: 0,
            max_iterations: 200,
            system_prompt: String::new(),
        }
    }

    pub fn with_target(mut self, target: Target) -> Self {
        self.target = Some(target);
        self
    }

    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = prompt.into();
        self
    }

    pub fn with_max_iterations(mut self, max: u32) -> Self {
        self.max_iterations = max;
        self
    }

    pub fn add_tool(&mut self, tool: ToolDefinition) {
        self.tool_definitions.push(tool);
    }

    pub fn add_message(&mut self, role: impl Into<String>, content: impl Into<String>) {
        self.conversation_history.push(serde_json::json!({
            "role": role.into(),
            "content": content.into(),
        }));
    }

    pub fn get_messages_with_system(&self) -> Vec<serde_json::Value> {
        let mut msgs = Vec::new();
        if !self.system_prompt.is_empty() {
            msgs.push(serde_json::json!({
                "role": "system",
                "content": self.system_prompt,
            }));
        }
        msgs.extend(self.conversation_history.clone());
        msgs
    }

    pub fn increment_iteration(&mut self) -> bool {
        self.iteration_count += 1;
        self.iteration_count <= self.max_iterations
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn add_observation(&mut self, obs: impl Into<String>) {
        self.observations.push(obs.into());
    }

    pub fn has_tool(&self, name: &str) -> bool {
        self.tool_definitions.iter().any(|t| t.name == name)
    }
}

impl Default for AgentContext {
    fn default() -> Self {
        Self::new()
    }
}
