use crate::patterns::tooluse::ToolUseRunner;
use crate::safety::SafetyChecker;
use crate::tool_registry::ToolRegistry;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use vest_core::error::VestError;
use vest_core::traits::{AgentStatus, LlmProvider};
use vest_core::types::{Finding, Target};

pub struct HierarchicalRunner {
    provider: Arc<dyn LlmProvider>,
    registry: Arc<ToolRegistry>,
    model: String,
    safety: Arc<SafetyChecker>,
    max_depth: u32,
    max_children: usize,
    max_iterations_per_child: u32,
    status: RwLock<AgentStatus>,
}

impl HierarchicalRunner {
    pub fn new(
        provider: Arc<dyn LlmProvider>,
        registry: Arc<ToolRegistry>,
        model: impl Into<String>,
        safety: Arc<SafetyChecker>,
    ) -> Self {
        Self {
            provider,
            registry,
            model: model.into(),
            safety,
            max_depth: 3,
            max_children: 10,
            max_iterations_per_child: 30,
            status: RwLock::new(AgentStatus::Idle),
        }
    }

    pub fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn with_max_children(mut self, max: usize) -> Self {
        self.max_children = max;
        self
    }

    pub fn with_max_iterations_per_child(mut self, max: u32) -> Self {
        self.max_iterations_per_child = max;
        self
    }

    pub async fn run(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        self.set_status(AgentStatus::Running).await;

        let plan = self.plan_strategy(target).await?;
        tracing::info!("Hierarchical plan: {} subtasks", plan.len());

        let max_children = self.max_children;
        let max_iter = self.max_iterations_per_child;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_children));
        let findings_arc = Arc::new(RwLock::new(Vec::new()));
        let mut join_set = JoinSet::new();

        for subtask in &plan {
            if *self.status.read().await == AgentStatus::Stopped {
                break;
            }

            let provider = Arc::clone(&self.provider);
            let registry = Arc::clone(&self.registry);
            let model = self.model.clone();
            let safety = Arc::clone(&self.safety);
            let findings = Arc::clone(&findings_arc);
            let permit = Arc::clone(&semaphore);
            let target = target.clone();
            let subtask = subtask.clone();

            join_set.spawn(async move {
                let _permit = permit.acquire().await.unwrap();

                let agent = ToolUseRunner::new(
                    provider,
                    registry,
                    model,
                    format!(
                        "You are a specialized security testing agent working on a subtask of a larger scan.\n\
                         Task: {}\n\
                         Complete this subtask thoroughly. When done, report your specific findings.",
                        subtask
                    ),
                    safety,
                ).with_max_iterations(max_iter);

                let result = agent.run(&target).await;
                if let Ok(mut new_findings) = result {
                    let mut all = findings.write().await;
                    all.append(&mut new_findings);
                }
            });
        }

        while (join_set.join_next().await).is_some() {}

        let all_findings = findings_arc.read().await.clone();
        self.set_status(AgentStatus::Completed).await;
        Ok(all_findings)
    }

    async fn plan_strategy(&self, target: &Target) -> Result<Vec<String>, VestError> {
        let plan_prompt = format!(
            "You are a security testing strategist. Analyze this target and create a plan.\n\
             Target: {}\nType: {:?}\n\
             \nDecompose the scanning into specific, actionable subtasks. Each subtask should be:\n\
             1. Specific to one attack surface or vulnerability class\n\
             2. Independent (can run in parallel with other subtasks)\n\
             3. Actionable (describe exactly what to look for)\n\
             \nProvide up to 5 subtasks as a JSON array of strings. Example:\n\
             [\"Scan the login flow for auth bypass vulnerabilities\", \"Analyze the binary for buffer overflow in the network packet handler\"]\
             \nRespond with ONLY the JSON array, no other text.",
            target.name, target.target_type
        );

        let messages = vec![
            serde_json::json!({"role": "system", "content": "You are a planning agent. Respond with JSON only."}),
            serde_json::json!({"role": "user", "content": plan_prompt}),
        ];

        let response = self.provider.chat(&messages, &self.model).await?;

        if let Some(json_str) = extract_json_array(&response) {
            if let Ok(tasks) = serde_json::from_str::<Vec<String>>(&json_str) {
                return Ok(tasks);
            }
        }

        let fallback = match target.target_type {
            vest_core::types::TargetType::Web => vec![
                "Scan for XSS and injection vulnerabilities".into(),
                "Test authentication flow for bypass".into(),
                "Check API endpoints for IDOR and CSRF".into(),
                "Scan for misconfigurations (CORS, headers)".into(),
            ],
            vest_core::types::TargetType::Binary => vec![
                "Analyze binary for buffer overflows".into(),
                "Check security mitigations (ASLR, NX, canaries)".into(),
                "Search for dangerous function calls".into(),
                "Find ROP gadgets".into(),
            ],
            _ => vec![
                "Reconnaissance of attack surface".into(),
                "Vulnerability analysis".into(),
                "Validation of findings".into(),
            ],
        };
        Ok(fallback)
    }

    pub async fn stop(&self) {
        self.set_status(AgentStatus::Stopped).await;
    }

    async fn set_status(&self, s: AgentStatus) {
        let mut status = self.status.write().await;
        *status = s;
    }
}

fn extract_json_array(text: &str) -> Option<String> {
    let trimmed = text.trim();

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        return Some(trimmed.to_string());
    }

    if let Some(start) = trimmed.find("```json") {
        let start = start + 7;
        if let Some(end) = trimmed[start..].find("```") {
            return Some(trimmed[start..start + end].trim().to_string());
        }
    }
    if let Some(start) = trimmed.find("```") {
        let start = start + 3;
        if let Some(end) = trimmed[start..].find("```") {
            let content = trimmed[start..start + end].trim();
            if content.starts_with('[') {
                return Some(content.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_array_direct() {
        let text = r#"["task1", "task2"]"#;
        let result = extract_json_array(text);
        assert_eq!(result, Some(r#"["task1", "task2"]"#.into()));
    }

    #[test]
    fn test_extract_json_array_code_fence() {
        let text = r#"Here's the plan:
```json
["Scan login", "Test API"]
```"#;
        let result = extract_json_array(text);
        assert!(result.is_some());
    }

    #[test]
    fn test_extract_json_array_not_array() {
        let text = "This is not a JSON array";
        let result = extract_json_array(text);
        assert!(result.is_none());
    }
}
