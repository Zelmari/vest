use std::sync::Arc;
use vest_core::error::VestError;
use vest_core::traits::LlmProvider;
use vest_core::types::Target;

pub struct Planner {
    provider: Option<Arc<dyn LlmProvider>>,
    model: String,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub tasks: Vec<Task>,
    pub reasoning: String,
}

#[derive(Debug, Clone)]
pub struct Task {
    pub description: String,
    pub category: TaskCategory,
    pub priority: TaskPriority,
    pub tools_needed: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCategory {
    Reconnaissance,
    Analysis,
    Exploitation,
    Validation,
    Reporting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl Planner {
    pub fn new() -> Self {
        Self {
            provider: None,
            model: "default".into(),
        }
    }

    pub fn with_provider(
        mut self,
        provider: Arc<dyn LlmProvider>,
        model: impl Into<String>,
    ) -> Self {
        self.provider = Some(provider);
        self.model = model.into();
        self
    }

    /// Generate a scan plan for the target
    pub async fn plan(&self, target: &Target) -> Result<Vec<String>, VestError> {
        if let Some(provider) = &self.provider {
            self.llm_plan(provider, target).await
        } else {
            Ok(self.rule_based_plan(target))
        }
    }

    /// LLM-based planning
    async fn llm_plan(
        &self,
        provider: &Arc<dyn LlmProvider>,
        target: &Target,
    ) -> Result<Vec<String>, VestError> {
        let prompt = format!(
            "You are a security testing planner. Analyze this target and create a step-by-step plan.\n\
             \nTarget: {}\nType: {:?}\n\
             Path: {}\nURL: {}\nPID: {}\nHost: {}\n\
             \nGenerate 3-7 concrete, actionable steps for vulnerability discovery.\n\
             Each step must be a specific action (e.g., 'Scan TCP port 8080 for open services', not 'Do reconnaissance').\n\
             \nRespond with a JSON array of strings. Example:\n\
             [\"Step 1\", \"Step 2\", \"Step 3\"]",
            target.name,
            target.target_type,
            target.path.as_deref().unwrap_or("none"),
            target.url_str.as_deref().unwrap_or("none"),
            target.pid.map(|p| p.to_string()).unwrap_or_else(|| "none".into()),
            target.host.as_deref().unwrap_or("none"),
        );

        let messages = vec![
            serde_json::json!({"role": "system", "content": "You are a planning agent. Respond with valid JSON only."}),
            serde_json::json!({"role": "user", "content": prompt}),
        ];

        let response = provider.chat(&messages, &self.model).await?;

        // Parse JSON array from response
        if let Some(json_str) = self.extract_json_array(&response) {
            if let Ok(tasks) = serde_json::from_str::<Vec<String>>(&json_str) {
                if !tasks.is_empty() {
                    return Ok(tasks);
                }
            }
        }

        // Fallback
        Ok(self.rule_based_plan(target))
    }

    /// Rule-based fallback planning
    pub fn rule_based_plan(&self, target: &Target) -> Vec<String> {
        match target.target_type {
            vest_core::types::TargetType::Web => vec![
                format!("Crawl {} to discover endpoints", target.name),
                "Scan discovered endpoints for XSS vulnerabilities".into(),
                "Test authentication endpoints for bypass".into(),
                "Check API endpoints for IDOR and privilege escalation".into(),
                "Scan for common misconfigurations (CORS, CSP, headers)".into(),
            ],
            vest_core::types::TargetType::Binary => vec![
                format!("Parse {} binary headers and sections", target.name),
                "Check security mitigations (ASLR, NX, canaries)".into(),
                "Scan for dangerous function calls (sink catalog)".into(),
                "Disassemble high-risk functions".into(),
                "Search for potential ROP gadgets".into(),
            ],
            vest_core::types::TargetType::Process => vec![
                format!(
                    "Attach to process {} and enumerate memory regions",
                    target.name
                ),
                "Scan for writable+executable memory regions".into(),
                "Search for unprotected sensitive data in memory".into(),
                "Check for injected code or hooks".into(),
                "Analyze network connections for protocol vulnerabilities".into(),
            ],
            vest_core::types::TargetType::Network => vec![
                format!("Scan {} for open ports", target.name),
                "Identify running services and versions".into(),
                "Test discovered services for known vulnerabilities".into(),
                "Fuzz custom protocols for crashes".into(),
            ],
            vest_core::types::TargetType::Browser => vec![
                format!("Navigate to {} and inspect page structure", target.name),
                "Intercept WebSocket traffic for protocol analysis".into(),
                "Inspect LocalStorage/IndexedDB for sensitive data".into(),
                "Test client-side validation bypasses".into(),
                "Analyze WebAssembly modules for vulnerabilities".into(),
            ],
            vest_core::types::TargetType::File => vec![
                format!("Identify file format of {}", target.name),
                "Parse and validate file structure".into(),
                "Fuzz file parsing with malformed inputs".into(),
                "Extract and analyze embedded content".into(),
            ],
        }
    }

    /// Generate a full plan structure (with categories and priorities)
    pub fn generate_full_plan(&self, target: &Target) -> Plan {
        let tasks = self.rule_based_plan(target);
        let steps: Vec<Task> = tasks
            .into_iter()
            .enumerate()
            .map(|(i, desc)| {
                let (category, priority) = match i {
                    0 => (TaskCategory::Reconnaissance, TaskPriority::Critical),
                    1..=2 => (TaskCategory::Analysis, TaskPriority::High),
                    _ => (TaskCategory::Analysis, TaskPriority::Medium),
                };
                Task {
                    description: desc,
                    category,
                    priority,
                    tools_needed: vec![],
                }
            })
            .collect();

        Plan {
            tasks: steps,
            reasoning: format!(
                "Rule-based plan for {} target: {}",
                target.target_type, target.name
            ),
        }
    }

    fn extract_json_array(&self, text: &str) -> Option<String> {
        let trimmed = text.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            return Some(trimmed.to_string());
        }
        if let Some(start) = trimmed.find("```json") {
            let start = start + 7;
            if let Some(end) = trimmed[start..].find("```") {
                let inner = trimmed[start..start + end].trim();
                if inner.starts_with('[') {
                    return Some(inner.to_string());
                }
            }
        }
        None
    }
}

impl Default for Planner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_rule_based_plan_web_target() {
        let planner = Planner::new();
        let target = Target {
            id: "t1".into(),
            name: "example.com".into(),
            target_type: vest_core::types::TargetType::Web,
            path: None,
            url_str: Some("https://example.com".into()),
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let plan = planner.rule_based_plan(&target);
        assert!(!plan.is_empty());
        assert!(plan[0].contains("example.com"));
    }

    #[test]
    fn test_rule_based_plan_binary_target() {
        let planner = Planner::new();
        let target = Target {
            id: "t1".into(),
            name: "game.exe".into(),
            target_type: vest_core::types::TargetType::Binary,
            path: Some("game.exe".into()),
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let plan = planner.rule_based_plan(&target);
        assert!(!plan.is_empty());
        assert!(plan.iter().any(|t| t.contains("ASLR")));
    }

    #[test]
    fn test_rule_based_plan_process_target() {
        let planner = Planner::new();
        let target = Target {
            id: "t1".into(),
            name: "game.exe".into(),
            target_type: vest_core::types::TargetType::Process,
            path: None,
            url_str: None,
            pid: Some(12345),
            host: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let plan = planner.rule_based_plan(&target);
        assert!(plan.iter().any(|t| t.contains("memory")));
    }

    #[test]
    fn test_generate_full_plan() {
        let planner = Planner::new();
        let target = Target {
            id: "t1".into(),
            name: "test.com".into(),
            target_type: vest_core::types::TargetType::Web,
            path: None,
            url_str: Some("test.com".into()),
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let plan = planner.generate_full_plan(&target);
        assert!(!plan.tasks.is_empty());
        assert!(!plan.reasoning.is_empty());
    }
}
