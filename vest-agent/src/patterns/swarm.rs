use crate::patterns::tooluse::ToolUseRunner;
use crate::safety::SafetyChecker;
use crate::tool_registry::ToolRegistry;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use vest_core::error::VestError;
use vest_core::traits::{AgentStatus, LlmProvider};
use vest_core::types::{Finding, MergeStrategy, Target};

#[derive(Debug, Clone)]
pub struct SwarmAgentConfig {
    pub name: String,
    pub role: String,
    pub vulnerability_classes: Vec<String>,
    pub system_prompt: String,
}

impl SwarmAgentConfig {
    pub fn memory_hunter() -> Self {
        Self {
            name: "memory_hunter".into(),
            role: "Memory Hunter".into(),
            vulnerability_classes: vec!["buffer_overflow".into(), "use_after_free".into(), "double_free".into(), "integer_overflow".into(), "format_string".into(), "stack_canary_bypass".into(), "rop_gadget".into()],
            system_prompt: "You are a memory corruption hunter. Focus on finding buffer overflows, use-after-free, double free, integer overflow, format strings, and stack canary bypass vulnerabilities. Use memory scanning and disassembly tools.".into(),
        }
    }

    pub fn web_hunter() -> Self {
        Self {
            name: "web_hunter".into(),
            role: "Web Hunter".into(),
            vulnerability_classes: vec!["xss".into(), "sql_injection".into(), "command_injection".into(), "ssti".into(), "ssrf".into(), "xxe".into(), "path_traversal".into(), "idor".into(), "auth_bypass".into(), "csrf".into(), "insecure_deserialization".into(), "jwt_attack".into(), "cors".into(), "clickjacking".into()],
            system_prompt: "You are a web vulnerability hunter. Focus on finding XSS, SQL injection, command injection, SSTI, SSRF, XXE, path traversal, IDOR, auth bypass, CSRF, and other OWASP Top 10 vulnerabilities. Use HTTP scanning and browser automation tools.".into(),
        }
    }

    pub fn binary_hunter() -> Self {
        Self {
            name: "binary_hunter".into(),
            role: "Binary Hunter".into(),
            vulnerability_classes: vec!["format_string".into(), "rop_gadget".into(), "aslr_bypass".into(), "dep_bypass".into(), "seh_overwrite".into(), "import_table_hooking".into(), "dll_injection".into(), "code_cave".into()],
            system_prompt: "You are a binary vulnerability hunter. Focus on finding format strings, ROP gadgets, ASLR/DEP bypass, SEH overwrites, import table hooking, DLL injection, and code caves. Use disassembly and binary analysis tools.".into(),
        }
    }

    pub fn auth_logic_hunter() -> Self {
        Self {
            name: "auth_logic_hunter".into(),
            role: "Auth & Logic Hunter".into(),
            vulnerability_classes: vec!["auth_bypass".into(), "idor".into(), "jwt_attack".into(), "race_condition".into()],
            system_prompt: "You are an authentication and business logic hunter. Focus on auth bypass, IDOR, JWT attacks, race conditions, and logical flaws in multi-step processes. Test with different roles and privileges.".into(),
        }
    }
}

pub struct SwarmRunner {
    provider: Arc<dyn LlmProvider>,
    registry: Arc<ToolRegistry>,
    model: String,
    safety: Arc<SafetyChecker>,
    agent_configs: Vec<SwarmAgentConfig>,
    parallelism: usize,
    max_iterations_per_agent: u32,
    merge_strategy: MergeStrategy,
    diversity_seeds: usize,
    status: RwLock<AgentStatus>,
}

impl SwarmRunner {
    pub fn new(
        provider: Arc<dyn LlmProvider>,
        registry: Arc<ToolRegistry>,
        model: impl Into<String>,
        safety: Arc<SafetyChecker>,
        agent_configs: Vec<SwarmAgentConfig>,
    ) -> Self {
        Self {
            provider,
            registry,
            model: model.into(),
            safety,
            agent_configs,
            parallelism: 8,
            max_iterations_per_agent: 50,
            merge_strategy: MergeStrategy::Voting,
            diversity_seeds: 1,
            status: RwLock::new(AgentStatus::Idle),
        }
    }

    pub fn with_parallelism(mut self, n: usize) -> Self {
        self.parallelism = n;
        self
    }

    pub fn with_merge_strategy(mut self, s: MergeStrategy) -> Self {
        self.merge_strategy = s;
        self
    }

    pub fn with_diversity_seeds(mut self, n: usize) -> Self {
        self.diversity_seeds = n;
        self
    }

    pub fn with_max_iterations_per_agent(mut self, max: u32) -> Self {
        self.max_iterations_per_agent = max;
        self
    }

    pub fn default_agents() -> Vec<SwarmAgentConfig> {
        vec![
            SwarmAgentConfig::memory_hunter(),
            SwarmAgentConfig::web_hunter(),
            SwarmAgentConfig::binary_hunter(),
            SwarmAgentConfig::auth_logic_hunter(),
        ]
    }

    pub async fn run(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        self.set_status(AgentStatus::Running).await;

        let mut all_tasks: Vec<(String, String)> = Vec::new();
        for config in &self.agent_configs {
            for seed in 0..self.diversity_seeds {
                let seed_prompt = if seed > 0 {
                    format!("{}\n\nDiversity seed {}. Try a different approach than previous iterations. Focus on different code paths, different parameters, different perspectives.", config.system_prompt, seed)
                } else {
                    config.system_prompt.clone()
                };
                all_tasks.push((config.name.clone(), seed_prompt));
            }
        }

        let parallelism = self.parallelism;
        let max_iter = self.max_iterations_per_agent;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(parallelism));
        let findings_arc = Arc::new(RwLock::new(Vec::new()));
        let mut join_set = JoinSet::new();

        for (_agent_name, prompt) in all_tasks {
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

            join_set.spawn(async move {
                let _permit = permit.acquire().await.unwrap();

                let agent = ToolUseRunner::new(provider, registry, model, prompt, safety)
                    .with_max_iterations(max_iter);

                let result = agent.run(&target).await;
                if let Ok(mut new_findings) = result {
                    let mut all = findings.write().await;
                    all.append(&mut new_findings);
                }
            });
        }

        while (join_set.join_next().await).is_some() {}

        let all_findings = findings_arc.read().await.clone();

        let merged = self.merge_findings(&all_findings);

        self.set_status(AgentStatus::Completed).await;
        Ok(merged)
    }

    fn merge_findings(&self, findings: &[Finding]) -> Vec<Finding> {
        match self.merge_strategy {
            MergeStrategy::Voting => self.merge_by_voting(findings),
            MergeStrategy::Union => self.merge_by_union(findings),
            MergeStrategy::Strict => self.merge_by_strict(findings),
        }
    }

    fn merge_by_voting(&self, findings: &[Finding]) -> Vec<Finding> {
        let mut dedup: Vec<Finding> = Vec::new();
        let mut seen: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

        for f in findings {
            let key = make_finding_key(f);
            *seen.entry(key).or_insert(0) += 1;
        }

        let total_agents = (self.agent_configs.len() * self.diversity_seeds).max(1);
        let threshold = ((total_agents as f64) * 0.4).ceil().max(1.0) as u32;

        for f in findings {
            let key = make_finding_key(f);
            if let Some(&count) = seen.get(&key) {
                if count >= threshold
                    && !dedup.iter().any(|d| {
                        d.title == f.title && d.vulnerability_class == f.vulnerability_class
                    })
                {
                    dedup.push(f.clone());
                }
            }
        }
        dedup
    }

    fn merge_by_union(&self, findings: &[Finding]) -> Vec<Finding> {
        let mut dedup: Vec<Finding> = Vec::new();
        for f in findings {
            if !dedup
                .iter()
                .any(|d| d.title == f.title && d.vulnerability_class == f.vulnerability_class)
            {
                dedup.push(f.clone());
            }
        }
        dedup
    }

    fn merge_by_strict(&self, findings: &[Finding]) -> Vec<Finding> {
        let mut dedup: Vec<Finding> = Vec::new();
        let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

        for f in findings {
            let key = make_finding_key(f);
            *counts.entry(key).or_insert(0) += 1;
        }

        let total_agents = (self.agent_configs.len() * self.diversity_seeds).max(1);
        let threshold = ((total_agents as f64) * 0.7).ceil().max(2.0) as u32;

        for f in findings {
            let key = make_finding_key(f);
            if counts.get(&key).copied().unwrap_or(0) >= threshold
                && !dedup
                    .iter()
                    .any(|d| d.title == f.title && d.vulnerability_class == f.vulnerability_class)
            {
                dedup.push(f.clone());
            }
        }
        dedup
    }

    pub async fn stop(&self) {
        self.set_status(AgentStatus::Stopped).await;
    }

    async fn set_status(&self, s: AgentStatus) {
        let mut status = self.status.write().await;
        *status = s;
    }
}

fn make_finding_key(f: &vest_core::types::Finding) -> String {
    let title_part = &f.title[..f.title.len().min(50)];
    format!("{}:{}", title_part, f.vulnerability_class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vest_core::types::Severity;

    #[test]
    fn test_default_agents_created() {
        let agents = SwarmRunner::default_agents();
        assert!(!agents.is_empty());
        assert!(agents.iter().any(|a| a.name == "memory_hunter"));
        assert!(agents.iter().any(|a| a.name == "web_hunter"));
    }

    #[test]
    fn test_memory_hunter_config() {
        let config = SwarmAgentConfig::memory_hunter();
        assert_eq!(config.name, "memory_hunter");
        assert!(!config.vulnerability_classes.is_empty());
        assert!(config
            .vulnerability_classes
            .contains(&"buffer_overflow".to_string()));
    }

    #[test]
    fn test_web_hunter_config() {
        let config = SwarmAgentConfig::web_hunter();
        assert_eq!(config.name, "web_hunter");
        assert!(config.vulnerability_classes.contains(&"xss".to_string()));
        assert!(config
            .vulnerability_classes
            .contains(&"sql_injection".to_string()));
    }

    #[test]
    fn test_merge_by_union_dedup() {
        let runner = SwarmRunner::new(
            Arc::new(MockProvider),
            Arc::new(ToolRegistry::new()),
            "test",
            Arc::new(SafetyChecker::new_allowing(true)),
            SwarmRunner::default_agents(),
        );
        let f1 = Finding {
            id: "1".into(),
            scan_id: "".into(),
            target_id: "".into(),
            title: "XSS in search".into(),
            description: "".into(),
            vulnerability_class: vest_core::types::VulnerabilityClass::XSS,
            severity: Severity::High,
            confidence: 0.9,
            status: vest_core::types::FindingStatus::Open,
            cvss_score: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!({}),
            poc: None,
            remediation: None,
            location: serde_json::json!({}),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let f2 = f1.clone();
        let f3 = Finding {
            id: "3".into(),
            title: "SQLi in login".into(),
            vulnerability_class: vest_core::types::VulnerabilityClass::SQLInjection,
            ..f1.clone()
        };

        let merged = runner.merge_by_union(&[f1, f2, f3]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_merge_by_voting_single_agent() {
        let runner = SwarmRunner::new(
            Arc::new(MockProvider),
            Arc::new(ToolRegistry::new()),
            "test",
            Arc::new(SafetyChecker::new_allowing(true)),
            vec![SwarmAgentConfig::memory_hunter()],
        );
        let f1 = Finding {
            id: "1".into(),
            scan_id: "".into(),
            target_id: "".into(),
            title: "Buffer Overflow".into(),
            description: "".into(),
            vulnerability_class: vest_core::types::VulnerabilityClass::BufferOverflow,
            severity: Severity::Critical,
            confidence: 0.95,
            status: vest_core::types::FindingStatus::Open,
            cvss_score: None,
            cve_id: None,
            cwe_id: None,
            evidence: serde_json::json!({}),
            poc: None,
            remediation: None,
            location: serde_json::json!({}),
            false_positive_history: None,
            tags: vec![],
            metadata: serde_json::json!({}),
            discovered_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let merged = runner.merge_by_voting(&[f1]);
        assert_eq!(merged.len(), 1);
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
            Ok("No findings".into())
        }
        async fn chat_stream(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            Ok("".into())
        }
        async fn list_models(&self) -> Result<Vec<String>, VestError> {
            Ok(vec![])
        }
        async fn check_model(&self, _model: &str) -> Result<bool, VestError> {
            Ok(true)
        }
        async fn embed(&self, _text: &str, _model: &str) -> Result<Vec<f32>, VestError> {
            Ok(vec![])
        }
    }
}
