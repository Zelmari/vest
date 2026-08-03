use crate::context::AgentContext;
use crate::interactive_approval::prompt_tty_one_shot_allow;
use crate::policy::NormalisedToolCall;
use crate::safety::SafetyChecker;
use crate::tool_registry::ToolRegistry;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use vest_core::error::VestError;
use vest_core::new_id;
use vest_core::traits::{AgentStatus, LlmProvider};
use vest_core::types::{Finding, FindingStatus, Severity, Target, VulnerabilityClass};
use vest_core::{ApprovalDecision, DataEgressClass, ToolEffect};

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

                        // Hot path (K5b): authorise → execute_authorised → filter_for_model.
                        // `requires_approval` is UX-only and must never skip the policy engine.
                        let (effect, egress_class) = match self.registry.get_tool(tool_name) {
                            Some(registered) => (
                                registered.definition.effect,
                                registered.definition.egress_class,
                            ),
                            None => (ToolEffect::Unknown, DataEgressClass::Prohibited),
                        };
                        let normalised = NormalisedToolCall::from_parts(
                            tool_name,
                            effect,
                            egress_class,
                            &tool_call.arguments,
                        );
                        let auth_ctx = self.safety.auth_context();
                        let approval = match self.safety.policy().authorise(&auth_ctx, &normalised)
                        {
                            Ok(cap) => cap,
                            Err(ApprovalDecision::RequireInteractive { reason })
                                if auth_ctx.interactive =>
                            {
                                if prompt_tty_one_shot_allow(&normalised, &reason) {
                                    self.safety
                                        .policy()
                                        .grant(&auth_ctx, &normalised, true)
                                        .await;
                                    match self.safety.policy().authorise(&auth_ctx, &normalised) {
                                        Ok(cap) => cap,
                                        Err(decision) => {
                                            let reason = match &decision {
                                                ApprovalDecision::Deny { reason } => reason.clone(),
                                                ApprovalDecision::RequireInteractive { reason } => {
                                                    reason.clone()
                                                }
                                                ApprovalDecision::Allow => String::new(),
                                            };
                                            ctx.add_message(
                                                "assistant",
                                                format!(
                                                    "Tool call rejected by policy: {}",
                                                    tool_name
                                                ),
                                            );
                                            ctx.add_message(
                                                "user",
                                                format!(
                                                    "The tool call '{}' was rejected by the policy engine: {}. Try a different approach.",
                                                    tool_name, reason
                                                ),
                                            );
                                            ctx.add_observation(format!(
                                                "Policy denied '{}': {}",
                                                tool_name, reason
                                            ));
                                            continue;
                                        }
                                    }
                                } else {
                                    ctx.add_message(
                                        "assistant",
                                        format!("Tool call rejected by policy: {}", tool_name),
                                    );
                                    ctx.add_message(
                                        "user",
                                        format!(
                                            "The tool call '{}' was rejected by the policy engine: {}. Try a different approach.",
                                            tool_name, reason
                                        ),
                                    );
                                    ctx.add_observation(format!(
                                        "Policy denied '{}': {}",
                                        tool_name, reason
                                    ));
                                    continue;
                                }
                            }
                            Err(decision) => {
                                let reason = match &decision {
                                    ApprovalDecision::Deny { reason } => reason.clone(),
                                    ApprovalDecision::RequireInteractive { reason } => {
                                        reason.clone()
                                    }
                                    ApprovalDecision::Allow => String::new(),
                                };
                                ctx.add_message(
                                    "assistant",
                                    format!("Tool call rejected by policy: {}", tool_name),
                                );
                                ctx.add_message(
                                        "user",
                                        format!(
                                            "The tool call '{}' was rejected by the policy engine: {}. Try a different approach.",
                                            tool_name, reason
                                        ),
                                    );
                                ctx.add_observation(format!(
                                    "Policy denied '{}': {}",
                                    tool_name, reason
                                ));
                                continue;
                            }
                        };

                        if let Err(e) = self.safety.check_rate_limit().await {
                            ctx.add_observation(format!("Rate limited: {}", e));
                            ctx.add_message(
                                "user",
                                format!("Rate limit reached: {}. Slow down and retry.", e),
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

                        match self.registry.execute_authorised(
                            tool_name,
                            tool_call.arguments.clone(),
                            &approval,
                            &auth_ctx,
                        ) {
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

                        let report_scan_complete = parse_report_json(&response)
                            .map(|report| {
                                let scan_complete = report.scan_complete.unwrap_or(false);
                                let findings = findings_from_report(report, target);
                                let count = findings.len();
                                for finding in findings {
                                    ctx.add_finding(finding);
                                }
                                if count > 0 {
                                    ctx.add_observation(format!(
                                        "Parsed {} finding(s) from final report",
                                        count
                                    ));
                                }
                                scan_complete
                            })
                            .unwrap_or(false);

                        let lower = response.to_lowercase();
                        if report_scan_complete
                            || lower.contains("scan complete")
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
            r#"
When done scanning, respond with a JSON report. Use severity values critical, high, medium, low, or info. Use vulnerability_class values in snake_case such as xss, sql_injection, buffer_overflow, command_injection, or unknown.
```json
{
  "scan_complete": true,
  "summary": "short human-readable summary",
  "findings": [
    {
      "title": "string",
      "description": "string",
      "vulnerability_class": "xss",
      "severity": "high",
      "confidence": 0.9,
      "cvss_score": 7.5,
      "cve_id": null,
      "cwe_id": "CWE-79",
      "evidence": {},
      "poc": null,
      "remediation": "string",
      "location": {},
      "tags": ["llm", "tooluse"],
      "metadata": {}
    }
  ]
}
```"#,
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

#[derive(Debug, Deserialize)]
struct LlmFindingReport {
    #[serde(default)]
    scan_complete: Option<bool>,
    #[serde(default)]
    findings: Vec<LlmFindingDraft>,
}

#[derive(Debug, Deserialize)]
struct LlmFindingDraft {
    title: String,
    description: String,
    vulnerability_class: String,
    severity: String,
    confidence: f64,
    evidence: serde_json::Value,
    location: serde_json::Value,
    #[serde(default)]
    cvss_score: Option<f64>,
    #[serde(default)]
    cve_id: Option<String>,
    #[serde(default)]
    cwe_id: Option<String>,
    #[serde(default)]
    poc: Option<String>,
    #[serde(default)]
    remediation: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    metadata: serde_json::Value,
}

#[cfg(test)]
fn parse_final_findings(response: &str, target: &Target) -> Vec<Finding> {
    parse_report_json(response)
        .map(|report| findings_from_report(report, target))
        .unwrap_or_default()
}

fn parse_report_json(response: &str) -> Option<LlmFindingReport> {
    parse_report_value(response.trim()).or_else(|| {
        extract_json_block(response).and_then(|json_str| parse_report_value(json_str.trim()))
    })
}

fn parse_report_value(json: &str) -> Option<LlmFindingReport> {
    let value = serde_json::from_str::<serde_json::Value>(json).ok()?;
    if value.is_array() {
        let findings = serde_json::from_value(value).ok()?;
        return Some(LlmFindingReport {
            scan_complete: None,
            findings,
        });
    }

    if value.get("findings").is_some() {
        return serde_json::from_value(value).ok();
    }

    None
}

fn findings_from_report(report: LlmFindingReport, target: &Target) -> Vec<Finding> {
    report
        .findings
        .into_iter()
        .filter_map(|draft| draft_to_finding(draft, target))
        .collect()
}

fn draft_to_finding(draft: LlmFindingDraft, target: &Target) -> Option<Finding> {
    if draft.title.trim().is_empty() || draft.description.trim().is_empty() {
        return None;
    }

    let severity = parse_severity(&draft.severity);
    let vulnerability_class = parse_vulnerability_class(&draft.vulnerability_class);
    let mut tags = draft.tags;
    if !tags.iter().any(|tag| tag == "llm") {
        tags.push("llm".to_string());
    }
    if !tags.iter().any(|tag| tag == "tooluse") {
        tags.push("tooluse".to_string());
    }

    let now = chrono::Utc::now();
    Some(Finding {
        id: new_id(),
        scan_id: String::new(),
        target_id: target.id.clone(),
        title: draft.title,
        description: draft.description,
        vulnerability_class,
        severity,
        confidence: draft.confidence.clamp(0.0, 1.0),
        status: FindingStatus::Open,
        cvss_score: draft
            .cvss_score
            .filter(|score| (0.0..=10.0).contains(score)),
        cve_id: draft.cve_id,
        cwe_id: draft.cwe_id,
        evidence: draft.evidence,
        poc: draft.poc,
        remediation: draft.remediation,
        location: draft.location,
        false_positive_history: None,
        tags,
        metadata: draft.metadata,
        discovered_at: now,
        updated_at: now,
    })
}

fn parse_severity(value: &str) -> Severity {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "informational" | "information" => Severity::Info,
        other => other.parse().unwrap_or(Severity::Info),
    }
}

fn parse_vulnerability_class(value: &str) -> VulnerabilityClass {
    let normalized = normalize_vulnerability_class(value);
    normalized.parse().unwrap_or(VulnerabilityClass::Unknown)
}

fn normalize_vulnerability_class(value: &str) -> String {
    let normalized = value.trim().replace(['-', ' '], "_").to_ascii_lowercase();

    match normalized.as_str() {
        "" => "unknown".to_string(),
        "sqli" | "sqlinjection" => "sql_injection".to_string(),
        "cross_site_scripting" | "cross_site_script" => "xss".to_string(),
        "commandinjection" => "command_injection".to_string(),
        "path_traversal" | "directory_traversal" => "path_traversal".to_string(),
        other => other.to_string(),
    }
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
    use vest_core::types::TargetType;

    fn make_target() -> Target {
        Target {
            id: "target-1".into(),
            name: "fixture.txt".into(),
            target_type: TargetType::File,
            path: Some("/tmp/fixture.txt".into()),
            url_str: None,
            pid: None,
            host: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

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

    #[test]
    fn test_parse_final_findings_pure_json() {
        let target = make_target();
        let response = r#"{
            "scan_complete": true,
            "summary": "one issue",
            "findings": [{
                "title": "Reflected XSS",
                "description": "Query parameter is reflected without encoding.",
                "vulnerability_class": "xss",
                "severity": "high",
                "confidence": 0.95,
                "cvss_score": 7.5,
                "cwe_id": "CWE-79",
                "evidence": {"parameter": "q"},
                "location": {"url": "/search?q=test"}
            }]
        }"#;

        let findings = parse_final_findings(response, &target);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target_id, "target-1");
        assert_eq!(findings[0].title, "Reflected XSS");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].vulnerability_class, VulnerabilityClass::XSS);
        assert!(findings[0].tags.contains(&"llm".to_string()));
        assert!(findings[0].tags.contains(&"tooluse".to_string()));
    }

    #[test]
    fn test_parse_final_findings_code_fence() {
        let target = make_target();
        let response = r#"Scan complete. Final report:
```json
{
  "scan_complete": true,
  "findings": [{
    "title": "SQL injection",
    "description": "Input reaches a query without parameters.",
    "vulnerability_class": "sql injection",
    "severity": "critical",
    "confidence": 2.0,
    "cvss_score": 11.0,
    "evidence": {"payload": "' OR 1=1--"},
    "location": {"url": "/login"}
  }]
}
```"#;

        let findings = parse_final_findings(response, &target);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].vulnerability_class,
            VulnerabilityClass::SQLInjection
        );
        assert_eq!(findings[0].confidence, 1.0);
        assert_eq!(findings[0].cvss_score, None);
    }

    #[test]
    fn test_parse_final_findings_empty_findings() {
        let findings = parse_final_findings(
            r#"{"scan_complete": true, "summary": "clean", "findings": []}"#,
            &make_target(),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_final_findings_normalizes_aliases() {
        let findings = parse_final_findings(
            r#"[{
                "title": "Command injection",
                "description": "Shell metacharacters are accepted.",
                "vulnerability_class": "CommandInjection",
                "severity": "informational",
                "confidence": -0.5,
                "evidence": {"input": ";id"},
                "location": {"file": "app.rs"}
            }]"#,
            &make_target(),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].vulnerability_class,
            VulnerabilityClass::CommandInjection
        );
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].confidence, 0.0);
    }

    #[test]
    fn test_parse_final_findings_ignores_invalid_json() {
        let findings = parse_final_findings("Scan complete. I found one thing.", &make_target());
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_runner_returns_final_json_findings() {
        let runner = ToolUseRunner::new(
            Arc::new(FinalReportProvider),
            Arc::new(ToolRegistry::new()),
            "test-model",
            "test prompt",
            Arc::new(SafetyChecker::new_allowing(true)),
        )
        .with_max_iterations(1);

        let findings = runner.run(&make_target()).await.unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Hardcoded token");
        assert_eq!(findings[0].severity, Severity::Medium);
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

    struct FinalReportProvider;

    #[async_trait]
    impl LlmProvider for FinalReportProvider {
        async fn chat(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            Ok(r#"{
                "scan_complete": true,
                "summary": "one finding",
                "findings": [{
                    "title": "Hardcoded token",
                    "description": "A token-like value appears in source.",
                    "vulnerability_class": "unknown",
                    "severity": "medium",
                    "confidence": 0.8,
                    "evidence": {"key": "api_token"},
                    "location": {"file": "fixture.txt"}
                }]
            }"#
            .into())
        }

        async fn chat_stream(
            &self,
            _messages: &[serde_json::Value],
            _model: &str,
        ) -> Result<String, VestError> {
            self.chat(_messages, _model).await
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
