use crate::patterns::tooluse::ToolUseRunner;
use crate::safety::SafetyChecker;
use crate::tool_registry::ToolRegistry;
use std::sync::Arc;
use tokio::sync::RwLock;
use vest_core::error::VestError;
use vest_core::traits::{AgentStatus, LlmProvider};
use vest_core::types::{Finding, Target};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelinePhase {
    Reconnaissance,
    SurfaceAnalysis,
    VulnerabilityHunting,
    Exploitation,
    Validation,
    Reporting,
}

impl PipelinePhase {
    pub fn phases(include_exploit: bool) -> Vec<PipelinePhase> {
        let mut phases = vec![
            PipelinePhase::Reconnaissance,
            PipelinePhase::SurfaceAnalysis,
            PipelinePhase::VulnerabilityHunting,
        ];
        if include_exploit {
            phases.push(PipelinePhase::Exploitation);
        }
        phases.push(PipelinePhase::Validation);
        phases.push(PipelinePhase::Reporting);
        phases
    }

    pub fn name(&self) -> &str {
        match self {
            PipelinePhase::Reconnaissance => "Reconnaissance",
            PipelinePhase::SurfaceAnalysis => "Surface Analysis",
            PipelinePhase::VulnerabilityHunting => "Vulnerability Hunting",
            PipelinePhase::Exploitation => "Exploitation",
            PipelinePhase::Validation => "Validation",
            PipelinePhase::Reporting => "Reporting",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            PipelinePhase::Reconnaissance => {
                "Discover attack surface: open ports, loaded modules, API endpoints, file formats"
            }
            PipelinePhase::SurfaceAnalysis => {
                "Analyze each attack surface for potential vulnerability classes"
            }
            PipelinePhase::VulnerabilityHunting => {
                "Attempt detection with specialized tools for each surface+vuln class pair"
            }
            PipelinePhase::Exploitation => {
                "Attempt PoC exploitation for each confirmed vulnerability"
            }
            PipelinePhase::Validation => "Skeptical review of all findings. Challenge each one.",
            PipelinePhase::Reporting => "Compile findings, rank by severity, generate output",
        }
    }

    pub fn system_prompt(&self) -> &str {
        match self {
            PipelinePhase::Reconnaissance => {
                "You are a reconnaissance agent. Your job is to discover the attack surface of the target. \
                 Identify open ports, loaded modules, API endpoints, file formats, network protocols, and any \
                 other interfaces that could be attacked. Use available tools to probe the target. \
                 Be thorough - every undiscovered surface is a missed vulnerability."
            }
            PipelinePhase::SurfaceAnalysis => {
                "You are a surface analysis agent. For each attack surface discovered during reconnaissance, \
                 identify which vulnerability classes are potentially applicable. For example, a network port \
                 might be vulnerable to buffer overflows, while a web API might be vulnerable to XSS, SQLi, etc. \
                 Prioritize surfaces by risk: public-facing, handling untrusted input, processing complex formats."
            }
            PipelinePhase::VulnerabilityHunting => {
                "You are a vulnerability hunting agent. For each surface+vulnerability-class pair identified, \
                 use specialized tools to attempt actual detection. Look for concrete evidence: memory corruption, \
                 suspicious patterns, exploitable conditions. Report each finding with specific details: addresses, \
                 endpoints, parameters, payloads that trigger the condition."
            }
            PipelinePhase::Exploitation => {
                "You are an exploitation agent. For each confirmed vulnerability, attempt to develop a working \
                 proof-of-concept exploit. Verify that the vulnerability is actually exploitable. Test for impact: \
                 can you read memory? Write memory? Execute code? Access unauthorized data? Document exact steps."
            }
            PipelinePhase::Validation => {
                "You are a validation agent. Your job is to be SKEPTICAL of every finding. Challenge each one: \
                 Could this be a false positive? Is the evidence solid? Is the finding reproducible? \
                 Is the severity correct? Look for mitigating factors: auth guards, sandboxing, input validation \
                 we might have missed. Downgrade or reject findings that don't hold up. Only confirmed, reproducible \
                 findings with solid evidence should pass validation."
            }
            PipelinePhase::Reporting => {
                "You are a reporting agent. Compile all validated findings into a structured report. \
                 Rank by severity (Critical > High > Medium > Low > Info). For each finding, provide: \
                 title, description, vulnerability class, severity, CVSS score if applicable, CWE reference, \
                 evidence summary, reproduction steps, remediation recommendation. Note any false positives \
                 that were filtered out during validation."
            }
        }
    }
}

pub struct PipelineRunner {
    provider: Arc<dyn LlmProvider>,
    registry: Arc<ToolRegistry>,
    model: String,
    safety: Arc<SafetyChecker>,
    phases: Vec<PipelinePhase>,
    max_iterations_per_phase: u32,
    initial_findings: Vec<Finding>,
    status: RwLock<AgentStatus>,
}

impl PipelineRunner {
    pub fn new(
        provider: Arc<dyn LlmProvider>,
        registry: Arc<ToolRegistry>,
        model: impl Into<String>,
        safety: Arc<SafetyChecker>,
        include_exploit: bool,
    ) -> Self {
        Self {
            provider,
            registry,
            model: model.into(),
            safety,
            phases: PipelinePhase::phases(include_exploit),
            max_iterations_per_phase: 40,
            initial_findings: Vec::new(),
            status: RwLock::new(AgentStatus::Idle),
        }
    }

    pub fn with_max_iterations_per_phase(mut self, max: u32) -> Self {
        self.max_iterations_per_phase = max;
        self
    }

    pub fn with_phases(mut self, phases: Vec<PipelinePhase>) -> Self {
        self.phases = phases;
        self
    }

    pub fn with_initial_findings(mut self, findings: Vec<Finding>) -> Self {
        self.initial_findings = findings;
        self
    }

    pub async fn run(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        self.set_status(AgentStatus::Running).await;
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut context_data = serde_json::json!({});

        for phase in &self.phases {
            if *self.status.read().await == AgentStatus::Stopped {
                break;
            }

            tracing::info!("Pipeline phase: {}", phase.name());

            let phase_runner = ToolUseRunner::new(
                Arc::clone(&self.provider),
                Arc::clone(&self.registry),
                self.model.clone(),
                self.build_phase_prompt(phase, &all_findings, &context_data),
                Arc::clone(&self.safety),
            )
            .with_max_iterations(self.max_iterations_per_phase);

            match phase_runner.run(target).await {
                Ok(findings) => {
                    for finding in &findings {
                        tracing::info!(
                            "Phase {} found: {} (severity: {:?})",
                            phase.name(),
                            finding.title,
                            finding.severity
                        );
                    }
                    context_data = serde_json::json!({
                        "previous_phase": phase.name(),
                        "findings_count": findings.len(),
                    });
                    all_findings.extend(findings);
                }
                Err(e) => {
                    tracing::error!("Phase {} failed: {}", phase.name(), e);
                }
            }
        }

        // Include initial (scanner) findings, enriching them
        for mut finding in self.initial_findings.clone() {
            crate::validator::enrich_finding_heuristic(&mut finding);
            // Only add if not already present (avoid duplication)
            let is_duplicate = all_findings
                .iter()
                .any(|f| f.title == finding.title && f.location == finding.location);
            if !is_duplicate {
                all_findings.push(finding);
            }
        }

        self.set_status(AgentStatus::Completed).await;
        Ok(all_findings)
    }

    fn build_phase_prompt(
        &self,
        phase: &PipelinePhase,
        previous_findings: &[Finding],
        context: &serde_json::Value,
    ) -> String {
        let mut prompt = String::new();
        prompt.push_str(phase.system_prompt());
        prompt.push_str(&format!("\n\nCurrent phase: {}", phase.name()));
        prompt.push_str(&format!("\nPhase description: {}", phase.description()));

        if !previous_findings.is_empty() {
            prompt.push_str(&format!(
                "\n\nFindings from previous phases ({}):",
                previous_findings.len()
            ));
            for f in previous_findings {
                prompt.push_str(&format!(
                    "\n  [{:?}] {} - {}",
                    f.severity,
                    f.title,
                    &f.description[..f.description.len().min(100)]
                ));
            }
        }

        // Include initial scanner findings for validation and reporting phases
        if !self.initial_findings.is_empty()
            && (phase == &PipelinePhase::Validation || phase == &PipelinePhase::Reporting)
        {
            prompt.push_str(&format!(
                "\n\nPre-existing scanner findings to validate and enrich ({}):",
                self.initial_findings.len()
            ));
            for f in &self.initial_findings {
                prompt.push_str(&format!(
                    "\n  [{:?}] {} - Class: {:?}, CVSS: {:?}",
                    f.severity, f.title, f.vulnerability_class, f.cvss_score
                ));
            }
        }

        if context != &serde_json::json!({}) {
            prompt.push_str(&format!(
                "\n\nContext from previous phase: {}",
                serde_json::to_string(context).unwrap_or_default()
            ));
        }

        prompt
    }

    pub async fn stop(&self) {
        self.set_status(AgentStatus::Stopped).await;
    }

    async fn set_status(&self, s: AgentStatus) {
        let mut status = self.status.write().await;
        *status = s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_phases_without_exploit() {
        let phases = PipelinePhase::phases(false);
        assert_eq!(phases.len(), 5);
        assert_eq!(phases[0], PipelinePhase::Reconnaissance);
        assert_eq!(phases[phases.len() - 1], PipelinePhase::Reporting);
        assert!(!phases.contains(&PipelinePhase::Exploitation));
    }

    #[test]
    fn test_pipeline_phases_with_exploit() {
        let phases = PipelinePhase::phases(true);
        assert_eq!(phases.len(), 6);
        assert!(phases.contains(&PipelinePhase::Exploitation));
    }

    #[test]
    fn test_phase_names() {
        assert_eq!(PipelinePhase::Reconnaissance.name(), "Reconnaissance");
        assert_eq!(PipelinePhase::Exploitation.name(), "Exploitation");
        assert_eq!(PipelinePhase::Reporting.name(), "Reporting");
    }

    #[test]
    fn test_phase_descriptions_not_empty() {
        let phases = PipelinePhase::phases(false);
        for phase in &phases {
            assert!(!phase.description().is_empty());
            assert!(!phase.system_prompt().is_empty());
        }
    }
}
