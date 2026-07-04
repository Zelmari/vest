use crate::memory::AgentMemory;
use crate::patterns::hierarchical::HierarchicalRunner;
use crate::patterns::pipeline::PipelineRunner;
use crate::patterns::swarm::SwarmRunner;
use crate::patterns::tooluse::ToolUseRunner;
use crate::planner::Planner;
use crate::safety::SafetyChecker;
use crate::tool_registry::ToolRegistry;
use crate::validator::Validator;
use std::sync::Arc;
use tokio::sync::RwLock;
use vest_core::error::VestError;
use vest_core::traits::LlmProvider;
use vest_core::types::{Finding, ScanMode, Target};

pub struct Orchestrator {
    provider: Arc<dyn LlmProvider>,
    registry: Arc<ToolRegistry>,
    model: String,
    mode: ScanMode,
    safety: Arc<SafetyChecker>,
    memory: Arc<RwLock<AgentMemory>>,
    planner: Planner,
    validator: Arc<Validator>,
    max_iterations: u32,
    include_exploit: bool,
    initial_findings: Vec<Finding>,
}

impl Orchestrator {
    pub fn new(
        provider: Arc<dyn LlmProvider>,
        registry: Arc<ToolRegistry>,
        model: impl Into<String>,
        mode: ScanMode,
        safety: Arc<SafetyChecker>,
    ) -> Self {
        Self {
            provider,
            registry,
            model: model.into(),
            mode,
            safety,
            memory: Arc::new(RwLock::new(AgentMemory::new())),
            planner: Planner::new(),
            validator: Arc::new(Validator::new()),
            max_iterations: 200,
            include_exploit: false,
            initial_findings: Vec::new(),
        }
    }

    pub fn with_planner(mut self, planner: Planner) -> Self {
        self.planner = planner;
        self
    }

    pub fn with_validator(mut self, validator: Validator) -> Self {
        self.validator = Arc::new(validator);
        self
    }

    pub fn with_max_iterations(mut self, max: u32) -> Self {
        self.max_iterations = max;
        self
    }

    pub fn with_include_exploit(mut self, exploit: bool) -> Self {
        self.include_exploit = exploit;
        self
    }

    pub fn with_initial_findings(mut self, findings: Vec<Finding>) -> Self {
        self.initial_findings = findings;
        self
    }

    pub async fn run(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        // Check safety - is target allowed?
        if !self.safety.is_target_allowed(&target.name) {
            return Err(VestError::ApprovalDenied(format!(
                "Target '{}' is not in the allowed targets list",
                target.name
            )));
        }

        // Check FP memory before scanning
        {
            let memory = self.memory.read().await;
            let fp_count = memory.false_positives.len();
            if fp_count > 0 {
                tracing::info!("Loaded {} false positive patterns from memory", fp_count);
            }
        }

        // Run the scan with the configured mode
        let raw_findings = match self.mode {
            ScanMode::ToolUse => self.run_tool_use(target).await?,
            ScanMode::Pipeline => self.run_pipeline(target).await?,
            ScanMode::Swarm => self.run_swarm(target).await?,
            ScanMode::Hierarchical => self.run_hierarchical(target).await?,
        };

        // Combine agent findings with initial (scanner) findings.
        // For Pipeline mode, the PipelineRunner already includes enriched initial_findings.
        let mut combined = raw_findings;

        // For other modes, initial_findings are appended and validated separately.
        if self.mode != ScanMode::Pipeline && !self.initial_findings.is_empty() {
            combined.extend(self.initial_findings.clone());
        }

        // Filter out known false positives
        let memory = self.memory.read().await;
        let raw_count = combined.len();
        let filtered: Vec<Finding> = combined
            .into_iter()
            .filter(|f| memory.is_known_false_positive(f).is_none())
            .collect();
        let fp_filtered = raw_count - filtered.len();
        if fp_filtered > 0 {
            tracing::info!("Filtered {} known false positives", fp_filtered);
        }
        drop(memory);

        // Validate findings (this will also enrich them heuristically)
        let validated = self.validator.validate(&filtered).await?;
        tracing::info!(
            "Validated {} findings ({} filtered out)",
            validated.len(),
            filtered.len() - validated.len()
        );

        // Store confirmed patterns in memory
        {
            let mut memory = self.memory.write().await;
            for finding in &validated {
                memory.record_confirmed_pattern(finding);
            }
        }

        Ok(validated)
    }

    async fn run_tool_use(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        let runner = ToolUseRunner::new(
            Arc::clone(&self.provider),
            Arc::clone(&self.registry),
            self.model.clone(),
            "You are a vulnerability scanning agent. Your task is to find security vulnerabilities in the target. \
             Use available tools methodically. For each finding, provide:\n\
             - Title and description\n\
             - Vulnerability class\n\
             - Severity (critical/high/medium/low/info)\n\
             - Evidence (what you found)\n\
             - Location (where you found it)\n\
             - CVSS score estimate\n\
             - Remediation recommendation\n\
             Be thorough and systematic.",
            Arc::clone(&self.safety),
        ).with_max_iterations(self.max_iterations);

        runner.run(target).await
    }

    async fn run_pipeline(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        let runner = PipelineRunner::new(
            Arc::clone(&self.provider),
            Arc::clone(&self.registry),
            self.model.clone(),
            Arc::clone(&self.safety),
            self.include_exploit,
        )
        .with_max_iterations_per_phase(self.max_iterations / 5)
        .with_initial_findings(self.initial_findings.clone());

        runner.run(target).await
    }

    async fn run_swarm(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        let agents = SwarmRunner::default_agents();
        let runner = SwarmRunner::new(
            Arc::clone(&self.provider),
            Arc::clone(&self.registry),
            self.model.clone(),
            Arc::clone(&self.safety),
            agents,
        )
        .with_parallelism(4)
        .with_max_iterations_per_agent(self.max_iterations / 4)
        .with_diversity_seeds(2);

        runner.run(target).await
    }

    async fn run_hierarchical(&self, target: &Target) -> Result<Vec<Finding>, VestError> {
        let runner = HierarchicalRunner::new(
            Arc::clone(&self.provider),
            Arc::clone(&self.registry),
            self.model.clone(),
            Arc::clone(&self.safety),
        )
        .with_max_depth(2)
        .with_max_children(5)
        .with_max_iterations_per_child(self.max_iterations / 5);

        runner.run(target).await
    }
}
