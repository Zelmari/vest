use async_trait::async_trait;

use crate::error::VestError;
use crate::types::{Finding, ScanSession, Target};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentStatus {
    Idle,
    Running,
    Completed,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReportFormat {
    Json,
    Terminal,
    Markdown,
}

/// Core scanner trait. Each scanner implementation scans a target and
/// returns a list of vulnerability findings.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Human-readable name of this scanner.
    async fn name(&self) -> &str;
    /// Human-readable description of what this scanner does.
    async fn description(&self) -> &str;
    /// Whether this scanner is currently enabled.
    async fn enabled(&self) -> bool;
    /// Run the scan against a target, returning any findings.
    async fn scan(&self, target: &Target) -> Result<Vec<Finding>, VestError>;
}

/// LLM provider abstraction. Every supported LLM backend implements this trait.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Send a chat completion request. Returns the model's response text.
    async fn chat(&self, messages: &[serde_json::Value], model: &str) -> Result<String, VestError>;
    /// Stream a chat completion. Returns the full response text after concatenating chunks.
    async fn chat_stream(
        &self,
        messages: &[serde_json::Value],
        model: &str,
    ) -> Result<String, VestError>;
    /// List available models for this provider.
    async fn list_models(&self) -> Result<Vec<String>, VestError>;
    /// Check if a specific model is available and ready.
    async fn check_model(&self, model: &str) -> Result<bool, VestError>;
    /// Generate embeddings for the given text using the specified model.
    async fn embed(&self, text: &str, model: &str) -> Result<Vec<f32>, VestError>;
}

/// A scan agent that can be run against a target.
#[async_trait]
pub trait Agent: Send + Sync {
    /// Run the agent against a target, returning any findings.
    async fn run(&self, target: &Target) -> Result<Vec<Finding>, VestError>;
    /// Stop a running agent.
    async fn stop(&self);
    /// Get the current status of the agent.
    async fn status(&self) -> AgentStatus;
}

/// Report generator. Takes scan results and produces formatted output.
#[async_trait]
pub trait Reporter: Send + Sync {
    /// Generate a report for the given scan session and findings.
    async fn generate_report(
        &self,
        scan: &ScanSession,
        findings: &[Finding],
    ) -> Result<String, VestError>;
    /// The output format this reporter produces.
    fn format_type(&self) -> ReportFormat;
}
