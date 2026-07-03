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

#[async_trait]
pub trait Scanner: Send + Sync {
    async fn name(&self) -> &str;
    async fn description(&self) -> &str;
    async fn enabled(&self) -> bool;
    async fn scan(&self, target: &Target) -> Result<Vec<Finding>, VestError>;
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn chat(&self, messages: &[serde_json::Value], model: &str) -> Result<String, VestError>;
    async fn chat_stream(
        &self,
        messages: &[serde_json::Value],
        model: &str,
    ) -> Result<String, VestError>;
    async fn list_models(&self) -> Result<Vec<String>, VestError>;
    async fn check_model(&self, model: &str) -> Result<bool, VestError>;
    async fn embed(&self, text: &str, model: &str) -> Result<Vec<f32>, VestError>;
}

#[async_trait]
pub trait Agent: Send + Sync {
    async fn run(&self, target: &Target) -> Result<Vec<Finding>, VestError>;
    async fn stop(&self);
    async fn status(&self) -> AgentStatus;
}

#[async_trait]
pub trait Reporter: Send + Sync {
    async fn generate_report(
        &self,
        scan: &ScanSession,
        findings: &[Finding],
    ) -> Result<String, VestError>;
    fn format_type(&self) -> ReportFormat;
}
