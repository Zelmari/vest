use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use vest_core::error::VestError;
use vest_core::traits::{AgentStatus, LlmProvider};
use vest_core::types::{Finding, Target};

#[async_trait]
pub trait VestAgent: Send + Sync {
    async fn run(&self, target: &Target) -> Result<Vec<Finding>, VestError>;
    async fn stop(&self);
    async fn status(&self) -> AgentStatus;
}

pub struct BaseAgent {
    pub name: String,
    pub role: String,
    pub model: String,
    provider: Arc<dyn LlmProvider>,
    status: RwLock<AgentStatus>,
    pub max_iterations: u32,
    pub system_prompt: String,
}

impl BaseAgent {
    pub fn new(
        name: impl Into<String>,
        role: impl Into<String>,
        model: impl Into<String>,
        provider: Arc<dyn LlmProvider>,
        system_prompt: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            role: role.into(),
            model: model.into(),
            provider,
            status: RwLock::new(AgentStatus::Idle),
            max_iterations: 200,
            system_prompt: system_prompt.into(),
        }
    }

    pub fn with_max_iterations(mut self, max: u32) -> Self {
        self.max_iterations = max;
        self
    }

    pub async fn set_status(&self, s: AgentStatus) {
        let mut status = self.status.write().await;
        *status = s;
    }

    pub async fn call_llm(&self, messages: &[serde_json::Value]) -> Result<String, VestError> {
        self.provider.chat(messages, &self.model).await
    }
}

#[async_trait]
impl VestAgent for BaseAgent {
    async fn run(&self, _target: &Target) -> Result<Vec<Finding>, VestError> {
        Err(VestError::Internal(
            "Abstract BaseAgent - use a pattern runner".into(),
        ))
    }

    async fn stop(&self) {
        self.set_status(AgentStatus::Stopped).await;
    }

    async fn status(&self) -> AgentStatus {
        *self.status.read().await
    }
}
