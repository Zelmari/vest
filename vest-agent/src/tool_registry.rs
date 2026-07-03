use crate::context::ToolDefinition;
use std::collections::HashMap;
use std::sync::Arc;

pub struct ToolRegistry {
    tools: HashMap<String, RegisteredTool>,
}

pub struct RegisteredTool {
    pub definition: ToolDefinition,
    pub handler: Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        definition: ToolDefinition,
        handler: impl Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync + 'static,
    ) {
        self.tools.insert(
            definition.name.clone(),
            RegisteredTool {
                definition,
                handler: Arc::new(handler),
            },
        );
    }

    pub fn get_tool(&self, name: &str) -> Option<&RegisteredTool> {
        self.tools.get(name)
    }

    pub fn get_all_definitions(&self) -> Vec<ToolDefinition> {
        self.tools.values().map(|t| t.definition.clone()).collect()
    }

    pub fn execute(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        match self.tools.get(name) {
            Some(tool) => (tool.handler)(args),
            None => Err(format!("Tool '{}' not found", name)),
        }
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}
