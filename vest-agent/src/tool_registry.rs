use crate::context::ToolDefinition;
use crate::egress::{classify_tool_result, filter_for_model};
use crate::policy::{AuthorisationContext, NormalisedToolCall, PolicyEngine};
use std::collections::HashMap;
use std::sync::Arc;
use vest_core::{ApprovalDecision, DataEgressClass};

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

    /// Execute only when a prior policy decision was `Allow`.
    pub fn execute_authorised(
        &self,
        name: &str,
        args: serde_json::Value,
        decision: &ApprovalDecision,
    ) -> Result<serde_json::Value, String> {
        if !decision.is_allow() {
            return Err(format!(
                "tool '{name}' execution denied: missing Allow decision ({decision:?})"
            ));
        }
        self.execute_unchecked(name, args)
    }

    /// Always evaluates policy before running the handler, then filters egress.
    pub fn invoke(
        &self,
        policy: &PolicyEngine,
        ctx: &AuthorisationContext,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| format!("Tool '{name}' not found"))?;

        let call = NormalisedToolCall::from_parts(
            name,
            tool.definition.effect,
            tool.definition.egress_class,
            &args,
        );
        let decision = policy.evaluate(ctx, &call);
        match decision {
            ApprovalDecision::Allow => {}
            ApprovalDecision::Deny { reason } => {
                return Err(format!("policy denied '{name}': {reason}"));
            }
            ApprovalDecision::RequireInteractive { reason } => {
                if !ctx.interactive {
                    return Err(format!(
                        "policy denied '{name}' (non-interactive): {reason}"
                    ));
                }
                return Err(format!(
                    "policy requires interactive approval for '{name}': {reason}"
                ));
            }
        }

        let raw = (tool.handler)(args)?;
        let from_effect = classify_tool_result(tool.definition.effect, &raw);
        let class = more_restrictive(tool.definition.egress_class, from_effect);
        filter_for_model(&raw, class, ctx)
    }

    fn execute_unchecked(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        match self.tools.get(name) {
            Some(tool) => (tool.handler)(args),
            None => Err(format!("Tool '{name}' not found")),
        }
    }

    /// Compatibility shim — prefer [`Self::invoke`] (does not evaluate policy).
    #[doc(hidden)]
    pub fn execute(
        &self,
        name: &str,
        _args: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        Err(format!(
            "ToolRegistry::execute is not a policy bypass; use invoke() for '{name}'"
        ))
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn more_restrictive(a: DataEgressClass, b: DataEgressClass) -> DataEgressClass {
    fn rank(c: DataEgressClass) -> u8 {
        match c {
            DataEgressClass::PublicNonSensitive => 0,
            DataEgressClass::UserAuthored => 1,
            DataEgressClass::LocalMetadata | DataEgressClass::TargetMetadata => 2,
            DataEgressClass::TargetContent => 3,
            DataEgressClass::LocalContent => 4,
            DataEgressClass::PotentiallySecretBearing => 5,
            DataEgressClass::ProcessMemory => 6,
            DataEgressClass::CredentialMaterial | DataEgressClass::Prohibited => 7,
        }
    }
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}
