use crate::approved::ApprovedToolCall;
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

    /// Execute only with an opaque capability minted by [`PolicyEngine::authorise`],
    /// then apply model egress filtering (K5 / K5b).
    ///
    /// A public `ApprovalDecision::Allow` value is not accepted and cannot execute
    /// a handler. Results are always passed through [`filter_for_model`] before return.
    pub fn execute_authorised(
        &self,
        name: &str,
        args: serde_json::Value,
        approval: &ApprovedToolCall,
        ctx: &AuthorisationContext,
    ) -> Result<serde_json::Value, String> {
        if approval.tool_id() != name {
            return Err(format!(
                "tool '{name}' execution denied: capability is for '{}'",
                approval.tool_id()
            ));
        }
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
        if !approval.matches_call(&call, &ctx.session_id) {
            return Err(format!(
                "tool '{name}' execution denied: capability does not match exact call"
            ));
        }
        if !approval.consume() {
            return Err(format!(
                "tool '{name}' execution denied: one-shot capability already consumed"
            ));
        }
        let raw = (tool.handler)(args)?;
        let from_effect = classify_tool_result(tool.definition.effect, &raw);
        let class = more_restrictive(tool.definition.egress_class, from_effect);
        filter_for_model(&raw, class, ctx)
    }

    /// Thin wrapper over the live hot path (K5b):
    /// [`PolicyEngine::authorise`] → [`Self::execute_authorised`] (includes egress filter).
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
        let approval = policy
            .authorise(ctx, &call)
            .map_err(|decision| format_authorise_denial(name, &decision))?;
        self.execute_authorised(name, args, &approval, ctx)
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

fn format_authorise_denial(name: &str, decision: &ApprovalDecision) -> String {
    match decision {
        ApprovalDecision::Deny { reason } => {
            format!("policy denied '{name}': {reason}")
        }
        ApprovalDecision::RequireInteractive { reason } => {
            format!("policy requires interactive approval for '{name}': {reason}")
        }
        ApprovalDecision::Allow => {
            format!("policy denied '{name}': unexpected Allow without capability")
        }
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
