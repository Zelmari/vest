//! Compatibility facade over [`crate::policy::PolicyEngine`].
//!
//! Tool-name substring matching is no longer authoritative. Prefer constructing
//! [`NormalisedToolCall`] with an explicit [`ToolEffect`].

use crate::net_scope::ApprovedNetworkScope;
use crate::policy::{AuthorisationContext, NormalisedToolCall, PolicyEngine};
use std::sync::Arc;
use tokio::sync::RwLock;
use vest_core::auth::{ApprovalDecision, DataEgressClass, ToolEffect};
use vest_core::error::VestError;

pub struct SafetyChecker {
    pub policy: Arc<PolicyEngine>,
    pub auth: RwLock<AuthorisationContext>,
    config: SafetyConfig,
    rate_limiter: RwLock<RateLimiterState>,
}

#[derive(Debug, Clone)]
pub struct SafetyConfig {
    pub write_approval: bool,
    pub exploit_approval: bool,
    pub network_write_approval: bool,
    pub rate_limit_enabled: bool,
    pub rate_limit_requests_per_second: u32,
    pub rate_limit_burst: u32,
    pub sandbox_enabled: bool,
    pub sandbox_image: String,
    pub max_scan_duration_seconds: u64,
    pub max_concurrent_exploits: u32,
    pub allowed_targets: Vec<String>,
    pub blocked_targets: Vec<String>,
    pub allowed_networks: Vec<String>,
    pub deny_private_targets: bool,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            write_approval: true,
            exploit_approval: true,
            network_write_approval: true,
            rate_limit_enabled: true,
            rate_limit_requests_per_second: 10,
            rate_limit_burst: 30,
            sandbox_enabled: true,
            sandbox_image: "vest-sandbox:latest".into(),
            max_scan_duration_seconds: 3600,
            max_concurrent_exploits: 1,
            allowed_targets: Vec::new(),
            blocked_targets: Vec::new(),
            allowed_networks: Vec::new(),
            deny_private_targets: false,
        }
    }
}

#[derive(Debug)]
struct RateLimiterState {
    tokens: f64,
    last_refill: std::time::Instant,
}

impl SafetyChecker {
    pub fn new(config: SafetyConfig) -> Self {
        let mut auth = AuthorisationContext::new("default");
        if let Ok(net) = ApprovedNetworkScope::new(config.allowed_networks.clone()) {
            auth.network = net;
        }
        auth.interactive = false;
        Self {
            policy: Arc::new(PolicyEngine::new()),
            auth: RwLock::new(auth),
            config,
            rate_limiter: RwLock::new(RateLimiterState {
                tokens: 30.0,
                last_refill: std::time::Instant::now(),
            }),
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    /// Test-only permissive checker (still denies Unknown effects).
    pub fn permissive() -> Self {
        Self {
            policy: Arc::new(PolicyEngine::new()),
            auth: RwLock::new(AuthorisationContext::permissive_for_tests("permissive")),
            config: SafetyConfig {
                write_approval: false,
                exploit_approval: false,
                network_write_approval: false,
                rate_limit_enabled: false,
                ..Default::default()
            },
            rate_limiter: RwLock::new(RateLimiterState {
                tokens: f64::MAX,
                last_refill: std::time::Instant::now(),
            }),
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_allowing(allowed: bool) -> Self {
        if allowed {
            Self::permissive()
        } else {
            Self::new(SafetyConfig::default())
        }
    }

    /// Evaluate a tool call. Prefer passing explicit `effect` via [`Self::approve_normalised`].
    pub fn approve_tool_call(
        &self,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> Result<bool, VestError> {
        // Legacy entry: map known tools explicitly; unknown → deny (fail closed).
        let effect = explicit_effect_for_tool(tool_name).unwrap_or(ToolEffect::Unknown);
        let call = NormalisedToolCall::from_parts(
            tool_name,
            effect,
            DataEgressClass::PotentiallySecretBearing,
            args,
        );
        self.approve_normalised(&call)
    }

    pub fn approve_normalised(&self, call: &NormalisedToolCall) -> Result<bool, VestError> {
        let auth = self
            .auth
            .try_read()
            .map_err(|_| VestError::Internal("auth context lock poisoned".into()))?;
        match self.policy.evaluate(&auth, call) {
            ApprovalDecision::Allow => Ok(true),
            ApprovalDecision::Deny { reason } => Err(VestError::ApprovalDenied(reason)),
            ApprovalDecision::RequireInteractive { reason } => {
                // Non-interactive fail-closed surfaces as denial unless caller grants.
                if auth.interactive {
                    if crate::interactive_approval::prompt_tty_one_shot_allow(call, &reason) {
                        self.policy.grant_sync(&auth, call, true);
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    Err(VestError::ApprovalDenied(reason))
                }
            }
        }
    }

    pub async fn check_rate_limit(&self) -> Result<(), VestError> {
        if !self.config.rate_limit_enabled {
            return Ok(());
        }

        let mut limiter = self.rate_limiter.write().await;
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(limiter.last_refill).as_secs_f64();

        limiter.tokens = (limiter.tokens
            + elapsed * self.config.rate_limit_requests_per_second as f64)
            .min(self.config.rate_limit_burst as f64);
        limiter.last_refill = now;

        if limiter.tokens >= 1.0 {
            limiter.tokens -= 1.0;
            Ok(())
        } else {
            Err(VestError::RateLimited(format!(
                "Rate limit reached ({} req/s, burst {}). Try again later.",
                self.config.rate_limit_requests_per_second, self.config.rate_limit_burst
            )))
        }
    }

    /// Structural target allow/block — exact host/origin or exact path equality, not substring.
    pub fn is_target_allowed(&self, target_name: &str) -> bool {
        if self.config.deny_private_targets
            && crate::net_scope::is_private_or_metadata_target(target_name)
        {
            return false;
        }
        if !self.config.blocked_targets.is_empty() {
            for blocked in &self.config.blocked_targets {
                if ApprovedNetworkScope::host_equals(target_name, blocked) || target_name == blocked
                {
                    return false;
                }
            }
        }
        if !self.config.allowed_targets.is_empty() {
            for allowed in &self.config.allowed_targets {
                if ApprovedNetworkScope::host_equals(target_name, allowed) || target_name == allowed
                {
                    return true;
                }
            }
            return false;
        }
        true
    }

    pub async fn grant_approval_for(&self, call: &NormalisedToolCall) {
        let auth = self.auth.read().await.clone();
        self.policy.grant(&auth, call, false).await;
    }

    /// Mint a session-scoped effect grant for the current auth session.
    pub async fn grant_effect_session(&self, effect: ToolEffect) {
        let session_id = self.auth.read().await.session_id.clone();
        self.policy.grant_effect_session(&session_id, effect).await;
    }

    /// Legacy broad category grant — intentionally a no-op (does not bypass policy).
    pub async fn grant_approval(&self, _category: &str) {
        // Broad category caches were removed; use grant_approval_for with a
        // NormalisedToolCall instead.
    }

    pub async fn request_approval(
        &self,
        action: &str,
        _target: &str,
        _details: &str,
        _risk: &str,
    ) -> Result<bool, VestError> {
        // Legacy category grant removed — require normalised grant.
        let _ = action;
        Ok(false)
    }

    pub fn config(&self) -> &SafetyConfig {
        &self.config
    }

    pub fn with_overrides(&self, overrides: SafetyConfig) -> Self {
        Self::new(overrides)
    }

    pub async fn set_authorisation_context(&self, ctx: AuthorisationContext) {
        *self.auth.write().await = ctx;
    }

    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    pub fn auth_context(&self) -> AuthorisationContext {
        self.auth
            .try_read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| AuthorisationContext::new("default"))
    }

    /// Register an explicit effect for a tool name (used by tool-use runner).
    pub fn register_tool_effect(&self, _tool_name: &str, _effect: ToolEffect) {
        // Effects are taken from ToolDefinition at invoke time; kept for API compatibility.
    }

    pub fn evaluate_tool_call(
        &self,
        tool_name: &str,
        args: &serde_json::Value,
    ) -> ApprovalDecision {
        let effect = explicit_effect_for_tool(tool_name).unwrap_or(ToolEffect::Unknown);
        let call = NormalisedToolCall::from_parts(
            tool_name,
            effect,
            DataEgressClass::PotentiallySecretBearing,
            args,
        );
        let auth = self.auth_context();
        self.policy.evaluate(&auth, &call)
    }
}

impl Default for SafetyChecker {
    fn default() -> Self {
        Self::new(SafetyConfig::default())
    }
}

/// Explicit effect table for known built-in tools. Unknown names return None → deny.
pub fn explicit_effect_for_tool(name: &str) -> Option<ToolEffect> {
    match name {
        "read_file" | "file_scan" | "scan_for_secrets" => Some(ToolEffect::LocalFileContentRead),
        "list_files" => Some(ToolEffect::LocalMetadataRead),
        "http_get" => Some(ToolEffect::PassiveNetworkRequest),
        "http_post" => Some(ToolEffect::StateChangingNetworkRequest),
        "web_scan" => Some(ToolEffect::ActiveNetworkProbe),
        "browser_inspect" => Some(ToolEffect::ActiveNetworkProbe),
        "memory_scan" => Some(ToolEffect::ProcessMemoryRead),
        "read_memory" => Some(ToolEffect::ProcessMemoryRead),
        "write_memory" | "write_process" | "inject" | "inject_dll" => Some(ToolEffect::LocalWrite),
        "write_file" | "modify_file" | "create_file" => Some(ToolEffect::LocalWrite),
        "execute_command" | "run_shell" | "shell_exec" => Some(ToolEffect::CommandExecution),
        "list_processes" => Some(ToolEffect::ProcessMetadataRead),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_tool_denied() {
        let checker = SafetyChecker::default();
        let result = checker.approve_tool_call("completely_unknown_tool", &serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn http_post_not_auto_allowed() {
        let checker = SafetyChecker::default();
        let result = checker.approve_tool_call(
            "http_post",
            &serde_json::json!({"url": "http://127.0.0.1/", "data": {}}),
        );
        assert!(result.is_err() || matches!(result, Ok(false)));
    }

    #[test]
    fn permissive_allows_known_effects() {
        let checker = SafetyChecker::permissive();
        assert!(checker
            .approve_tool_call("http_get", &serde_json::json!({"url": "http://127.0.0.1/"}))
            .unwrap());
    }

    #[test]
    fn target_allow_is_not_substring() {
        let checker = SafetyChecker::new(SafetyConfig {
            allowed_targets: vec!["example.com".into()],
            ..Default::default()
        });
        assert!(checker.is_target_allowed("example.com"));
        assert!(
            !checker.is_target_allowed("example.com.evil.test"),
            "prefix/substring host must not match"
        );
    }

    #[tokio::test]
    async fn test_rate_limit_allows_initial_burst() {
        let checker = SafetyChecker::new(SafetyConfig {
            rate_limit_enabled: true,
            rate_limit_requests_per_second: 10,
            rate_limit_burst: 5,
            ..Default::default()
        });
        for _ in 0..5 {
            assert!(checker.check_rate_limit().await.is_ok());
        }
        assert!(matches!(
            checker.check_rate_limit().await,
            Err(VestError::RateLimited(_))
        ));
    }
}
